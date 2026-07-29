#!/usr/bin/env python3
"""Run explicitly configured local review tools and report every decision."""
from __future__ import annotations

import argparse
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

if sys.version_info < (3, 11):
    raise SystemExit("Dissect requires Python 3.11 or newer.")

from dissect_checks.redaction import redact_argv, redact_sensitive_text


KNOWN_TOOL_EXECUTABLES = {
    "gitleaks": frozenset({"gitleaks"}),
    "trufflehog": frozenset({"trufflehog"}),
    "semgrep": frozenset({"semgrep"}),
    "trivy": frozenset({"trivy"}),
    "pip-audit": frozenset({"pip-audit"}),
}
KNOWN_TOOLS = tuple(KNOWN_TOOL_EXECUTABLES)
SHELL_AND_RUNNER_BASENAMES = frozenset({
    "bash", "bun", "cargo", "cmd", "cmd.exe", "deno", "env", "node", "npm",
    "npx", "perl", "php", "pnpm", "powershell", "pwsh", "python", "python3",
    "ruby", "sh", "yarn", "zsh",
})
RUNNER_FINGERPRINT_CANDIDATES = (
    "sh", "bash", "zsh", "python", "python3", "node", "env",
)


def load_config() -> dict:
    try:
        return json.loads((Path.cwd() / ".ai-review" / "local.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _basename(path: Path) -> str:
    name = path.name.lower()
    return name[:-4] if name.endswith(".exe") else name


def _resolve_executable(value: str) -> Path | None:
    detected = shutil.which(value)
    if not detected:
        return None
    try:
        return Path(detected).resolve(strict=True)
    except OSError:
        return None


def _executable_fingerprint(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


@lru_cache(maxsize=1)
def _runner_fingerprints() -> frozenset[str]:
    fingerprints = set()
    for name in RUNNER_FINGERPRINT_CANDIDATES:
        resolved = _resolve_executable(name)
        if resolved:
            fingerprint = _executable_fingerprint(resolved)
            if fingerprint:
                fingerprints.add(fingerprint)
    return frozenset(fingerprints)


def _known_identity_error(name: str, configured: str, resolved: Path | None) -> str | None:
    if name not in KNOWN_TOOL_EXECUTABLES:
        return "Custom executable requires --allow-custom-tool NAME=RESOLVED_PATH."
    configured_name = _basename(Path(configured))
    resolved_name = _basename(resolved) if resolved else ""
    allowed = KNOWN_TOOL_EXECUTABLES[name]
    if configured_name not in allowed or resolved_name not in allowed:
        return (
            f"Configured executable identity does not match known tool {name!r}; "
            "shells, generic runners, symlinks to another executable, and renamed commands "
            "are not accepted."
        )
    if configured_name in SHELL_AND_RUNNER_BASENAMES or resolved_name in SHELL_AND_RUNNER_BASENAMES:
        return "Shell interpreters and generic command runners are not accepted as known tools."
    if resolved and _executable_fingerprint(resolved) in _runner_fingerprints():
        return (
            "Configured executable is byte-identical to a shell interpreter or generic runner; "
            "renaming or copying a runner does not establish a known-tool identity."
        )
    if resolved:
        try:
            resolved.relative_to(Path.cwd().resolve())
        except ValueError:
            pass
        else:
            return (
                "Repository-local executables cannot establish a known-tool identity; "
                "use a separately installed tool or an exact custom-tool approval."
            )
    return None


def _custom_approvals(values: list[str]) -> dict[str, Path]:
    approvals = {}
    for value in values:
        name, separator, executable = value.partition("=")
        if not separator or not name or not executable:
            continue
        resolved = _resolve_executable(executable)
        if resolved:
            approvals[name] = resolved
    return approvals


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--allow-tool",
        action="append",
        default=[],
        metavar="NAME",
        help="Explicitly allow one named trusted local tool; repeat for multiple tools.",
    )
    parser.add_argument(
        "--allow-custom-tool",
        action="append",
        default=[],
        metavar="NAME=RESOLVED_PATH",
        help=(
            "Explicitly allow one custom tool bound to its executable identity; "
            "repeat for multiple tools."
        ),
    )
    args = parser.parse_args()
    allowed_known = set(args.allow_tool)
    allowed_custom = _custom_approvals(args.allow_custom_tool)
    config = load_config()
    configured = (config.get("security_review") or {}).get("tool_commands") or {}
    results = []

    for name in sorted(set(KNOWN_TOOLS) | set(configured)):
        raw_config = configured.get(name)
        if isinstance(raw_config, dict):
            raw_argv = raw_config.get("argv")
            execution_argv = (
                [str(value) for value in raw_argv]
                if isinstance(raw_argv, list) and raw_argv
                and all(isinstance(value, str) and value for value in raw_argv)
                else []
            )
            finding_exit_codes = {
                int(code) for code in raw_config.get("finding_exit_codes", [])
                if isinstance(code, int) or (isinstance(code, str) and code.isdigit())
            }
        else:
            execution_argv = []
            finding_exit_codes = set()
        configured_entry = raw_config is not None
        display_name = redact_sensitive_text(name)
        executable = execution_argv[0] if execution_argv else name.split()[0]
        resolved_executable = _resolve_executable(executable) if executable else None
        detected = resolved_executable is not None
        identity_error = (
            _known_identity_error(name, executable, resolved_executable)
            if execution_argv and name in KNOWN_TOOL_EXECUTABLES
            else None
        )
        custom_approved = (
            name in allowed_custom
            and resolved_executable is not None
            and allowed_custom[name] == resolved_executable
        )
        approved = (
            name in KNOWN_TOOL_EXECUTABLES
            and name in allowed_known
            and identity_error is None
        ) or (
            name not in KNOWN_TOOL_EXECUTABLES
            and custom_approved
        )
        displayed_argv = (
            [str(resolved_executable), *execution_argv[1:]]
            if resolved_executable and execution_argv
            else execution_argv
        )
        result = {
            "tool": display_name,
            "detected": detected,
            "configured": configured_entry,
            "argv": redact_argv(displayed_argv),
            "resolved_executable": (
                redact_sensitive_text(str(resolved_executable))
                if resolved_executable else None
            ),
            "approved": approved,
            "executed": False,
            "execution_completed": False,
            "exit_code": None,
            "complete": False,
            "passed": None,
            "findings_produced": None,
            "coverage_complete": None,
            "output": "",
        }
        if configured_entry and not execution_argv:
            result["output"] = (
                "Configured check was not run: use an object with a non-empty string argv array; "
                "shell command strings are rejected."
            )
        elif execution_argv and identity_error:
            result["output"] = f"Configured check was not run: {identity_error}"
        elif execution_argv and not approved:
            result["output"] = (
                "Configured check was not run: review the complete argv and resolved executable, "
                + (
                    f"then pass --allow-tool {display_name} from a trusted local invocation."
                    if name in KNOWN_TOOL_EXECUTABLES
                    else (
                        "then pass --allow-custom-tool "
                        f"{display_name}=RESOLVED_PATH from a trusted local invocation."
                    )
                )
            )
        elif execution_argv:
            if not detected:
                result["output"] = "Configured check was not run because the tool was not detected."
            else:
                execution_plan = [
                    str(resolved_executable),
                    *execution_argv[1:],
                ]
                completed = subprocess.run(
                    execution_plan,
                    shell=False,
                    cwd=Path.cwd(),
                    text=True,
                    capture_output=True,
                    check=False,
                )
                result.update({
                    "executed": True,
                    "execution_completed": True,
                    "exit_code": completed.returncode,
                    "complete": True,
                    "passed": completed.returncode == 0,
                    "findings_produced": (
                        completed.returncode in finding_exit_codes
                        if finding_exit_codes
                        else (False if completed.returncode == 0 else None)
                    ),
                    "coverage_complete": (
                        completed.returncode == 0
                        or completed.returncode in finding_exit_codes
                    ),
                    "output": redact_sensitive_text(
                        (completed.stdout + completed.stderr).strip()
                    )[-4000:],
                })
        elif detected:
            result["output"] = (
                "Detected but not executed; configure a trusted argv entry and invoke "
                "--allow-tool NAME explicitly."
            )
        results.append(result)

    if args.format == "json":
        print(json.dumps({"tools": results}, indent=2, sort_keys=True))
    else:
        for result in results:
            if not result["detected"] and not result["configured"]:
                continue
            print(
                f"[tool] {result['tool']}: detected={str(result['detected']).lower()} "
                f"configured={str(result['configured']).lower()} approved={str(result['approved']).lower()} "
                f"executed={str(result['executed']).lower()} "
                f"exit={result['exit_code'] if result['exit_code'] is not None else 'n/a'} "
                f"execution_completed={str(result['execution_completed']).lower()} "
                f"passed={result['passed']} findings={result['findings_produced']} "
                f"coverage_complete={result['coverage_complete']}"
            )
            if result["argv"]:
                print(f"  argv: {json.dumps(result['argv'])}")
            if result["resolved_executable"]:
                print(f"  resolved executable: {result['resolved_executable']}")
            if result["output"]:
                print(f"  output: {result['output']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
