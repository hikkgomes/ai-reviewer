#!/usr/bin/env python3
"""Run explicitly configured local review tools and report every decision."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shlex
import shutil
import subprocess


KNOWN_TOOLS = ("gitleaks", "trufflehog", "semgrep", "trivy", "npm", "pnpm", "yarn", "pip-audit", "cargo")


def load_config() -> dict:
    try:
        return json.loads((Path.cwd() / ".ai-review" / "local.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args()
    config = load_config()
    configured = (config.get("security_review") or {}).get("tool_commands") or {}
    results = []

    for name in sorted(set(KNOWN_TOOLS) | set(configured)):
        command = str(configured.get(name) or "").strip()
        try:
            executable = shlex.split(command)[0] if command else name.split()[0]
        except ValueError:
            executable = ""
        detected = bool(executable and shutil.which(executable))
        result = {
            "tool": name,
            "detected": detected,
            "configured": bool(command),
            "command": command,
            "executed": False,
            "exit_code": None,
            "complete": False,
            "output": "",
        }
        if command:
            if not detected:
                result["output"] = "Configured check was not run because the tool was not detected."
            else:
                completed = subprocess.run(
                    command,
                    shell=True,
                    cwd=Path.cwd(),
                    text=True,
                    capture_output=True,
                    check=False,
                )
                result.update({
                    "executed": True,
                    "exit_code": completed.returncode,
                    "complete": completed.returncode == 0,
                    "output": (completed.stdout + completed.stderr).strip()[-4000:],
                })
        elif detected:
            result["output"] = "Detected but not executed; configure security_review.tool_commands to authorise it."
        results.append(result)

    if args.format == "json":
        print(json.dumps({"tools": results}, indent=2, sort_keys=True))
    else:
        for result in results:
            if not result["detected"] and not result["configured"]:
                continue
            print(
                f"[tool] {result['tool']}: detected={str(result['detected']).lower()} "
                f"configured={str(result['configured']).lower()} executed={str(result['executed']).lower()} "
                f"exit={result['exit_code'] if result['exit_code'] is not None else 'n/a'} "
                f"complete={str(result['complete']).lower()}"
            )
            if result["command"]:
                print(f"  command: {result['command']}")
            if result["output"]:
                print(f"  output: {result['output']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
