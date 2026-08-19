#!/usr/bin/env python3
"""Run the skill-local anti-slop Oxlint plugin and emit ledger candidates."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any, Iterable

if sys.version_info < (3, 11):
    raise SystemExit("Dissect requires Python 3.11 or newer.")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from diff_file_list import DiffEntry, deserialize_entries, read_diff_entries  # noqa: E402
from dissect_checks.redaction import redact_sensitive_text  # noqa: E402
from file_paths import is_ignored_path  # noqa: E402
from review_ledger import blank_candidate, validate_candidate  # noqa: E402


JS_TS_SUFFIXES = {".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"}
RULE_PREFIXES = ("anti-slop/", "anti-slop-effect/")
MIN_NODE = (22, 18)
MAX_FILES_PER_INVOCATION = 2000
VENDOR_DIR = Path(__file__).resolve().parent / "vendor" / "anti-slop"


class RunnerError(RuntimeError):
    """An invalid invocation or an internal scope error."""


class PathEscapeError(RunnerError):
    """A requested file is outside the review root."""


class AnalysisSkip(RuntimeError):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


class RunnerArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise RunnerError(message)


def _node_version(node: str) -> tuple[int, int, int] | None:
    try:
        result = subprocess.run(
            [node, "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    value = result.stdout or result.stderr or ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    value = value.strip()
    match = re.search(r"v?(\d+)\.(\d+)(?:\.(\d+))?", value)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def _oxlint_path(vendor_dir: Path) -> Path:
    binary = vendor_dir / "node_modules" / ".bin" / "oxlint"
    if os.name == "nt" and not binary.exists():
        return binary.with_suffix(".cmd")
    return binary


def preflight(vendor_dir: Path) -> str | None:
    """Return a stable skip reason, or ``None`` when the runtime is ready."""
    node = shutil.which("node")
    if node is None:
        return "node_unavailable"
    version = _node_version(node)
    if version is None or version[:2] < MIN_NODE:
        return "node_version_unsupported"
    if not _oxlint_path(vendor_dir).is_file():
        return "deps_missing"
    return None


def filter_files(paths: Iterable[str | Path], target_root: Path) -> list[Path]:
    """Select existing JavaScript/TypeScript files inside ``target_root``."""
    root = target_root.resolve()
    selected: dict[str, Path] = {}
    for value in paths:
        raw = str(value)
        if not raw:
            continue
        candidate = Path(raw)
        resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
        if not resolved.is_relative_to(root):
            raise PathEscapeError(f"path escapes target root: {raw}")
        if is_ignored_path(root, resolved):
            continue
        if resolved.suffix.lower() not in JS_TS_SUFFIXES or not resolved.is_file():
            continue
        selected[resolved.as_posix()] = resolved
    return [selected[key] for key in sorted(selected)]


def _has_effect_dependency(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    return any(
        isinstance(data.get(section), dict) and "effect" in data[section]
        for section in ("dependencies", "devDependencies", "peerDependencies")
    )


def _workspace_patterns(data: dict[str, Any]) -> list[str]:
    workspaces = data.get("workspaces")
    if isinstance(workspaces, list):
        return [item for item in workspaces if isinstance(item, str)]
    if isinstance(workspaces, dict) and isinstance(workspaces.get("packages"), list):
        return [item for item in workspaces["packages"] if isinstance(item, str)]
    return []


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def detect_effect(target_root: Path) -> bool:
    """Detect Effect in the root manifest or one workspace expansion."""
    manifest = _read_json(target_root / "package.json")
    if manifest is None:
        return False
    if _has_effect_dependency(manifest):
        return True
    for pattern in _workspace_patterns(manifest):
        try:
            matches = target_root.glob(pattern)
        except (OSError, ValueError):
            continue
        for match in matches:
            try:
                if not match.resolve().is_relative_to(target_root.resolve()):
                    continue
            except OSError:
                continue
            package_path = match / "package.json" if match.is_dir() else match
            if package_path.name != "package.json":
                continue
            package = _read_json(package_path)
            if package is not None and _has_effect_dependency(package):
                return True
    return False


def _merge_chunk_output(outputs: list[str]) -> str:
    if len(outputs) <= 1:
        return outputs[0] if outputs else ""
    diagnostics: list[Any] = []
    for output in outputs:
        try:
            payload = json.loads(output)
        except (TypeError, ValueError):
            return "\n".join(outputs)
        if isinstance(payload, dict) and isinstance(payload.get("diagnostics"), list):
            diagnostics.extend(payload["diagnostics"])
        elif isinstance(payload, list):
            diagnostics.extend(payload)
    return json.dumps({"diagnostics": diagnostics}, separators=(",", ":"))


def run_oxlint(
    oxlint_bin: Path,
    config_path: Path,
    files: Iterable[str | Path],
    timeout: float,
) -> tuple[str, str]:
    """Run Oxlint in chunks and return merged stdout plus stderr."""
    file_values = [str(path) for path in files]
    vendor_dir = config_path.resolve().parent
    outputs: list[str] = []
    errors: list[str] = []
    for index in range(0, len(file_values), MAX_FILES_PER_INVOCATION):
        chunk = file_values[index:index + MAX_FILES_PER_INVOCATION]
        argv = [str(oxlint_bin), "--config", str(config_path), "--format", "json", *chunk]
        try:
            result = subprocess.run(
                argv,
                cwd=vendor_dir,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            raise AnalysisSkip("timeout", str(error)) from error
        except OSError as error:
            raise AnalysisSkip("runner_error", str(error)) from error
        outputs.append(result.stdout or "")
        if result.stderr:
            errors.append(result.stderr)
    return _merge_chunk_output(outputs), "\n".join(errors)


def _canonical_rule_id(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    for prefix in RULE_PREFIXES:
        if value.startswith(prefix):
            return value
    for plugin in ("anti-slop", "anti-slop-effect"):
        marker = f"{plugin}("
        if value.startswith(marker) and value.endswith(")"):
            return f"{plugin}/{value[len(marker):-1]}"
    return ""


def _diagnostic_location(diagnostic: dict[str, Any]) -> tuple[int, int]:
    labels = diagnostic.get("labels")
    if isinstance(labels, list) and labels and isinstance(labels[0], dict):
        span = labels[0].get("span")
        if isinstance(span, dict):
            try:
                return int(span.get("line", 0)), int(span.get("column", 0))
            except (TypeError, ValueError):
                pass
    location = diagnostic.get("location")
    if isinstance(location, dict):
        start = location.get("start") if isinstance(location.get("start"), dict) else location
        try:
            return int(start.get("line", 0)), int(start.get("column", 0))
        except (AttributeError, TypeError, ValueError):
            pass
    return int(diagnostic.get("line", 0) or 0), int(diagnostic.get("column", 0) or 0)


def parse_diagnostics(stdout: str, stderr: str = "") -> list[dict[str, Any]]:
    """Parse the Oxlint JSON shape and retain only anti-slop plugin rules."""
    try:
        payload = json.loads(stdout)
    except (TypeError, ValueError) as error:
        detail = redact_sensitive_text((stderr or "")[:500])
        raise AnalysisSkip("unparseable_output", detail) from error
    raw_diagnostics = payload.get("diagnostics", []) if isinstance(payload, dict) else payload
    if not isinstance(raw_diagnostics, list):
        raise AnalysisSkip("unparseable_output", redact_sensitive_text((stderr or "")[:500]))
    parsed: list[dict[str, Any]] = []
    for diagnostic in raw_diagnostics:
        if not isinstance(diagnostic, dict):
            continue
        rule = _canonical_rule_id(
            diagnostic.get("code", diagnostic.get("rule_id", diagnostic.get("ruleId", diagnostic.get("rule"))))
        )
        if not rule.startswith(RULE_PREFIXES):
            continue
        line, column = _diagnostic_location(diagnostic)
        parsed.append({
            "rule": rule,
            "message": str(diagnostic.get("message", "")),
            "filename": str(diagnostic.get("filename", diagnostic.get("file", diagnostic.get("path", "")))),
            "line": line,
            "column": column,
        })
    return parsed


def _relative_path(filename: str, target_root: Path) -> str:
    root = target_root.resolve()
    path = Path(filename.replace("\\", "/"))
    if not path.is_absolute():
        value = path.as_posix()
        while value.startswith("./"):
            value = value[2:]
        return value
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def to_candidates(diagnostics: Iterable[dict[str, Any]], target_root: Path) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for index, diagnostic in enumerate(diagnostics, 1):
        rule = str(diagnostic.get("rule", ""))
        message = str(diagnostic.get("message", ""))
        relpath = _relative_path(str(diagnostic.get("filename", "")), target_root)
        line = int(diagnostic.get("line", 0) or 0)
        column = int(diagnostic.get("column", 0) or 0)
        candidate = blank_candidate(
            f"candidate-anti-slop-{index}",
            source=rule,
            claim=f"{rule}: {message} at {relpath}:{line}",
        )
        candidate["trigger_path"] = [f"{relpath}:{line}"]
        candidate["supporting_evidence"] = [{
            "kind": "lint_diagnostic",
            "file": relpath,
            "line": line,
            "column": column,
            "message": message,
        }]
        errors = validate_candidate(candidate)
        if errors:
            raise RunnerError("invalid anti-slop candidate: " + "; ".join(errors))
        candidates.append(candidate)
    return candidates


def _envelope(
    *,
    status: str,
    skip_reason: str | None,
    config_variant: str,
    files_scanned: int,
    candidates: list[dict[str, Any]],
    detail: str = "",
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "tool": "anti-slop",
        "status": status,
        "skip_reason": skip_reason,
        "config_variant": config_variant,
        "files_scanned": files_scanned,
        "candidates": candidates,
    }
    if detail:
        payload["detail"] = detail[:500]
    return _redact_payload(payload)


def _redact_payload(value: Any) -> Any:
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, list):
        return [_redact_payload(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_payload(item) for key, item in value.items()}
    return value


def analyse(
    target_root: Path,
    paths: Iterable[str | Path],
    *,
    timeout: float = 300,
    vendor_dir: Path = VENDOR_DIR,
) -> dict[str, Any]:
    target_root = target_root.resolve()
    config_variant = "effect" if detect_effect(target_root) else "generic"
    try:
        files = filter_files(paths, target_root)
    except PathEscapeError:
        raise
    if not files:
        return _envelope(
            status="skipped",
            skip_reason="no_js_ts_files",
            config_variant=config_variant,
            files_scanned=0,
            candidates=[],
        )
    reason = preflight(vendor_dir)
    if reason is not None:
        return _envelope(
            status="skipped",
            skip_reason=reason,
            config_variant=config_variant,
            files_scanned=0,
            candidates=[],
        )
    oxlint_bin = _oxlint_path(vendor_dir)
    config_path = vendor_dir / ("oxlint-review-effect.json" if config_variant == "effect" else "oxlint-review.json")
    try:
        stdout, stderr = run_oxlint(oxlint_bin, config_path, files, timeout)
        diagnostics = parse_diagnostics(stdout, stderr)
        candidates = to_candidates(diagnostics, target_root)
    except AnalysisSkip as skip:
        return _envelope(
            status="skipped",
            skip_reason=skip.reason,
            config_variant=config_variant,
            files_scanned=0,
            candidates=[],
            detail=skip.detail,
        )
    return _envelope(
        status="ok",
        skip_reason=None,
        config_variant=config_variant,
        files_scanned=len(files),
        candidates=candidates,
    )


def _entries_paths(entries: Iterable[DiffEntry]) -> list[str]:
    return sorted({
        entry.reviewed_path
        for entry in entries
        if entry.exists_in_worktree and entry.reviewed_path
        and Path(entry.reviewed_path).suffix.lower() in JS_TS_SUFFIXES
    })


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = RunnerArgumentParser(description=__doc__)
    parser.add_argument("--entries-from", default=None, metavar="FILE|-")
    parser.add_argument("--file", action="append", default=[], dest="files", metavar="PATH")
    parser.add_argument("--target-root", required=True, type=Path)
    parser.add_argument("--format", choices=("json",), default="json")
    parser.add_argument("--timeout", type=float, default=300)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        if args.timeout <= 0:
            raise RunnerError("--timeout must be greater than zero")
        if args.entries_from is not None:
            entries = (
                deserialize_entries(sys.stdin.buffer.read())
                if args.entries_from == "-"
                else read_diff_entries(Path(args.entries_from))
            )
            paths = _entries_paths(entries)
        else:
            paths = args.files
        payload = analyse(args.target_root, paths, timeout=args.timeout)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    except PathEscapeError as error:
        print(redact_sensitive_text(str(error)), file=sys.stderr)
        return 1
    except (RunnerError, OSError, ValueError) as error:
        print(redact_sensitive_text(str(error)), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
