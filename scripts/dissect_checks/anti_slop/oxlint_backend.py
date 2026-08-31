"""Skill-local Oxlint backend for JavaScript and TypeScript."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Any, Iterable, Sequence

from analysis_budget import AnalysisBudget, AnalysisBudgetExceeded
from dissect_checks.redaction import redact_sensitive_text
from file_paths import is_generated_path, is_ignored_path
from language_registry import language_for_path
from .model import AnalysisTarget, BackendDiagnostic, BackendResult
from .chunking import CommandChunkError, iter_command_chunks
from .rules import owner_for


BACKEND_ID = "oxlint-js-ts"
LANGUAGES = ("javascript", "typescript")
RULE_PREFIXES = ("anti-slop/", "anti-slop-effect/")
MIN_NODE = (22, 18)
MAX_FILE_BYTES = 10 * 1024 * 1024
VENDOR_DIR = Path(__file__).resolve().parents[2] / "vendor" / "anti-slop"


class RunnerError(RuntimeError):
    """An invalid invocation or invalid analyser output."""


class PathEscapeError(RunnerError):
    """A tool diagnostic or requested path escaped the review root."""


class AnalysisSkip(RuntimeError):
    def __init__(self, reason: str, detail: str = "", *, partial_outputs: Sequence[str] = (), checked_files: int = 0) -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail
        self.partial_outputs = tuple(partial_outputs)
        self.checked_files = checked_files


def _node_version(node: str) -> tuple[int, int, int] | None:
    try:
        result = subprocess.run([node, "--version"], capture_output=True, text=True, check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = result.stdout or result.stderr or ""
    match = re.search(r"v?(\d+)\.(\d+)(?:\.(\d+))?", str(value).strip())
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)) if match else None


def _oxlint_path(vendor_dir: Path) -> Path:
    binary = vendor_dir / "node_modules" / ".bin" / "oxlint"
    return binary.with_suffix(".cmd") if os.name == "nt" and not binary.exists() else binary


def preflight(vendor_dir: Path) -> str | None:
    node = shutil.which("node")
    if node is None:
        return "node_unavailable"
    version = _node_version(node)
    if version is None or version[:2] < MIN_NODE:
        return "node_version_unsupported"
    if not _oxlint_path(vendor_dir).is_file():
        return "deps_missing"
    return None


def filter_files(paths: Iterable[str | Path], target_root: Path, config: dict[str, Any] | None = None) -> list[Path]:
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
        spec = language_for_path(resolved)
        if is_ignored_path(root, resolved) or is_generated_path(root, resolved, config or {}) or spec is None or spec.anti_slop_backend != BACKEND_ID:
            continue
        if resolved.is_file():
            selected[resolved.as_posix()] = resolved
    return [selected[key] for key in sorted(selected)]


def _has_effect_dependency(data: Any) -> bool:
    return isinstance(data, dict) and any(
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


def _validate_tool_json(stdout: str, stderr: str, expected_files: int) -> Any:
    try:
        payload = json.loads(stdout)
    except (TypeError, ValueError) as error:
        raise AnalysisSkip("invalid_json", redact_sensitive_text((stderr or "")[:500])) from error
    raw = payload.get("diagnostics") if isinstance(payload, dict) else payload
    if not isinstance(raw, list):
        raise AnalysisSkip("invalid_json", redact_sensitive_text((stderr or "")[:500]))
    if isinstance(payload, dict) and isinstance(payload.get("number_of_files"), int) and payload["number_of_files"] != expected_files:
        raise AnalysisSkip("file_count_mismatch", f"Oxlint reported {payload['number_of_files']} files for {expected_files}")
    return payload


def _merge_chunk_output(outputs: Sequence[str]) -> str:
    diagnostics: list[Any] = []
    for output in outputs:
        payload = json.loads(output)
        raw = payload.get("diagnostics", []) if isinstance(payload, dict) else payload
        diagnostics.extend(raw)
    return json.dumps({"diagnostics": diagnostics}, separators=(",", ":"))


def run_oxlint(
    oxlint_bin: Path,
    config_path: Path,
    files: Iterable[str | Path],
    timeout: float,
    *,
    max_files: int = 250,
    max_argument_bytes: int = 24000,
) -> tuple[str, str]:
    """Run all chunks under one absolute deadline."""
    file_values = [str(path) for path in files]
    deadline = time.monotonic() + timeout
    outputs: list[str] = []
    errors: list[str] = []
    checked = 0
    try:
        for chunk in iter_command_chunks(file_values, max_files, max_argument_bytes):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AnalysisSkip("total_timeout", "anti-slop deadline exceeded", partial_outputs=outputs, checked_files=checked)
            argv = [
                str(oxlint_bin), "--config", str(config_path), "--format", "json",
                "--no-ignore", "--disable-nested-config", *chunk,
            ]
            try:
                result = subprocess.run(
                    argv,
                    cwd=config_path.resolve().parent,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=remaining,
                )
            except subprocess.TimeoutExpired as error:
                raise AnalysisSkip("total_timeout", str(error), partial_outputs=outputs, checked_files=checked) from error
            except OSError as error:
                raise AnalysisSkip("runner_error", str(error), partial_outputs=outputs, checked_files=checked) from error
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            if result.returncode not in {0, 1}:
                raise AnalysisSkip("process_failure", redact_sensitive_text(stderr[:500]), partial_outputs=outputs, checked_files=checked)
            try:
                _validate_tool_json(stdout, stderr, len(chunk))
            except AnalysisSkip as error:
                raise AnalysisSkip(
                    error.reason,
                    error.detail,
                    partial_outputs=outputs,
                    checked_files=checked,
                ) from error
            outputs.append(stdout)
            errors.append(stderr)
            checked += len(chunk)
    except CommandChunkError as error:
        raise AnalysisSkip("argument_too_large", str(error), partial_outputs=outputs, checked_files=checked) from error
    return _merge_chunk_output(outputs), "\n".join(item for item in errors if item)


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
    try:
        payload = json.loads(stdout)
    except (TypeError, ValueError) as error:
        raise AnalysisSkip("invalid_json", redact_sensitive_text((stderr or "")[:500])) from error
    raw_diagnostics = payload.get("diagnostics", []) if isinstance(payload, dict) else payload
    if not isinstance(raw_diagnostics, list):
        raise AnalysisSkip("invalid_json", redact_sensitive_text((stderr or "")[:500]))
    parsed: list[dict[str, Any]] = []
    for diagnostic in raw_diagnostics:
        if not isinstance(diagnostic, dict):
            continue
        rule = _canonical_rule_id(diagnostic.get("code", diagnostic.get("rule_id", diagnostic.get("ruleId", diagnostic.get("rule")))))
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
        if value == ".." or ".." in Path(value).parts:
            raise PathEscapeError(f"diagnostic path escapes target root: {filename}")
        return value
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError as error:
        raise PathEscapeError(f"diagnostic path escapes target root: {filename}") from error


def _target_for_filename(filename: str, target_root: Path, targets: Sequence[AnalysisTarget]) -> tuple[str, AnalysisTarget]:
    """Map a tool path to the requested logical target or reject it.

    Snapshot targets can live outside the review checkout.  An exact physical
    path match is therefore valid even when the path is outside ``target_root``.
    """
    physical = {
        target.physical_path.resolve().as_posix(): target
        for target in targets
    }
    raw = Path(filename.replace("\\", "/"))
    if raw.is_absolute():
        resolved = raw.resolve().as_posix()
        target = physical.get(resolved)
        if target is not None:
            return target.logical_path, target
    logical = _relative_path(filename, target_root)
    matches = [target for target in targets if target.logical_path == logical]
    if len(matches) != 1:
        if not matches:
            raise RunnerError(f"diagnostic refers to an unrequested file: {logical}")
        raise RunnerError(f"diagnostic path is ambiguous for requested snapshots: {logical}")
    return logical, matches[0]


def diagnostics_from_tool(diagnostics: Iterable[dict[str, Any]], target_root: Path, targets: Sequence[AnalysisTarget]) -> list[BackendDiagnostic]:
    output: list[BackendDiagnostic] = []
    for diagnostic in diagnostics:
        relpath, target = _target_for_filename(str(diagnostic.get("filename", "")), target_root, targets)
        rule_id = str(diagnostic.get("rule", ""))
        if owner_for(rule_id) != "oxlint":
            raise RunnerError(f"Oxlint returned an unexpected rule ID: {rule_id}")
        line = max(1, int(diagnostic.get("line", 0) or 0))
        column = max(0, int(diagnostic.get("column", 0) or 0))
        output.append(BackendDiagnostic(
            BACKEND_ID,
            target.language_id,
            rule_id,
            relpath,
            line,
            column,
            str(diagnostic.get("message", "")),
            {
                "source_layer": target.source_kind,
                "content_sha256": target.content_sha256,
                "config_variant": "effect" if detect_effect(target_root) else "generic",
            },
        ))
    return sorted(output, key=lambda item: (item.path, item.line, item.column, item.rule_id, item.message))


def to_candidates(diagnostics: Iterable[dict[str, Any]], target_root: Path, *, backend_id: str = BACKEND_ID) -> list[dict[str, Any]]:
    """Compatibility candidate conversion with stable content-independent IDs."""
    from review_ledger import blank_candidate, validate_candidate

    output: list[dict[str, Any]] = []
    for diagnostic in diagnostics:
        rule = str(diagnostic.get("rule", ""))
        if owner_for(rule) != "oxlint":
            raise RunnerError(f"Oxlint returned an unexpected rule ID: {rule}")
        relpath = _relative_path(str(diagnostic.get("filename", "")), target_root)
        line = max(1, int(diagnostic.get("line", 0) or 0))
        column = max(0, int(diagnostic.get("column", 0) or 0))
        identity = json.dumps({"analyser": "anti-slop", "backend": backend_id, "rule": rule, "path": relpath, "source_layer": diagnostic.get("source_layer", "working-tree"), "line": line, "column": column}, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
        candidate = blank_candidate(
            f"candidate-anti-slop-{digest}",
            source=rule,
            claim=f"{rule}: structural review candidate at {relpath}:{line}",
        )
        candidate["trigger_path"] = [f"{relpath}:{line}"]
        candidate["supporting_evidence"] = [{
            "kind": "lint_diagnostic", "backend_id": backend_id, "file": relpath,
            "line": line, "column": column, "message": str(diagnostic.get("message", "")),
            "analysis_level": "structural", "source_layer": diagnostic.get("source_layer", "working-tree"),
        }]
        errors = validate_candidate(candidate)
        if errors:
            raise RunnerError("invalid anti-slop candidate: " + "; ".join(errors))
        output.append(candidate)
    return output


def analyse(
    root: Path,
    targets: Sequence[AnalysisTarget],
    budget: AnalysisBudget,
    *,
    vendor_dir: Path = VENDOR_DIR,
    max_files: int = 250,
    max_argument_bytes: int = 24000,
    max_file_bytes: int = MAX_FILE_BYTES,
) -> BackendResult:
    applicable = tuple(sorted((target for target in targets if target.language_id in LANGUAGES), key=lambda item: item.logical_path))
    if not applicable:
        return BackendResult(BACKEND_ID, "structural", LANGUAGES, "not_applicable", 0, 0, 0, [], None, "No applicable JavaScript or TypeScript files.")
    reason = preflight(vendor_dir)
    if reason is not None:
        return BackendResult(BACKEND_ID, "structural", LANGUAGES, "unavailable", len(applicable), 0, len(applicable), [], reason, "Skill-local Oxlint runtime is unavailable.")
    runnable: list[AnalysisTarget] = []
    skipped = 0
    first_skip_reason: str | None = None
    first_skip_detail = ""
    for target in applicable:
        try:
            budget.claim_file()
            if target.physical_path.stat().st_size > max_file_bytes:
                raise AnalysisBudgetExceeded("max_file_bytes", "JavaScript or TypeScript file exceeds the structural analysis limit")
            with target.physical_path.open("rb") as source_file:
                data = source_file.read(max_file_bytes + 1)
            if len(data) > max_file_bytes:
                raise AnalysisBudgetExceeded("max_file_bytes", "JavaScript or TypeScript file exceeds the structural analysis limit")
            if b"\0" in data[:4096]:
                raise AnalysisBudgetExceeded("binary_source", "NUL byte in JavaScript or TypeScript source prefix")
            budget.claim_bytes(len(data))
            runnable.append(target)
        except AnalysisBudgetExceeded as error:
            skipped += 1
            first_skip_reason = first_skip_reason or error.reason_code
            first_skip_detail = first_skip_detail or error.detail
        except OSError as error:
            skipped += 1
            first_skip_reason = first_skip_reason or "read_failure"
            first_skip_detail = first_skip_detail or str(error)
    if not runnable:
        return BackendResult(
            BACKEND_ID, "structural", LANGUAGES, "unavailable", len(applicable), 0,
            skipped, [], first_skip_reason, first_skip_detail or "No JavaScript or TypeScript file completed structural analysis.",
        )
    config_variant = "effect" if detect_effect(root) else "generic"
    config_path = vendor_dir / ("oxlint-review-effect.json" if config_variant == "effect" else "oxlint-review.json")
    try:
        stdout, stderr = run_oxlint(
            _oxlint_path(vendor_dir), config_path, [target.physical_path for target in runnable],
            budget.remaining_seconds(), max_files=max_files, max_argument_bytes=max_argument_bytes,
        )
        diagnostics = diagnostics_from_tool(parse_diagnostics(stdout, stderr), root, runnable)
        status = "partial" if skipped else "complete"
        return BackendResult(BACKEND_ID, "structural", LANGUAGES, status, len(applicable), len(runnable), skipped, diagnostics, first_skip_reason, first_skip_detail or "Completed.")
    except AnalysisSkip as error:
        partial: list[BackendDiagnostic] = []
        if error.partial_outputs:
            try:
                partial = diagnostics_from_tool(
                    [item for output in error.partial_outputs for item in parse_diagnostics(output)],
                    root,
                    runnable,
                )
            except (AnalysisSkip, RunnerError, ValueError):
                partial = []
        checked = error.checked_files
        total_skipped = len(applicable) - checked
        return BackendResult(BACKEND_ID, "structural", LANGUAGES, "partial" if checked else "unavailable", len(applicable), checked, total_skipped, partial, error.reason, redact_sensitive_text(error.detail[:500]))
    except (RunnerError, OSError, ValueError) as error:
        return BackendResult(BACKEND_ID, "structural", LANGUAGES, "failed", len(applicable), 0, len(applicable), [], "runner_error", redact_sensitive_text(str(error)[:500]))
