"""Pinned ast-grep structural backend for the first polyglot rule packs."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from typing import Any, Iterable, Sequence

from analysis_budget import AnalysisBudget, AnalysisBudgetExceeded
from dissect_checks.redaction import redact_sensitive_text
from .model import AnalysisTarget, BackendDiagnostic, BackendResult, LoadedAnalysisTarget, load_target
from .chunking import CommandChunkError, iter_command_chunks
from .rules import owner_for


VENDOR_DIR = Path(__file__).resolve().parents[2] / "vendor" / "anti-slop"
CONFIG_PATH = VENDOR_DIR / "ast-grep" / "sgconfig.yml"
MAX_FILE_BYTES = 10 * 1024 * 1024

BACKENDS = {
    "ast-grep-go": ("go", "Go", "anti-slop-go"),
    "ast-grep-rust": ("rust", "Rust", "anti-slop-rust"),
    "ast-grep-c": ("c", "C", "anti-slop-c"),
    "ast-grep-cpp": ("cpp", "Cpp", "anti-slop-cpp"),
    "ast-grep-java": ("java", "Java", "anti-slop-java"),
    "ast-grep-csharp": ("csharp", "CSharp", "anti-slop-csharp"),
}


def binary_path(vendor_dir: Path = VENDOR_DIR) -> Path:
    binary = vendor_dir / "node_modules" / ".bin" / "ast-grep"
    return binary.with_suffix(".cmd") if os.name == "nt" and not binary.exists() else binary


def preflight(vendor_dir: Path = VENDOR_DIR) -> str | None:
    if not binary_path(vendor_dir).is_file():
        return "deps_missing"
    if not (vendor_dir / "ast-grep" / "sgconfig.yml").is_file():
        return "rules_missing"
    return None


def _delimiter_error(source: bytes) -> str | None:
    """Catch bounded, target-local syntax truncation before AST matching."""
    text = source.decode("utf-8", errors="replace")
    pairs = {"(": ")", "[": "]", "{": "}"}
    closing = set(pairs.values())
    stack: list[str] = []
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char == "/" and next_char == "/":
            line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            block_comment = True
            index += 2
            continue
        if char in {'"', "'", "`"}:
            quote = char
        elif char in pairs:
            stack.append(pairs[char])
        elif char in closing:
            if not stack or stack.pop() != char:
                return "unbalanced_delimiters"
        index += 1
    if quote or block_comment or stack:
        return "unbalanced_delimiters"
    return None


def _location(value: Any) -> tuple[int, int]:
    if isinstance(value, dict):
        start = value.get("start", value)
        if isinstance(start, dict):
            try:
                return max(1, int(start.get("line", 0)) + 1), max(0, int(start.get("column", 0)))
            except (TypeError, ValueError):
                pass
    return 1, 0


def _raw_matches(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    raise ValueError("ast-grep output is not a JSON array")


def _parse_output(stdout: str) -> list[dict[str, Any]]:
    try:
        return _raw_matches(json.loads(stdout))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("invalid ast-grep JSON output") from error


def _rule_id(value: dict[str, Any]) -> str:
    for key in ("ruleId", "rule_id", "rule", "id"):
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate:
            return candidate
    metadata = value.get("meta") or value.get("metadata")
    if isinstance(metadata, dict):
        for key in ("id", "rule_id", "ruleId"):
            candidate = metadata.get(key)
            if isinstance(candidate, str) and candidate:
                return candidate
    return ""


def _path(value: dict[str, Any]) -> str:
    for key in ("file", "filename", "path"):
        candidate = value.get(key)
        if isinstance(candidate, str):
            return candidate.replace("\\", "/")
    return ""


def _message(value: dict[str, Any]) -> str:
    for key in ("message", "text", "reason"):
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate:
            return candidate
    return "Structural anti-slop match."


def _matches_to_diagnostics(matches: Iterable[dict[str, Any]], root: Path, targets: Sequence[AnalysisTarget], prefix: str) -> list[BackendDiagnostic]:
    physical = {target.physical_path.resolve().as_posix(): target for target in targets}
    requested: dict[str, list[AnalysisTarget]] = {}
    for target in targets:
        requested.setdefault(target.logical_path, []).append(target)
    output: list[BackendDiagnostic] = []
    for match in matches:
        raw_path = _path(match)
        path = Path(raw_path)
        if path.is_absolute():
            target = physical.get(path.resolve().as_posix())
            if target is not None:
                logical = target.logical_path
            else:
                try:
                    logical = path.resolve().relative_to(root.resolve()).as_posix()
                except ValueError as error:
                    raise ValueError(f"ast-grep diagnostic path escapes root: {raw_path}") from error
                matches_for_path = requested.get(logical, [])
                if len(matches_for_path) != 1:
                    raise ValueError(f"ast-grep diagnostic refers to an unrequested file: {logical}")
                target = matches_for_path[0]
        else:
            logical = path.as_posix()
            while logical.startswith("./"):
                logical = logical[2:]
            if logical == ".." or ".." in Path(logical).parts:
                raise ValueError(f"ast-grep diagnostic path escapes root: {raw_path}")
            matches_for_path = requested.get(logical, [])
            if len(matches_for_path) != 1:
                raise ValueError(f"ast-grep diagnostic refers to an unrequested file: {logical}")
            target = matches_for_path[0]
        rule = _rule_id(match)
        if not rule:
            continue
        if "/" not in rule:
            rule = f"{prefix}/{rule}"
        if not rule.startswith(prefix + "/") or owner_for(rule) != prefix.replace("anti-slop-", "ast-grep-"):
            raise ValueError(f"ast-grep returned an unexpected rule ID: {rule}")
        line, column = _location(match.get("range", match.get("location", match)))
        output.append(BackendDiagnostic(
            prefix.replace("anti-slop-", "ast-grep-"),
            target.language_id,
            rule,
            logical,
            line,
            column,
            _message(match),
            {
                "source_layer": target.source_kind,
                "content_sha256": target.content_sha256,
                "analysis_level": "structural",
                "discriminator": f"{rule}:{line}:{column}",
                "metadata": match.get("meta", match.get("metadata", {})),
            },
        ))
    return sorted(output, key=lambda item: (item.path, item.line, item.column, item.rule_id, item.message))


def _run_language(
    backend_id: str,
    root: Path,
    targets: Sequence[AnalysisTarget],
    budget: AnalysisBudget,
    *,
    vendor_dir: Path,
    max_files: int,
    max_argument_bytes: int,
    threads: int = 0,
) -> tuple[list[BackendDiagnostic], int, str | None, str]:
    language_id, language_name, prefix = BACKENDS[backend_id]
    values = [str(target.physical_path) for target in targets]
    diagnostics: list[BackendDiagnostic] = []
    checked = 0
    try:
        for chunk in iter_command_chunks(values, max_files, max_argument_bytes):
            remaining = budget.remaining_seconds()
            if remaining <= 0:
                return diagnostics, checked, "total_timeout", "ast-grep deadline exceeded"
            argv = [
                str(binary_path(vendor_dir)), "scan", "--config", str(vendor_dir / "ast-grep" / "sgconfig.yml"),
                "--filter", prefix, "--json=compact", "--include-metadata", "--color", "never",
                "--no-ignore", "hidden", "--no-ignore", "dot", "--no-ignore", "exclude",
                "--no-ignore", "global", "--no-ignore", "parent", "--no-ignore", "vcs",
            ]
            if threads > 0:
                argv.extend(["--threads", str(threads)])
            argv.extend(chunk)
            try:
                completed = subprocess.run(argv, cwd=vendor_dir, capture_output=True, text=True, check=False, timeout=remaining)
            except subprocess.TimeoutExpired as error:
                return diagnostics, checked, "total_timeout", str(error)
            except OSError as error:
                return diagnostics, checked, "runner_error", str(error)
            if completed.returncode not in {0, 1}:
                return diagnostics, checked, "process_failure", redact_sensitive_text((completed.stderr or "")[:500])
            try:
                matches = _parse_output(completed.stdout or "")
                diagnostics.extend(_matches_to_diagnostics(matches, root, targets[checked:checked + len(chunk)], prefix))
            except ValueError as error:
                return diagnostics, checked, "invalid_json", str(error)
            checked += len(chunk)
    except CommandChunkError as error:
        return diagnostics, checked, "argument_too_large", str(error)
    return diagnostics, checked, None, "Completed."


def _prepare_targets(
    root: Path,
    applicable: Sequence[AnalysisTarget],
    budget: AnalysisBudget,
    max_file_bytes: int,
) -> tuple[list[AnalysisTarget], int, str | None, str, dict[str, str], list[dict[str, Any]]]:
    runnable: list[AnalysisTarget] = []
    skipped = 0
    first_reason: str | None = None
    first_detail = ""
    parse_states: dict[str, str] = {}
    parse_errors: list[dict[str, Any]] = []
    for target in applicable:
        try:
            loaded = target if isinstance(target, LoadedAnalysisTarget) else load_target(
                root, target, budget, max_file_bytes=max_file_bytes,
            )
            target = loaded.target
            syntax_error = _delimiter_error(loaded.data)
            key = target.target_id
            if syntax_error is not None:
                skipped += 1
                first_reason = first_reason or "parse_error"
                first_detail = first_detail or syntax_error
                parse_states[key] = "failed"
                parse_errors.append({"path": target.logical_path, "reason_code": "parse_error", "detail": syntax_error})
                continue
            runnable.append(target)
            parse_states[key] = "not_run"
        except AnalysisBudgetExceeded as error:
            skipped += 1
            first_reason = first_reason or error.reason_code
            first_detail = first_detail or error.detail
            parse_states[target.target_id] = "failed"
            parse_errors.append({"path": target.logical_path, "reason_code": error.reason_code})
            if error.reason_code in {"total_timeout", "max_files", "max_total_bytes"}:
                break
        except (OSError, ValueError, TypeError) as error:
            skipped += 1
            first_reason = first_reason or "read_failure"
            first_detail = first_detail or str(error)
            parse_states[target.target_id] = "failed"
            parse_errors.append({"path": target.logical_path, "reason_code": "read_failure", "detail": str(error)[:240]})
    return runnable, skipped, first_reason, first_detail, parse_states, parse_errors


def analyse(
    root: Path,
    targets: Sequence[AnalysisTarget],
    budget: AnalysisBudget,
    *,
    vendor_dir: Path = VENDOR_DIR,
    max_files: int = 250,
    max_argument_bytes: int = 24000,
    threads: int = 0,
    max_file_bytes: int = MAX_FILE_BYTES,
) -> BackendResult:
    backend_id = next((key for key, (language, *_rest) in BACKENDS.items() if any(target.language_id == language for target in targets)), "")
    if not backend_id:
        languages = tuple(sorted({language for language, _name, _prefix in BACKENDS.values()}))
        return BackendResult("ast-grep", "structural", languages, "not_applicable", 0, 0, 0, [], None, "No applicable ast-grep files.")
    language_id, _language_name, _prefix = BACKENDS[backend_id]
    applicable = tuple(sorted((target for target in targets if target.language_id == language_id), key=lambda item: item.logical_path))
    reason = preflight(vendor_dir)
    if reason is not None:
        return BackendResult(backend_id, "structural", (language_id,), "unavailable", len(applicable), 0, len(applicable), [], reason, "Skill-local ast-grep runtime is unavailable.")
    runnable, skipped, first_skip_reason, first_skip_detail, parse_states, parse_errors = _prepare_targets(
        root, applicable, budget, max_file_bytes,
    )
    if not runnable:
        return BackendResult(
            backend_id, "structural", (language_id,), "unavailable", len(applicable), 0,
            skipped, [], first_skip_reason, first_skip_detail or "No source file completed structural analysis.",
            parse_states, parse_errors,
        )
    diagnostics, checked, reason_code, reason_text = _run_language(
        backend_id, root, tuple(runnable), budget, vendor_dir=vendor_dir,
        max_files=max_files, max_argument_bytes=max_argument_bytes, threads=threads,
    )
    if reason_code:
        for target in runnable[:checked]:
            parse_states[target.target_id] = "complete"
        for target in runnable[checked:]:
            parse_states[target.target_id] = "not_verified"
        parse_errors.append({"reason_code": reason_code, "detail": reason_text[:240]})
        return BackendResult(backend_id, "structural", (language_id,), "partial" if checked else "unavailable", len(applicable), checked, len(applicable) - checked, diagnostics, reason_code, reason_text, parse_states, parse_errors)
    for target in runnable:
        parse_states[target.target_id] = "complete"
    status = "partial" if skipped else "complete"
    return BackendResult(backend_id, "structural", (language_id,), status, len(applicable), checked, skipped, diagnostics, first_skip_reason, first_skip_detail or "Completed.", parse_states, parse_errors)
