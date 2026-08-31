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
from dataclasses import replace

from analysis_budget import AnalysisBudget, AnalysisBudgetExceeded
from dissect_checks.redaction import redact_sensitive_text
from file_paths import is_generated_path, is_ignored_path
from language_registry import language_for_path
from .model import AnalysisTarget, BackendDiagnostic, BackendResult, LoadedAnalysisTarget, load_target
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
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
    )


def _manifest_metadata(
    root: Path,
    target: AnalysisTarget,
    max_file_bytes: int,
    *,
    budget: AnalysisBudget | None = None,
    cache: dict[tuple[str, str, str], tuple[str, str, str, bool] | None] | None = None,
) -> tuple[str, str, str, bool]:
    """Resolve the nearest manifest from the same current source snapshot."""
    metadata_cache = cache if cache is not None else {}
    if target.source_kind not in {"working-tree", "untracked"}:
        if target.manifest_path and target.manifest_sha256:
            return target.manifest_path, target.manifest_source_layer, target.manifest_sha256, target.config_variant == "effect"
        directory = Path(target.logical_path).parent
        revision = target.revision if target.revision not in {"", "WORKTREE"} else "HEAD"
        while True:
            manifest_path = (directory / "package.json").as_posix()
            cache_key = (target.source_kind, revision, manifest_path)
            if cache_key in metadata_cache:
                metadata = metadata_cache[cache_key]
                if metadata is not None:
                    return metadata
                if directory == Path("."):
                    break
                directory = directory.parent
                continue
            reference = (
                f":{target.source_kind.split(':', 1)[-1] if target.source_kind.startswith('index:') else 0}:{manifest_path}"
                if target.source_kind.startswith("index")
                else f"{revision}:{manifest_path}"
            )
            try:
                size_result = subprocess.run(["git", "cat-file", "-s", reference], cwd=root, capture_output=True, text=True, check=False)
                size = int(size_result.stdout.strip()) if size_result.returncode == 0 else -1
            except OSError:
                size = -1
            if size < 0 or size > max_file_bytes:
                metadata_cache[cache_key] = None
                if directory == Path("."):
                    break
                directory = directory.parent
                continue
            if budget is not None:
                budget.claim_file()
                budget.claim_bytes(size)
            try:
                result = subprocess.run(
                    ["git", "show", "--format=", reference],
                    cwd=root,
                    capture_output=True,
                    check=False,
                )
                data = result.stdout if result.returncode == 0 and len(result.stdout) == size else b""
            except OSError:
                data = b""
            if data and len(data) <= max_file_bytes:
                try:
                    value = json.loads(data.decode("utf-8"))
                except (UnicodeError, ValueError):
                    value = None
                if isinstance(value, dict):
                    metadata = (manifest_path, target.source_kind, hashlib.sha256(data).hexdigest(), _has_effect_dependency(value))
                    metadata_cache[cache_key] = metadata
                    return metadata
            metadata_cache[cache_key] = None
            if directory == Path("."):
                break
            directory = directory.parent
        return "", "", "", False
    try:
        physical = target.physical_path.resolve()
        root = root.resolve()
        physical.relative_to(root)
    except (OSError, ValueError):
        return "", "", "", False
    directory = physical.parent
    while True:
        manifest = directory / "package.json"
        logical = manifest.relative_to(root).as_posix() if manifest.is_relative_to(root) else ""
        cache_key = (target.source_kind, "WORKTREE", logical)
        if cache_key in metadata_cache:
            metadata = metadata_cache[cache_key]
            if metadata is not None:
                return metadata
            if directory == root:
                break
            directory = directory.parent
            continue
        try:
            manifest.relative_to(root)
            size = manifest.stat().st_size
            if size > max_file_bytes:
                data = b""
            else:
                if budget is not None:
                    budget.claim_file()
                    budget.claim_bytes(size)
                with manifest.open("rb") as handle:
                    data = handle.read(size)
                if len(data) != size or manifest.stat().st_size != size:
                    data = b""
        except (OSError, ValueError):
            data = b""
        if data and len(data) <= max_file_bytes:
            try:
                value = json.loads(data.decode("utf-8"))
            except (UnicodeError, ValueError):
                value = None
            if isinstance(value, dict):
                metadata = (logical, target.source_kind, hashlib.sha256(data).hexdigest(), _has_effect_dependency(value))
                metadata_cache[cache_key] = metadata
                return metadata
        metadata_cache[cache_key] = None
        if directory == root:
            break
        directory = directory.parent
    return "", "", "", False


def enrich_targets(
    root: Path,
    targets: Sequence[AnalysisTarget],
    *,
    max_file_bytes: int = MAX_FILE_BYTES,
    budget: AnalysisBudget | None = None,
) -> tuple[AnalysisTarget, ...]:
    """Bind ordinary JS/TS targets to their nearest manifest before loading."""
    output: list[AnalysisTarget] = []
    cache: dict[tuple[str, str, str], tuple[str, str, str, bool] | None] = {}
    for target in targets:
        if target.language_id not in LANGUAGES or target.config_variant:
            output.append(target)
            continue
        try:
            path, layer, digest, has_effect = _manifest_metadata(
                root, target, max_file_bytes, budget=budget, cache=cache,
            )
        except AnalysisBudgetExceeded:
            # The source loader below will record the terminal budget state
            # for this target. Keep the target on the normal coverage path.
            output.append(target)
            continue
        output.append(replace(
            target,
            config_variant="effect" if has_effect else "generic",
            manifest_path=path,
            manifest_source_layer=layer,
            manifest_sha256=digest,
        ))
    return tuple(output)


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


def _is_parser_diagnostic(diagnostic: dict[str, Any]) -> bool:
    code = str(diagnostic.get("code", diagnostic.get("rule_id", diagnostic.get("ruleId", "")))).lower()
    category = str(diagnostic.get("category", diagnostic.get("severity", ""))).lower()
    message = str(diagnostic.get("message", "")).lower()
    return (
        code.startswith(("parse", "syntax", "parser"))
        or code in {"e_parse", "e-syntax", "oxlint/parse-error"}
        or "parse error" in message
        or "syntax error" in message
        or category in {"parse", "parser", "syntax"}
    )


def parse_diagnostics_with_errors(stdout: str, stderr: str = "") -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    try:
        payload = json.loads(stdout)
    except (TypeError, ValueError) as error:
        raise AnalysisSkip("invalid_json", redact_sensitive_text((stderr or "")[:500])) from error
    raw_diagnostics = payload.get("diagnostics", []) if isinstance(payload, dict) else payload
    if not isinstance(raw_diagnostics, list):
        raise AnalysisSkip("invalid_json", redact_sensitive_text((stderr or "")[:500]))
    parsed: list[dict[str, Any]] = []
    parser_errors: list[dict[str, Any]] = []
    for diagnostic in raw_diagnostics:
        if not isinstance(diagnostic, dict):
            continue
        if _is_parser_diagnostic(diagnostic):
            parser_errors.append({
                "filename": str(diagnostic.get("filename", diagnostic.get("file", diagnostic.get("path", "")))),
                "message": str(diagnostic.get("message", "Parser rejected the source."))[:240],
            })
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
    return parsed, parser_errors


def parse_diagnostics(stdout: str, stderr: str = "") -> list[dict[str, Any]]:
    """Return anti-slop diagnostics while retaining parser errors separately."""
    return parse_diagnostics_with_errors(stdout, stderr)[0]


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


def diagnostics_from_tool(
    diagnostics: Iterable[dict[str, Any]],
    target_root: Path,
    targets: Sequence[AnalysisTarget],
    *,
    config_variant: str = "",
) -> list[BackendDiagnostic]:
    output: list[BackendDiagnostic] = []
    for diagnostic in diagnostics:
        relpath, target = _target_for_filename(str(diagnostic.get("filename", "")), target_root, targets)
        rule_id = str(diagnostic.get("rule", ""))
        if owner_for(rule_id) != "oxlint":
            raise RunnerError(f"Oxlint returned an unexpected rule ID: {rule_id}")
        line = max(1, int(diagnostic.get("line", 0) or 0))
        column = max(0, int(diagnostic.get("column", 0) or 0))
        selected_variant = config_variant or target.config_variant or "generic"
        metadata = {
            "source_layer": target.source_kind,
            "content_sha256": target.content_sha256,
            "config_variant": selected_variant,
            "manifest_path": target.manifest_path,
            "manifest_source_layer": target.manifest_source_layer,
            "manifest_sha256": target.manifest_sha256,
            "discriminator": f"{rule_id}:{line}:{column}",
        }
        output.append(BackendDiagnostic(
            BACKEND_ID,
            target.language_id,
            rule_id,
            relpath,
            line,
            column,
            str(diagnostic.get("message", "")),
            metadata,
        ))
    return sorted(output, key=lambda item: (item.path, item.line, item.column, item.rule_id, item.message))


def _target_state_key(target: AnalysisTarget) -> str:
    return target.target_id


def _target_variant(target: AnalysisTarget) -> str:
    return target.config_variant or "generic"


def _load_runnable_targets(
    root: Path,
    applicable: Sequence[AnalysisTarget],
    budget: AnalysisBudget,
    max_file_bytes: int,
) -> tuple[list[AnalysisTarget], int, str | None, str]:
    runnable: list[AnalysisTarget] = []
    skipped = 0
    first_reason: str | None = None
    first_detail = ""
    for target in applicable:
        try:
            loaded = target if isinstance(target, LoadedAnalysisTarget) else load_target(
                root, target, budget, max_file_bytes=max_file_bytes,
            )
            runnable.append(loaded.target)
        except AnalysisBudgetExceeded as error:
            skipped += 1
            first_reason = first_reason or error.reason_code
            first_detail = first_detail or error.detail
        except (OSError, ValueError, TypeError) as error:
            skipped += 1
            first_reason = first_reason or "read_failure"
            first_detail = first_detail or str(error)
    return runnable, skipped, first_reason, first_detail


def _analyse_variants(
    root: Path,
    runnable: Sequence[AnalysisTarget],
    budget: AnalysisBudget,
    *,
    vendor_dir: Path,
    max_files: int,
    max_argument_bytes: int,
) -> tuple[list[BackendDiagnostic], int, str | None, str, dict[str, str], list[dict[str, Any]]]:
    parse_states = {_target_state_key(target): "not_run" for target in runnable}
    parse_errors: list[dict[str, Any]] = []
    diagnostics: list[BackendDiagnostic] = []
    checked = 0
    runner_reason: str | None = None
    runner_detail = ""
    variants: dict[str, list[AnalysisTarget]] = {}
    for target in runnable:
        variants.setdefault(_target_variant(target), []).append(target)
    for variant in sorted(variants):
        group = tuple(sorted(variants[variant], key=lambda item: (item.logical_path, item.source_kind, item.content_sha256)))
        config_name = "oxlint-review-effect.json" if variant == "effect" else "oxlint-review.json"
        try:
            stdout, stderr = run_oxlint(
                _oxlint_path(vendor_dir),
                vendor_dir / config_name,
                [target.physical_path for target in group],
                budget.remaining_seconds(),
                max_files=max_files,
                max_argument_bytes=max_argument_bytes,
            )
            parsed, parser_failures = parse_diagnostics_with_errors(stdout, stderr)
            failed_keys = _parser_failed_targets(root, group, parser_failures)
            parse_errors.extend({**failure, "config_variant": variant} for failure in parser_failures)
            diagnostics.extend(diagnostics_from_tool(parsed, root, group, config_variant=variant))
            for target in group:
                parse_states[_target_state_key(target)] = "failed" if _target_state_key(target) in failed_keys else "complete"
            checked += len(group) - len(failed_keys)
            if failed_keys:
                runner_reason = runner_reason or "parse_error"
                runner_detail = runner_detail or "Applicable source did not all parse successfully."
        except AnalysisSkip as error:
            runner_reason = runner_reason or error.reason
            runner_detail = runner_detail or redact_sensitive_text(error.detail[:500])
            completed_count = min(len(group), error.checked_files)
            checked += completed_count
            for target in group[:completed_count]:
                parse_states[_target_state_key(target)] = "complete"
            if error.partial_outputs:
                try:
                    partial_items: list[dict[str, Any]] = []
                    for output in error.partial_outputs:
                        partial_items.extend(parse_diagnostics(output))
                    diagnostics.extend(diagnostics_from_tool(partial_items, root, group[:completed_count], config_variant=variant))
                except (AnalysisSkip, RunnerError, ValueError):
                    pass
            break
        except (RunnerError, OSError, ValueError) as error:
            runner_reason = runner_reason or "runner_error"
            runner_detail = runner_detail or redact_sensitive_text(str(error)[:500])
            break
    return diagnostics, checked, runner_reason, runner_detail, parse_states, parse_errors


def _parser_failed_targets(
    root: Path,
    targets: Sequence[AnalysisTarget],
    failures: Sequence[Mapping[str, Any]],
) -> set[str]:
    failed: set[str] = set()
    unknown = False
    for failure in failures:
        filename = str(failure.get("filename", ""))
        try:
            _logical, target = _target_for_filename(filename, root, targets)
            failed.add(_target_state_key(target))
        except (PathEscapeError, RunnerError):
            unknown = True
    if unknown:
        failed.update(_target_state_key(target) for target in targets)
    return failed


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
    applicable = tuple(sorted(
        (target for target in targets if target.language_id in LANGUAGES),
        key=lambda item: (item.logical_path, item.source_kind, item.content_sha256),
    ))
    if not applicable:
        return BackendResult(
            BACKEND_ID, "structural", LANGUAGES, "not_applicable",
            0, 0, 0, [], None, "No applicable JavaScript or TypeScript files.",
        )
    reason = preflight(vendor_dir)
    if reason is not None:
        return BackendResult(
            BACKEND_ID, "structural", LANGUAGES, "unavailable", len(applicable), 0,
            len(applicable), [], reason, "Skill-local Oxlint runtime is unavailable.",
        )

    runnable, skipped, first_skip_reason, first_skip_detail = _load_runnable_targets(
        root, applicable, budget, max_file_bytes,
    )

    diagnostics, checked, runner_reason, runner_detail, parse_states, parse_errors = _analyse_variants(
        root,
        runnable,
        budget,
        vendor_dir=vendor_dir,
        max_files=max_files,
        max_argument_bytes=max_argument_bytes,
    )

    diagnostics.sort(key=lambda item: (item.path, item.line, item.column, item.rule_id, item.message))
    total_skipped = len(applicable) - checked
    if runner_reason or skipped:
        status = "partial" if checked else "unavailable"
    else:
        status = "complete"
    reason_code = runner_reason or first_skip_reason
    reason_text = runner_detail or first_skip_detail or "Completed."
    return BackendResult(
        BACKEND_ID,
        "structural",
        LANGUAGES,
        status,
        len(applicable),
        checked,
        total_skipped,
        diagnostics,
        reason_code,
        reason_text,
        parse_states,
        parse_errors,
    )
