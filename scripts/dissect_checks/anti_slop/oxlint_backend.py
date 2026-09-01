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
OXLINT_VERSION = "1.78.0"
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
    binary = _oxlint_path(vendor_dir)
    if not binary.is_file():
        return "deps_missing"
    try:
        tool = subprocess.run([str(binary), "--version"], capture_output=True, text=True, check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return "tool_version_unavailable"
    if tool.returncode != 0 or OXLINT_VERSION not in f"{tool.stdout}\n{tool.stderr}":
        return "tool_version_unsupported"
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
        isinstance(data.get(section), dict)
        and any(
            str(name).lower() == "effect" or str(name).lower().startswith("@effect/")
            for name in data[section]
        )
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
    )


def _physical_snapshot_manifest(
    target: AnalysisTarget,
    max_file_bytes: int,
    *,
    budget: AnalysisBudget | None,
    cache: dict[tuple[str, str, str], tuple[str, str, str, bool] | None],
) -> tuple[str, str, str, bool]:
    """Resolve a manifest beside an explicitly materialised target tree."""
    try:
        physical = target.physical_path.resolve(strict=True)
    except OSError:
        return "", "", "", False
    logical_parts = Path(target.logical_path).parts
    snapshot_root = physical
    for _ in logical_parts:
        snapshot_root = snapshot_root.parent
    directory = physical.parent
    while directory == snapshot_root or snapshot_root in directory.parents:
        manifest = directory / "package.json"
        manifest_path = manifest.relative_to(snapshot_root).as_posix()
        cache_key = ("physical:" + target.source_kind, str(snapshot_root), manifest_path)
        if cache_key in cache:
            value = cache[cache_key]
            if value is not None:
                return value
        try:
            size = manifest.stat().st_size
        except OSError:
            cache[cache_key] = None
            if directory == snapshot_root:
                break
            directory = directory.parent
            continue
        if size > max_file_bytes:
            value = (manifest_path, target.source_kind, "", False)
            cache[cache_key] = value
            return value
        try:
            if budget is not None:
                budget.claim_source(size)
            with manifest.open("rb") as handle:
                data = handle.read(size)
            if len(data) != size or manifest.stat().st_size != size:
                value = (manifest_path, target.source_kind, "", False)
                cache[cache_key] = value
                return value
            digest = hashlib.sha256(data).hexdigest()
            parsed = json.loads(data.decode("utf-8"))
        except AnalysisBudgetExceeded:
            raise
        except (OSError, UnicodeError, ValueError):
            value = (manifest_path, target.source_kind, "", False)
            cache[cache_key] = value
            return value
        if not isinstance(parsed, dict):
            value = (manifest_path, target.source_kind, digest, False)
        else:
            value = (manifest_path, target.source_kind, digest, _has_effect_dependency(parsed))
        cache[cache_key] = value
        return value
    return "", "", "", False


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
    if target.physical_snapshot:
        try:
            physical = target.physical_path.resolve()
            physical.relative_to(root.resolve())
            use_physical_snapshot = target.data is not None
        except (OSError, ValueError):
            use_physical_snapshot = True
        if use_physical_snapshot:
            return _physical_snapshot_manifest(
                target,
                max_file_bytes,
                budget=budget,
                cache=metadata_cache,
            )
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
            if target.source_kind.startswith("index"):
                stage = _index_stage(target)
                reference = f":{stage}:{manifest_path}"
            else:
                reference = f"{revision}:{manifest_path}"
            try:
                size_result = subprocess.run(["git", "cat-file", "-s", reference], cwd=root, capture_output=True, text=True, check=False)
                size = int(size_result.stdout.strip()) if size_result.returncode == 0 else -1
            except (OSError, subprocess.SubprocessError, ValueError):
                size = -1
            if size < 0:
                metadata_cache[cache_key] = None
                if directory == Path("."):
                    break
                directory = directory.parent
                continue
            if size > max_file_bytes:
                # A nearest manifest which cannot be bounded is still the
                # applicable manifest. Do not inherit a parent package's
                # Effect configuration and silently analyse with the wrong
                # rule pack.
                metadata = (manifest_path, target.source_kind, "", False)
                metadata_cache[cache_key] = metadata
                return metadata
            if budget is not None:
                budget.claim_source(size)
            try:
                result = subprocess.run(
                    ["git", "show", "--format=", reference],
                    cwd=root,
                    capture_output=True,
                    check=False,
                    timeout=5,
                )
                data = result.stdout if result.returncode == 0 and len(result.stdout) == size else b""
            except (OSError, subprocess.SubprocessError):
                data = b""
            if data is not None and len(data) <= max_file_bytes:
                digest = hashlib.sha256(data).hexdigest()
                try:
                    value = json.loads(data.decode("utf-8"))
                except (UnicodeError, ValueError):
                    # A nearest manifest still owns the source snapshot even
                    # when it is malformed.  Do not silently inherit a
                    # parent package's Effect configuration.
                    metadata = (manifest_path, target.source_kind, digest, False)
                    metadata_cache[cache_key] = metadata
                    return metadata
                if isinstance(value, dict):
                    metadata = (manifest_path, target.source_kind, digest, _has_effect_dependency(value))
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
                    budget.claim_source(size)
                with manifest.open("rb") as handle:
                    data = handle.read(size)
                if len(data) != size or manifest.stat().st_size != size:
                    data = b""
        except (OSError, ValueError):
            data = b""
        if data is not None and len(data) <= max_file_bytes:
            digest = hashlib.sha256(data).hexdigest()
            try:
                value = json.loads(data.decode("utf-8"))
            except (UnicodeError, ValueError):
                metadata = (logical, target.source_kind, digest, False)
                metadata_cache[cache_key] = metadata
                return metadata
            if isinstance(value, dict):
                metadata = (logical, target.source_kind, digest, _has_effect_dependency(value))
                metadata_cache[cache_key] = metadata
                return metadata
        metadata_cache[cache_key] = None
        if directory == root:
            break
        directory = directory.parent
    return "", "", "", False


def _index_stage(target: AnalysisTarget) -> int:
    """Return the Git index stage encoded by a snapshot target.

    Diff entries normally use stage zero.  Accept the explicit ``index:N``
    form and a numeric revision as well so callers cannot accidentally read
    the current HEAD manifest for an index target.
    """
    value = ""
    if ":" in target.source_kind:
        value = target.source_kind.rsplit(":", 1)[-1]
    elif target.revision.startswith(":"):
        value = target.revision[1:].split(":", 1)[0]
    elif target.revision.isdigit():
        value = target.revision
    try:
        stage = int(value or "0")
    except ValueError:
        stage = 0
    return stage if 0 <= stage <= 3 else 0


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
            # A budget failure while resolving the variant is evidence that
            # this target was not analysed with a known rule configuration.
            # Do not silently fall back to the generic pack.
            output.append(replace(target, config_variant="unavailable"))
            continue
        if path and not digest:
            # A nearest manifest exists but is too large or unavailable. It
            # still owns the target's configuration; inheriting a parent or
            # generic pack would mix source snapshots.
            output.append(replace(
                target,
                config_variant="unavailable",
                manifest_path=path,
                manifest_source_layer=layer,
                manifest_sha256=digest,
            ))
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
    raw_code = diagnostic.get("code", diagnostic.get("rule_id", diagnostic.get("ruleId", "")))
    code = str(raw_code).lower()
    category = str(diagnostic.get("category", diagnostic.get("severity", ""))).lower()
    message = str(diagnostic.get("message", "")).lower()
    # Oxlint's parser diagnostics intentionally have no rule code.  They use
    # messages such as "Unexpected token" and "Expected `}` but found `EOF`".
    # Filtering only by anti-slop rule IDs would otherwise turn malformed
    # source into a false complete result.
    has_known_rule = bool(_canonical_rule_id(raw_code))
    parser_message = bool(re.search(
        r"\b(?:unexpected\s+(?:token|character|end)|expected\b.*\b(?:found|eof|statement)|"
        r"unterminated\b|missing\s+['`\"]|invalid\s+(?:character|syntax)|"
        r"parse(?:r)?\s+error|syntax\s+error)\b",
        message,
        re.I,
    ))
    return (
        code.startswith(("parse", "syntax", "parser"))
        or code in {"e_parse", "e-syntax", "oxlint/parse-error"}
        or (not has_known_rule and parser_message)
        or (not has_known_rule and category == "error" and not code and bool(diagnostic.get("labels")))
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
                "message": redact_sensitive_text(str(diagnostic.get("message", "Parser rejected the source."))[:240]),
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
    # Some tool versions print a parser failure to stderr and leave an empty
    # JSON diagnostics array.  Preserve that failure as target-wide evidence;
    # the caller will conservatively mark the requested group incomplete.
    if not parser_errors and not parsed and re.search(
        r"\b(?:parse(?:r)?\s+error|syntax\s+error|unexpected\s+(?:token|character|end)|"
        r"expected\b.*\b(?:found|eof))\b",
        stderr or "",
        re.I,
    ):
        parser_errors.append({
            "filename": "",
            "message": redact_sensitive_text((stderr or "Parser rejected the source.")[:240]),
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
            redact_sensitive_text(str(diagnostic.get("message", ""))),
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
) -> tuple[list[AnalysisTarget], int, str | None, str, dict[str, str], list[dict[str, Any]]]:
    runnable: list[AnalysisTarget] = []
    skipped = 0
    first_reason: str | None = None
    first_detail = ""
    parse_states: dict[str, str] = {}
    parse_errors: list[dict[str, Any]] = []
    for index, target in enumerate(applicable):
        original_target = target.target if isinstance(target, LoadedAnalysisTarget) else target
        raw_key = original_target.target_id
        try:
            loaded = target if isinstance(target, LoadedAnalysisTarget) else load_target(
                root, target, budget, max_file_bytes=max_file_bytes,
            )
            runnable.append(loaded.target)
            parse_states[loaded.target.target_id] = "not_run"
        except AnalysisBudgetExceeded as error:
            skipped += 1
            first_reason = first_reason or error.reason_code
            first_detail = first_detail or error.detail
            parse_states[raw_key] = "failed"
            parse_errors.append({"path": original_target.logical_path, "reason_code": error.reason_code, "detail": error.detail[:240]})
            if error.reason_code in {"total_timeout", "max_files", "max_total_bytes"}:
                for remaining in applicable[index + 1:]:
                    remaining_target = remaining.target if isinstance(remaining, LoadedAnalysisTarget) else remaining
                    parse_states[remaining_target.target_id] = "not_verified"
                skipped += len(applicable) - index - 1
                break
        except (OSError, ValueError, TypeError) as error:
            skipped += 1
            first_reason = first_reason or "read_failure"
            first_detail = first_detail or str(error)
            parse_states[raw_key] = "failed"
            parse_errors.append({"path": original_target.logical_path, "reason_code": "read_failure", "detail": str(error)[:240]})
    return runnable, skipped, first_reason, first_detail, parse_states, parse_errors


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
            for target in group[completed_count:]:
                parse_states[_target_state_key(target)] = "not_verified"
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
            for target in group:
                parse_states[_target_state_key(target)] = "not_verified"
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
    unresolved_configuration = tuple(
        target for target in applicable
        if (target.target if isinstance(target, LoadedAnalysisTarget) else target).config_variant == "unavailable"
    )
    runnable_configuration = tuple(
        target for target in applicable
        if (target.target if isinstance(target, LoadedAnalysisTarget) else target).config_variant != "unavailable"
    )
    reason = preflight(vendor_dir) if runnable_configuration else None
    if reason is not None:
        state = {
            (target.target if isinstance(target, LoadedAnalysisTarget) else target).target_id: "not_verified"
            for target in applicable
        }
        return BackendResult(
            BACKEND_ID, "structural", LANGUAGES, "unavailable", len(applicable), 0,
            len(applicable), [], reason, "Skill-local Oxlint runtime is unavailable.",
            state,
            [{"path": (target.target if isinstance(target, LoadedAnalysisTarget) else target).logical_path, "reason_code": reason} for target in applicable[:3]],
        )

    runnable, skipped, first_skip_reason, first_skip_detail, load_parse_states, load_parse_errors = _load_runnable_targets(
        root, runnable_configuration, budget, max_file_bytes,
    )

    diagnostics, checked, runner_reason, runner_detail, parse_states, parse_errors = _analyse_variants(
        root,
        runnable,
        budget,
        vendor_dir=vendor_dir,
        max_files=max_files,
        max_argument_bytes=max_argument_bytes,
    )
    for key, value in load_parse_states.items():
        parse_states.setdefault(key, value)
    parse_errors = [*load_parse_errors, *parse_errors]
    for target in unresolved_configuration:
        base_target = target.target if isinstance(target, LoadedAnalysisTarget) else target
        parse_states[base_target.target_id] = "failed"
        parse_errors.append({
            "path": base_target.logical_path,
            "reason_code": "manifest_unavailable",
        })
    if unresolved_configuration:
        skipped += len(unresolved_configuration)
        first_skip_reason = first_skip_reason or "manifest_unavailable"
        first_skip_detail = first_skip_detail or "The nearest package manifest was unavailable or exceeded the source limit."

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
