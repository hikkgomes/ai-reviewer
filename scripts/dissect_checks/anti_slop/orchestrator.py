"""Stable orchestration for structural anti-slop backends."""
from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Sequence

from analysis_budget import AnalysisBudget, analysis_limits
from file_paths import is_generated_path, is_ignored_path
from language_registry import ambiguous_header_paths, language_for_path, paths_for_anti_slop
from review_ledger import blank_candidate, validate_candidate
from . import ast_grep_backend, oxlint_backend, python_ast_backend
from .model import AnalysisTarget, BackendDiagnostic, BackendResult


BACKEND_ORDER = (
    "oxlint-js-ts", "python-ast", "ast-grep-go", "ast-grep-rust",
    "ast-grep-c", "ast-grep-cpp", "ast-grep-java", "ast-grep-csharp",
)
BACKEND_LANGUAGES = {
    "oxlint-js-ts": ("javascript", "typescript"),
    "python-ast": ("python",),
    **{key: (value[0],) for key, value in ast_grep_backend.BACKENDS.items()},
}


def _content_hash(path: Path) -> str:
    limit = 10 * 1024 * 1024
    try:
        with path.open("rb") as source_file:
            data = source_file.read(limit + 1)
        if len(data) > limit:
            return ""
        return hashlib.sha256(data).hexdigest()
    except OSError:
        return ""


def build_targets(
    root: Path,
    paths: Iterable[str | Path],
    *,
    source_kind: str = "working-tree",
    revision: str = "WORKTREE",
    excluded_paths: Iterable[str | Path] = (),
) -> tuple[AnalysisTarget, ...]:
    """Build validated structural targets after language and path filtering."""
    root = root.resolve()
    excluded = {Path(path).as_posix() for path in excluded_paths}
    values: list[str] = []
    for value in paths:
        candidate = Path(value)
        if candidate.is_absolute():
            try:
                values.append(candidate.resolve().relative_to(root).as_posix())
            except ValueError:
                continue
        else:
            values.append(candidate.as_posix())
    grouped = paths_for_anti_slop(values)
    backend_targets: list[AnalysisTarget] = []
    for backend_id in BACKEND_ORDER:
        expected_languages = BACKEND_LANGUAGES[backend_id]
        for relative in grouped.get(backend_id, ()):
            if relative in excluded or is_ignored_path(root, relative):
                continue
            physical = (root / relative).resolve()
            try:
                physical.relative_to(root)
            except ValueError:
                continue
            if not physical.is_file():
                continue
            language_id = language_for_path(relative)
            language = expected_languages[0] if relative.lower().endswith(".h") else language_id.language_id if language_id is not None and language_id.language_id in expected_languages else expected_languages[0]
            backend_targets.append(AnalysisTarget(relative, physical, language, source_kind, revision, _content_hash(physical)))
    return tuple(sorted({target.logical_path: target for target in backend_targets}.values(), key=lambda item: (BACKEND_ORDER.index(_backend_for_language(item.language_id)), item.logical_path)))


def _backend_for_language(language_id: str) -> str:
    return next(backend for backend, languages in BACKEND_LANGUAGES.items() if language_id in languages)


def _candidate(diagnostics: Sequence[BackendDiagnostic]) -> dict[str, Any]:
    ordered = tuple(sorted(
        diagnostics,
        key=lambda item: (
            item.path,
            str(item.metadata.get("source_layer", "working-tree")),
            str(item.metadata.get("content_sha256", "")),
            item.line,
            item.column,
            item.backend_id,
            item.rule_id,
            item.message,
        ),
    ))
    diagnostic = ordered[0]
    identity = json.dumps({
        "analyser": "anti-slop",
        "diagnostics": [{
            "backend": item.backend_id,
            "rule": item.rule_id,
            "path": item.path,
            "source_layer": str(item.metadata.get("source_layer", "working-tree")),
            "content_sha256": item.metadata.get("content_sha256", ""),
            "line": item.line,
            "column": item.column,
            "discriminator": item.metadata.get("discriminator", ""),
        } for item in ordered],
    }, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
    candidate = blank_candidate(
        f"candidate-anti-slop-{digest}",
        source=diagnostic.rule_id,
        claim=f"{diagnostic.rule_id}: structural review candidate at {diagnostic.path}:{diagnostic.line}",
        contract="Confirm the concrete harmful behaviour and its semantic impact before reporting.",
    )
    candidate["trigger_path"] = [f"{diagnostic.path}:{diagnostic.line}"]
    candidate["supporting_evidence"] = [
        {
            "kind": "structural_diagnostic",
            "backend_id": item.backend_id,
            "language_id": item.language_id,
            "rule_id": item.rule_id,
            "file": item.path,
            "line": item.line,
            "column": item.column,
            "message": item.message,
            "source_layer": str(item.metadata.get("source_layer", "working-tree")),
            "analysis_level": "structural",
            "metadata": dict(item.metadata),
        }
        for item in ordered
    ]
    errors = validate_candidate(candidate)
    if errors:
        raise ValueError("invalid anti-slop candidate: " + "; ".join(errors))
    return candidate


def _budget(limits: dict[str, int | float]) -> AnalysisBudget:
    return AnalysisBudget(
        float(limits["anti_slop_timeout_seconds"]),
        int(limits["anti_slop_max_files"]),
        int(limits["anti_slop_max_total_bytes"]),
        int(limits["anti_slop_max_candidates"]),
    )


def _empty_result(backend_id: str) -> BackendResult:
    return BackendResult(backend_id, "structural", BACKEND_LANGUAGES[backend_id], "not_applicable", 0, 0, 0, [], None, f"No applicable {', '.join(BACKEND_LANGUAGES[backend_id])} files.")


def _validated_targets(root: Path, targets: Iterable[AnalysisTarget], config: dict[str, Any]) -> tuple[AnalysisTarget, ...]:
    selected: dict[tuple[str, str, str], AnalysisTarget] = {}
    root_resolved = root.resolve()
    for target in targets:
        logical = Path(target.logical_path)
        if logical.is_absolute() or not logical.parts or ".." in logical.parts:
            continue
        relative = logical.as_posix()
        spec = language_for_path(relative, header_language=target.language_id)
        if spec is None or spec.anti_slop_backend is None:
            continue
        if relative.lower().endswith(".h"):
            if target.language_id not in {"c", "cpp"}:
                continue
        elif spec.language_id != target.language_id:
            continue
        if is_ignored_path(root, relative) or is_generated_path(root, root / relative, config):
            continue
        physical = target.physical_path if target.physical_path.is_absolute() else root / target.physical_path
        try:
            resolved = physical.resolve()
            inside_root = resolved.is_relative_to(root_resolved)
        except (OSError, ValueError):
            continue
        source_layers = set(target.source_kind.split("+"))
        if not inside_root and not source_layers <= {"commit", "index"}:
            continue
        if not resolved.is_file():
            continue
        key = (relative, target.source_kind, target.content_sha256)
        selected[key] = replace(target, logical_path=relative, physical_path=resolved)
    return tuple(sorted(selected.values(), key=lambda item: (item.logical_path, item.source_kind, item.content_sha256)))


def analyse(
    root: Path,
    paths: Iterable[str | Path] | None = None,
    *,
    targets: Sequence[AnalysisTarget] | None = None,
    ambiguous_paths: Iterable[str | Path] | None = None,
    config: dict[str, Any] | None = None,
    vendor_dir: Path = oxlint_backend.VENDOR_DIR,
) -> dict[str, Any]:
    """Run enabled structural backends and return deterministic evidence."""
    root = root.resolve()
    limits = analysis_limits(config or {})
    if targets is not None:
        target_values = _validated_targets(root, targets, config or {})
        selected_paths: tuple[str | Path, ...] = tuple(paths or ())
    else:
        selected_paths = tuple(
            value for value in (paths or ())
            if not is_generated_path(root, root / Path(value), config or {})
        )
        target_values = build_targets(root, selected_paths)
    by_backend: dict[str, list[AnalysisTarget]] = {backend: [] for backend in BACKEND_ORDER}
    for target in target_values:
        backend = _backend_for_language(target.language_id)
        by_backend[backend].append(target)

    results: list[BackendResult] = []
    anti_budget = _budget(limits)
    for backend_id in BACKEND_ORDER:
        backend_targets = tuple(sorted(by_backend[backend_id], key=lambda item: item.logical_path))
        if not backend_targets:
            results.append(_empty_result(backend_id))
            continue
        if backend_id == "oxlint-js-ts":
            result = oxlint_backend.analyse(
                root, backend_targets, anti_budget, vendor_dir=vendor_dir,
                max_files=int(limits["external_command_max_files"]),
                max_argument_bytes=int(limits["external_command_max_argument_bytes"]),
                max_file_bytes=int(limits["anti_slop_max_file_bytes"]),
            )
        elif backend_id == "python-ast":
            result = python_ast_backend.analyse(
                root, backend_targets, anti_budget,
                max_file_bytes=int(limits["anti_slop_max_file_bytes"]),
            )
        else:
            result = ast_grep_backend.analyse(
                root, backend_targets, anti_budget, vendor_dir=vendor_dir,
                max_files=int(limits["external_command_max_files"]),
                max_argument_bytes=int(limits["external_command_max_argument_bytes"]),
                threads=int(limits["worker_threads"]),
                max_file_bytes=int(limits["anti_slop_max_file_bytes"]),
            )
        results.append(result)

    ambiguous_scope = ambiguous_paths if ambiguous_paths is not None else selected_paths
    ambiguous = list(ambiguous_header_paths(ambiguous_scope))
    if ambiguous:
        for backend_id in ("ast-grep-c", "ast-grep-cpp"):
            current = next((item for item in results if item.backend_id == backend_id), None)
            if current is None:
                continue
            current.applicable_files += len(ambiguous)
            current.skipped_files += len(ambiguous)
            current.status = "partial" if current.checked_files else "unavailable"
            current.reason_code = "ambiguous_header_language"
            current.reason = "C/C++ header language is ambiguous in this scope."

    candidates: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    diagnostic_groups: dict[tuple[str, str, int], list[BackendDiagnostic]] = {}
    normalised_results: list[BackendResult] = []
    for result in results:
        try:
            for diagnostic in result.diagnostics:
                metadata = dict(diagnostic.metadata)
                nested_metadata = metadata.get("metadata")
                contract = str(
                    metadata.get("contract")
                    or (nested_metadata.get("contract") if isinstance(nested_metadata, dict) else "")
                    or diagnostic.rule_id
                )
                diagnostic_groups.setdefault((contract, diagnostic.path, diagnostic.line), []).append(diagnostic)
        except Exception as error:
            result.status = "failed"
            result.reason_code = "candidate_conversion"
            result.reason = str(error)
        normalised_results.append(result)

    candidate_budget_error: AnalysisBudgetExceeded | None = None
    for group_key in sorted(diagnostic_groups):
        try:
            anti_budget.claim_candidate()
            candidate = _candidate(diagnostic_groups[group_key])
            if candidate["id"] in seen_ids:
                raise ValueError(f"duplicate anti-slop candidate id: {candidate['id']}")
            seen_ids.add(candidate["id"])
            candidates.append(candidate)
        except AnalysisBudgetExceeded as error:
            candidate_budget_error = error
            break
        except Exception as error:
            for result in normalised_results:
                if result.applicable_files:
                    result.status = "failed"
                    result.reason_code = "candidate_conversion"
                    result.reason = str(error)
            break
    if candidate_budget_error is not None:
        for result in normalised_results:
            if result.applicable_files and result.status == "complete":
                result.status = "partial" if result.checked_files else "unavailable"
                result.reason_code = candidate_budget_error.reason_code
                result.reason = candidate_budget_error.detail

    candidates.sort(key=lambda item: (
        item["supporting_evidence"][0].get("file", ""),
        item["supporting_evidence"][0].get("source_layer", ""),
        item["supporting_evidence"][0].get("line", 0),
        item["supporting_evidence"][0].get("column", 0),
        item["source"],
        item["claim"],
    ))
    applicable = sum(result.applicable_files for result in normalised_results)
    incomplete = any(result.applicable_files and result.status != "complete" for result in normalised_results)
    state = "Not applicable" if applicable == 0 else "Not verified" if incomplete else "Checked"
    internal_status = "not_applicable" if state == "Not applicable" else "partial" if incomplete else "complete"
    return {
        "tool": "anti-slop",
        "status": internal_status,
        "state": state,
        "reason": "No enabled structural anti-slop backend had applicable files." if state == "Not applicable" else "At least one applicable structural backend did not complete." if incomplete else "All applicable structural anti-slop backends completed.",
        "files_scanned": sum(result.checked_files for result in normalised_results),
        "candidates": candidates,
        "backends": {result.backend_id: result.as_dict() for result in normalised_results},
        "ambiguous_header_paths": ambiguous,
    }
