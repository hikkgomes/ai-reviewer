"""Stable orchestration for structural anti-slop backends."""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from analysis_budget import AnalysisBudget, AnalysisBudgetExceeded, analysis_limits
from file_paths import is_generated_path, is_ignored_path
from language_registry import ambiguous_header_paths, language_for_path, paths_for_anti_slop
from review_ledger import blank_candidate, validate_candidate
from dissect_checks.redaction import redact_payload
from . import ast_grep_backend, oxlint_backend, python_ast_backend
from .model import AnalysisTarget, BackendDiagnostic, BackendResult, LoadedAnalysisTarget, canonical_diagnostic_identity, load_target


BACKEND_ORDER = (
    "oxlint-js-ts", "python-ast", "ast-grep-go", "ast-grep-rust",
    "ast-grep-c", "ast-grep-cpp", "ast-grep-java", "ast-grep-csharp",
)
BACKEND_LANGUAGES = {
    "oxlint-js-ts": ("javascript", "typescript"),
    "python-ast": ("python",),
    **{key: (value[0],) for key, value in ast_grep_backend.BACKENDS.items()},
}


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
            language_id = language_for_path(relative)
            language = expected_languages[0] if relative.lower().endswith(".h") else language_id.language_id if language_id is not None and language_id.language_id in expected_languages else expected_languages[0]
            backend_targets.append(AnalysisTarget(relative, physical, language, source_kind, revision))
    return tuple(sorted({target.logical_path: target for target in backend_targets}.values(), key=lambda item: (BACKEND_ORDER.index(_backend_for_language(item.language_id)), item.logical_path)))


@dataclass(frozen=True)
class TargetLoadSkip:
    target: AnalysisTarget
    reason_code: str
    detail: str = ""
    count: int = 1

    def __post_init__(self) -> None:
        if isinstance(self.count, bool) or not isinstance(self.count, int) or self.count < 1:
            raise ValueError("target load skip count must be positive")


def load_targets(
    root: Path,
    targets: Sequence[AnalysisTarget],
    budget: AnalysisBudget,
    *,
    max_file_bytes: int,
) -> tuple[tuple[LoadedAnalysisTarget, ...], tuple[TargetLoadSkip, ...]]:
    """Load each source once after claiming the shared analysis budget."""
    loaded: list[LoadedAnalysisTarget] = []
    skipped: list[TargetLoadSkip] = []
    root = root.resolve()
    terminal_reasons = {"total_timeout", "max_files", "max_total_bytes"}
    for index, target in enumerate(targets):
        try:
            loaded.append(load_target(root, target, budget, max_file_bytes=max_file_bytes))
        except AnalysisBudgetExceeded as error:
            remaining = len(targets) - index
            count = remaining if error.reason_code in terminal_reasons else 1
            skipped.append(TargetLoadSkip(target, error.reason_code, error.detail, count))
            if error.reason_code in terminal_reasons:
                break
        except (OSError, ValueError, TypeError) as error:
            skipped.append(TargetLoadSkip(target, "read_failure", str(error)))
    return tuple(loaded), tuple(skipped)


def _backend_for_language(language_id: str) -> str:
    return next(backend for backend, languages in BACKEND_LANGUAGES.items() if language_id in languages)


def _candidate(diagnostics: Sequence[BackendDiagnostic]) -> dict[str, Any]:
    exact = {
        canonical_diagnostic_identity(item): item
        for item in diagnostics
    }
    ordered = tuple(sorted(
        exact.values(),
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
        "diagnostics": [canonical_diagnostic_identity(item) for item in ordered],
    }, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
    candidate = blank_candidate(
        f"candidate-anti-slop-{digest}",
        source=diagnostic.rule_id,
        claim=f"{diagnostic.rule_id}: structural review candidate at {diagnostic.path}:{diagnostic.line}",
        contract="Confirm the concrete harmful behaviour and its semantic impact before reporting.",
    )
    candidate["trigger_path"] = [f"{diagnostic.path}:{diagnostic.line}"]

    def metadata_value(item: BackendDiagnostic, key: str, default: Any = "") -> Any:
        metadata = dict(item.metadata)
        nested = metadata.get("metadata")
        if not isinstance(nested, Mapping):
            nested = {}
        return metadata.get(key) or nested.get(key) or default

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
            "source_layer": str(metadata_value(item, "source_layer", "working-tree")),
            "content_sha256": str(metadata_value(item, "content_sha256", "")),
            "rule_discriminator": str(
                metadata_value(item, "rule_discriminator")
                or metadata_value(item, "discriminator")
                or ""
            ),
            "config_variant": str(metadata_value(item, "config_variant", "")),
            "manifest_path": str(metadata_value(item, "manifest_path", "")),
            "manifest_source_layer": str(metadata_value(item, "manifest_source_layer", "")),
            "manifest_sha256": str(metadata_value(item, "manifest_sha256", "")),
            "analysis_level": "structural",
            "metadata": redact_payload(dict(item.metadata)),
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


def _run_backend(
    backend_id: str,
    root: Path,
    targets: Sequence[LoadedAnalysisTarget],
    budget: AnalysisBudget,
    limits: Mapping[str, int | float],
    config: Mapping[str, Any],
    vendor_dir: Path,
) -> BackendResult:
    max_files = int(limits["external_command_max_files"])
    max_argument_bytes = int(limits["external_command_max_argument_bytes"])
    max_file_bytes = int(limits["anti_slop_max_file_bytes"])
    if backend_id == "oxlint-js-ts":
        return oxlint_backend.analyse(
            root, targets, budget, vendor_dir=vendor_dir,
            max_files=max_files, max_argument_bytes=max_argument_bytes,
            max_file_bytes=max_file_bytes,
        )
    if backend_id == "python-ast":
        options = config.get("review_options") if isinstance(config, Mapping) else {}
        enable_getattr = bool(options.get("anti_slop_python_getattr", False)) if isinstance(options, Mapping) else False
        return python_ast_backend.analyse(
            root, targets, budget, max_file_bytes=max_file_bytes, enable_getattr=enable_getattr,
        )
    return ast_grep_backend.analyse(
        root, targets, budget, vendor_dir=vendor_dir,
        max_files=max_files, max_argument_bytes=max_argument_bytes,
        threads=int(limits["worker_threads"]), max_file_bytes=max_file_bytes,
    )


def _run_backends(
    root: Path,
    targets: Sequence[AnalysisTarget],
    limits: Mapping[str, int | float],
    config: Mapping[str, Any],
    vendor_dir: Path,
    budget: AnalysisBudget | None = None,
) -> tuple[list[BackendResult], AnalysisBudget]:
    by_backend: dict[str, list[AnalysisTarget]] = {backend: [] for backend in BACKEND_ORDER}
    for target in targets:
        by_backend[_backend_for_language(target.language_id)].append(target)
    budget = budget or _budget(dict(limits))
    loaded_targets, load_skips = load_targets(
        root, targets, budget, max_file_bytes=int(limits["anti_slop_max_file_bytes"]),
    )
    loaded_by_backend: dict[str, list[LoadedAnalysisTarget]] = {backend: [] for backend in BACKEND_ORDER}
    for target in loaded_targets:
        loaded_by_backend[_backend_for_language(target.language_id)].append(target)
    skips_by_backend: dict[str, list[TargetLoadSkip]] = {backend: [] for backend in BACKEND_ORDER}
    for skip in load_skips:
        try:
            skips_by_backend[_backend_for_language(skip.target.language_id)].append(skip)
        except StopIteration:
            continue
    results: list[BackendResult] = []
    for backend_id in BACKEND_ORDER:
        raw_targets = tuple(sorted(by_backend[backend_id], key=lambda item: (item.logical_path, item.source_kind, item.content_sha256)))
        backend_targets = tuple(sorted(loaded_by_backend[backend_id], key=lambda item: (item.logical_path, item.source_kind, item.content_sha256)))
        if not raw_targets:
            results.append(_empty_result(backend_id))
            continue
        # The source loader is shared by all backend packs. If a terminal
        # budget claim stops loading, calculate the missing targets for this
        # backend instead of attaching the aggregate remainder to the first
        # backend which encountered the limit.
        unmatched_loaded = list(backend_targets)
        missing_targets: list[AnalysisTarget] = []
        for raw_target in raw_targets:
            match_index = next(
                (
                    index for index, loaded in enumerate(unmatched_loaded)
                    if loaded.logical_path == raw_target.logical_path
                    and loaded.source_kind == raw_target.source_kind
                    and loaded.revision == raw_target.revision
                    and (not raw_target.content_sha256 or loaded.content_sha256 == raw_target.content_sha256)
                ),
                None,
            )
            if match_index is None:
                missing_targets.append(raw_target)
            else:
                unmatched_loaded.pop(match_index)
        if not backend_targets:
            skip = skips_by_backend[backend_id][0] if skips_by_backend[backend_id] else None
            results.append(BackendResult(
                backend_id, "structural", BACKEND_LANGUAGES[backend_id], "unavailable",
                len(raw_targets), 0, len(raw_targets), [],
                skip.reason_code if skip else "source_unavailable",
                skip.detail if skip else "No source file completed structural analysis.",
                {
                    target.target_id: "failed" if skip is not None and (
                        target.logical_path,
                        target.source_kind,
                        target.revision,
                    ) == (
                        skip.target.logical_path,
                        skip.target.source_kind,
                        skip.target.revision,
                    ) else "not_verified"
                    for target in raw_targets
                },
                [
                    {
                        "path": item.target.logical_path,
                        "reason_code": item.reason_code,
                        "detail": item.detail[:240],
                    }
                    for item in skips_by_backend[backend_id][:3]
                ],
            ))
            continue
        result = _run_backend(backend_id, root, backend_targets, budget, limits, config, vendor_dir)
        raw_applicable = len(raw_targets)
        load_skipped = len(missing_targets)
        result.applicable_files = raw_applicable
        result.skipped_files = min(
            raw_applicable,
            result.skipped_files + load_skipped,
        )
        if load_skipped:
            first_skip = skips_by_backend[backend_id][0] if skips_by_backend[backend_id] else None
            if first_skip is not None:
                result.reason_code = result.reason_code or first_skip.reason_code
                result.reason = result.reason or first_skip.detail
            if result.status == "complete":
                result.status = "partial" if result.checked_files else "unavailable"
            skip_by_location = {
                (item.target.logical_path, item.target.source_kind, item.target.revision): item
                for item in skips_by_backend[backend_id]
            }
            for target in missing_targets:
                skip = skip_by_location.get((target.logical_path, target.source_kind, target.revision))
                result.parse_states[target.target_id] = "failed" if skip is not None else "not_verified"
                if skip is not None:
                    result.parse_errors.append({
                        "path": target.logical_path,
                        "reason_code": skip.reason_code,
                        "detail": skip.detail[:240],
                    })
        results.append(result)
    return results, budget


def _mark_ambiguous_headers(results: Sequence[BackendResult], paths: Iterable[str | Path]) -> list[str]:
    ambiguous = list(ambiguous_header_paths(paths))
    if not ambiguous:
        return ambiguous
    for backend_id in ("ast-grep-c", "ast-grep-cpp"):
        current = next((item for item in results if item.backend_id == backend_id), None)
        if current is None:
            continue
        current.applicable_files += len(ambiguous)
        current.skipped_files += len(ambiguous)
        current.status = "partial" if current.checked_files else "unavailable"
        current.reason_code = "ambiguous_header_language"
        current.reason = "C/C++ header language is ambiguous in this scope."
    return ambiguous


def _candidate_ledger(
    results: Sequence[BackendResult],
    budget: AnalysisBudget,
) -> list[dict[str, Any]]:
    groups: dict[str, list[BackendDiagnostic]] = {}
    for result in results:
        try:
            for diagnostic in result.diagnostics:
                groups.setdefault(canonical_diagnostic_identity(diagnostic), []).append(diagnostic)
        except Exception as error:
            result.status = "failed"
            result.reason_code = "candidate_conversion"
            result.reason = str(error)
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for key in sorted(groups):
        try:
            budget.claim_candidate()
            candidate = _candidate(groups[key])
            if candidate["id"] in seen:
                raise ValueError(f"duplicate anti-slop candidate id: {candidate['id']}")
            seen.add(candidate["id"])
            candidates.append(candidate)
        except AnalysisBudgetExceeded as error:
            for result in results:
                if result.applicable_files and result.status == "complete":
                    result.status = "partial" if result.checked_files else "unavailable"
                    result.reason_code = error.reason_code
                    result.reason = error.detail
            break
        except Exception as error:
            for result in results:
                if result.applicable_files:
                    result.status = "failed"
                    result.reason_code = "candidate_conversion"
                    result.reason = str(error)
            break
    candidates.sort(key=lambda item: (
        item["supporting_evidence"][0].get("file", ""),
        item["supporting_evidence"][0].get("source_layer", ""),
        item["supporting_evidence"][0].get("line", 0),
        item["supporting_evidence"][0].get("column", 0),
        item["source"],
        item["claim"],
    ))
    location_to_ids: dict[tuple[Any, Any, Any], set[str]] = {}
    for candidate in candidates:
        for item in candidate.get("supporting_evidence", []):
            if isinstance(item, dict):
                location = (item.get("file"), item.get("line"), item.get("source_layer", "working-tree"))
                location_to_ids.setdefault(location, set()).add(candidate["id"])
    for candidate in candidates:
        locations = {
            (item.get("file"), item.get("line"), item.get("source_layer", "working-tree"))
            for item in candidate.get("supporting_evidence", []) if isinstance(item, dict)
        }
        related = sorted({
            related_id
            for location in locations
            for related_id in location_to_ids.get(location, set())
            if related_id != candidate["id"]
        })
        if related:
            candidate["related_candidate_ids"] = related
    return candidates


def _validated_targets(root: Path, targets: Iterable[AnalysisTarget], config: dict[str, Any]) -> tuple[AnalysisTarget, ...]:
    selected: dict[tuple[str, str, object], AnalysisTarget] = {}
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
        if not inside_root and target.data is None and not target.physical_snapshot:
            continue
        # Do not hash supplied source bytes before the shared budget claims
        # them. The loader calculates the SHA-256 after the claim.
        identity = target.content_sha256 or target.data or ""
        key = (relative, target.source_kind, identity)
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
    anti_budget = _budget(dict(limits))
    target_values = oxlint_backend.enrich_targets(
        root,
        target_values,
        max_file_bytes=int(limits["anti_slop_max_file_bytes"]),
        budget=anti_budget,
    )
    results, anti_budget = _run_backends(root, target_values, limits, config or {}, vendor_dir, anti_budget)
    ambiguous_scope = ambiguous_paths if ambiguous_paths is not None else selected_paths
    ambiguous = _mark_ambiguous_headers(results, ambiguous_scope)
    candidates = _candidate_ledger(results, anti_budget)
    normalised_results = results
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
