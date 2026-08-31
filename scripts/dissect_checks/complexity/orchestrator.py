"""Orchestrate bounded full and diff complexity analysis."""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from analysis_budget import AnalysisBudget, AnalysisBudgetExceeded, analysis_limits
from file_paths import is_generated_path, is_ignored_path, iter_files
from language_registry import language_for_path
from review_ledger import blank_candidate, validate_candidate
from .configuration import resolve_policy
from .lizard_backend import SUPPORTED_SUFFIXES, LIZARD_VERSION, extract_functions
from .model import ComplexityCandidate, ComplexityFunction, ComplexityResult


@dataclass(frozen=True)
class _Loaded:
    path: str
    data: bytes
    digest: str
    source_kind: str


def _read_selected(
    root: Path,
    paths: Iterable[str],
    budget: AnalysisBudget,
    max_bytes: int,
    *,
    source_kind: str,
) -> tuple[list[_Loaded], int, str | None]:
    output: list[_Loaded] = []
    skipped = 0
    reason: str | None = None
    ordered = sorted(set(paths))
    for index, path in enumerate(ordered):
        path_object = Path(path)
        if path_object.is_absolute() or ".." in path_object.parts:
            skipped += 1
            reason = reason or "unsafe_path"
            continue
        try:
            budget.claim_file()
            physical = (root / path_object).resolve()
            size = physical.stat().st_size
            if size > max_bytes:
                raise AnalysisBudgetExceeded("max_file_bytes", "complexity source file exceeds the configured limit")
            budget.claim_bytes(size)
            with physical.open("rb") as handle:
                data = handle.read(size)
            if len(data) != size or physical.stat().st_size != size:
                raise OSError("complexity source changed during bounded read")
            if b"\0" in data[:4096]:
                raise AnalysisBudgetExceeded("binary_source", "complexity source contains a NUL byte")
            output.append(_Loaded(path, data, hashlib.sha256(data).hexdigest(), source_kind))
        except AnalysisBudgetExceeded as error:
            skipped += 1
            reason = reason or error.reason_code
            if error.reason_code in {"total_timeout", "max_files", "max_total_bytes"}:
                skipped += len(ordered) - index - 1
                break
        except OSError:
            skipped += 1
            reason = reason or "read_failure"
    return output, skipped, reason


def _changed_line_set(ranges: Mapping[str, Iterable[tuple[int, int]]] | None, path: str) -> set[int]:
    output: set[int] = set()
    for start, end in (ranges or {}).get(path) or ():
        output.update(range(max(1, int(start)), max(int(start), int(end)) + 1))
    return output


def _function_changed(function: ComplexityFunction, lines: set[int]) -> bool:
    return bool(lines) and any(function.start_line <= line <= function.end_line for line in lines)


def _candidate(
    function: ComplexityFunction,
    *,
    reason_code: str,
    threshold: int,
    threshold_source: str,
    base_complexity: int | None,
    head_complexity: int,
    delta: int | None,
    changed_lines: Iterable[int],
    mapping_status: str = "complete",
) -> dict[str, Any]:
    identity = f"{function.logical_path}\0{function.source_layer}\0{function.content_sha256}\0{function.qualified_name}\0{function.start_line}\0{reason_code}"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
    candidate = blank_candidate(
        f"candidate-complexity-{digest}",
        source="COR-COMPLEXITY",
        claim=f"{function.qualified_name} has cyclomatic complexity {head_complexity} ({reason_code}).",
        contract="Review branch cohesion, failure paths, state transitions, and testability before treating complexity as a defect.",
    )
    candidate["trigger_path"] = [f"{function.logical_path}:{function.start_line}"]
    candidate["supporting_evidence"] = [{
        "kind": "complexity",
        "rule_id": "COR-COMPLEXITY",
        "file": function.logical_path,
        "line": function.start_line,
        "source_layer": function.source_layer,
        "content_sha256": function.content_sha256,
        "qualified_name": function.qualified_name,
        "function_id": function.function_id,
        "start_line": function.start_line,
        "end_line": function.end_line,
        "cyclomatic": head_complexity,
        "base_complexity": base_complexity,
        "head_complexity": head_complexity,
        "delta": delta,
        "threshold": threshold,
        "threshold_source": threshold_source,
        "reason_code": reason_code,
        "is_test": function.is_test,
        "analysis_level": "structural",
        "does_not_prove": ["automatic defect", "poor design", "missing test", "unsafe behaviour"],
        "changed_lines": sorted(set(changed_lines)),
        "mapping_status": mapping_status,
    }]
    errors = validate_candidate(candidate)
    if errors:
        raise ValueError("invalid complexity candidate: " + "; ".join(errors))
    return candidate


def _selected_paths(
    root: Path,
    paths: Iterable[str | Path] | None,
    config: Mapping[str, Any],
) -> tuple[list[str], set[str]]:
    raw = [Path(path).as_posix() for path in paths] if paths is not None else [
        path.relative_to(root).as_posix() for path in iter_files(root)
    ]
    unsafe = {
        path for path in raw
        if (Path(path).is_absolute() or ".." in Path(path).parts)
        and Path(path).suffix.lower() in SUPPORTED_SUFFIXES
    }
    selected = [
        path for path in sorted(set(raw))
        if path not in unsafe
        and Path(path).suffix.lower() in SUPPORTED_SUFFIXES
        and not is_ignored_path(root, path)
        and not is_generated_path(root, root / path, dict(config))
    ]
    return selected, unsafe


def _load_head_sources(
    root: Path,
    selected: Sequence[str],
    unsafe: set[str],
    head_contents: Mapping[str, bytes | str] | None,
    budget: AnalysisBudget,
    max_file_bytes: int,
    source_kind: str,
) -> tuple[dict[str, bytes], int, str | None]:
    if head_contents is None:
        loaded, skipped, reason = _read_selected(root, selected, budget, max_file_bytes, source_kind=source_kind)
        return {item.path: item.data for item in loaded}, skipped + len(unsafe), ("unsafe_path" if unsafe else None) or reason
    output: dict[str, bytes] = {}
    skipped = len(unsafe)
    reason: str | None = "unsafe_path" if unsafe else None
    ordered = list(selected)
    for index, path in enumerate(ordered):
        value = head_contents.get(path)
        if value is None:
            skipped += 1
            reason = reason or "source_unavailable"
            continue
        data = value if isinstance(value, bytes) else value.encode("utf-8", errors="surrogatepass")
        try:
            budget.claim_file()
            if len(data) > max_file_bytes:
                budget.claim_bytes(max_file_bytes)
                raise AnalysisBudgetExceeded("max_file_bytes", "complexity source file exceeds the configured limit")
            budget.claim_bytes(len(data))
            if b"\0" in data[:4096]:
                raise AnalysisBudgetExceeded("binary_source", "complexity source contains a NUL byte")
            output[path] = data
        except AnalysisBudgetExceeded as error:
            skipped += 1
            reason = reason or error.reason_code
            if error.reason_code in {"total_timeout", "max_files", "max_total_bytes"}:
                skipped += len(ordered) - index - 1
                break
    return output, skipped, reason


def _extract_head_functions(
    root: Path,
    values: Mapping[str, bytes],
    budget: AnalysisBudget,
    limits: Mapping[str, int | float],
    source_kind: str,
) -> tuple[list[ComplexityFunction], dict[str, Any], int, set[str], str | None]:
    functions: list[ComplexityFunction] = []
    policies: dict[str, Any] = {}
    parse_failed = 0
    parsed_paths: set[str] = set()
    reason: str | None = None
    for path, data in sorted(values.items()):
        language = language_for_path(path)
        language_id = "" if language is None else "c" if language.language_id == "c-header" else language.language_id
        try:
            budget.check_deadline()
            extracted = extract_functions(path, data, source_kind=source_kind)
            budget.check_deadline()
            policy = resolve_policy(root, language_id, fallback_threshold=int(limits["complexity_fallback_threshold"]))
            policies[language_id] = policy
            functions.extend(
                replace(item, threshold=int(policy["threshold"]), threshold_source=str(policy.get("source", "dissect fallback")))
                for item in extracted
            )
            parsed_paths.add(path)
        except AnalysisBudgetExceeded as error:
            reason = reason or error.reason_code
            break
        except (SyntaxError, ValueError, TypeError):
            parse_failed += 1
            reason = reason or "parse_error"
    return functions, policies, parse_failed, parsed_paths, reason


def _base_functions(
    base_contents: Mapping[str, bytes | str] | None,
    selected: Sequence[str],
    budget: AnalysisBudget,
) -> tuple[dict[tuple[str, str, str], list[ComplexityFunction]], str | None]:
    output: dict[tuple[str, str, str], list[ComplexityFunction]] = {}
    reason: str | None = None
    if base_contents is None:
        return output, reason
    selected_set = set(selected)
    for path, value in sorted(base_contents.items()):
        if path not in selected_set:
            continue
        data = value if isinstance(value, bytes) else value.encode("utf-8", errors="surrogatepass")
        try:
            budget.check_deadline()
            for function in extract_functions(path, data, source_kind="base"):
                output.setdefault((path, function.qualified_name, function.signature), []).append(function)
        except (AnalysisBudgetExceeded, SyntaxError, ValueError, TypeError):
            reason = reason or "base_parse_error"
    return output, reason


def _candidate_reason(
    function: ComplexityFunction,
    *,
    mode: str,
    threshold: int,
    base_complexity: int | None,
    delta: int | None,
    delta_limit: int,
    fallback_lower: int,
    mapping_status: str,
) -> str | None:
    if mode == "full" and function.cyclomatic > threshold:
        return "above_threshold"
    if mode == "diff" and base_complexity is None and function.cyclomatic > threshold:
        return "new_above_threshold" if mapping_status == "complete" else "base_mapping_ambiguous"
    if mode == "diff" and base_complexity is not None and function.cyclomatic > threshold and function.cyclomatic > base_complexity:
        return "changed_above_threshold"
    if mode == "diff" and delta is not None and delta >= delta_limit and function.cyclomatic > fallback_lower:
        return "complexity_growth"
    return None


def _build_candidates(
    functions: Iterable[ComplexityFunction],
    base_functions: Mapping[tuple[str, str, str], list[ComplexityFunction]],
    *,
    mode: str,
    changed_ranges: Mapping[str, Iterable[tuple[int, int]]] | None,
    policies: Mapping[str, Any],
    limits: Mapping[str, int | float],
    budget: AnalysisBudget,
) -> tuple[list[ComplexityCandidate], set[str], str | None]:
    candidates: list[ComplexityCandidate] = []
    unverified_ranges: set[str] = set()
    reason: str | None = None
    fallback_lower = int(limits["complexity_delta_minimum_head"])
    delta_limit = int(limits["complexity_delta_threshold"])
    for function in sorted(functions, key=lambda item: (item.logical_path, item.start_line, item.qualified_name)):
        language = language_for_path(function.logical_path)
        language_id = "" if language is None else "c" if language.language_id == "c-header" else language.language_id
        policy = policies.get(language_id, {"threshold": int(limits["complexity_fallback_threshold"]), "source": "dissect fallback"})
        threshold = int(policy["threshold"])
        line_set = _changed_line_set(changed_ranges, function.logical_path)
        if mode == "diff":
            if changed_ranges is None or function.logical_path not in changed_ranges or changed_ranges.get(function.logical_path) is None:
                unverified_ranges.add(function.logical_path)
                continue
            if not _function_changed(function, line_set):
                continue
        matches, mapping_status = _match_base(function, base_functions)
        base_complexity = matches[0].cyclomatic if mapping_status == "complete" and matches else None
        delta = function.cyclomatic - base_complexity if base_complexity is not None else None
        candidate_reason = _candidate_reason(
            function, mode=mode, threshold=threshold,
            base_complexity=base_complexity, delta=delta,
            delta_limit=delta_limit, fallback_lower=fallback_lower,
            mapping_status=mapping_status,
        )
        if candidate_reason is None:
            continue
        try:
            budget.claim_candidate()
        except AnalysisBudgetExceeded:
            reason = reason or "max_candidates"
            break
        candidates.append(ComplexityCandidate(
            f"candidate-complexity-{hashlib.sha256((function.function_id + candidate_reason).encode()).hexdigest()[:24]}",
            function, candidate_reason, threshold, str(policy.get("source", "dissect fallback")),
            base_complexity, function.cyclomatic, delta, tuple(sorted(line_set)), mapping_status,
        ))
        _candidate(
            function, reason_code=candidate_reason, threshold=threshold,
            threshold_source=str(policy.get("source", "dissect fallback")),
            base_complexity=base_complexity, head_complexity=function.cyclomatic,
            delta=delta, changed_lines=line_set, mapping_status=mapping_status,
        )
    return candidates, unverified_ranges, reason


def analyse(
    root: Path,
    paths: Iterable[str | Path] | None = None,
    *,
    mode: str = "full",
    config: Mapping[str, Any] | None = None,
    base_contents: Mapping[str, bytes | str] | None = None,
    head_contents: Mapping[str, bytes | str] | None = None,
    changed_ranges: Mapping[str, Iterable[tuple[int, int]]] | None = None,
    source_kind: str = "working-tree",
) -> ComplexityResult:
    root = root.resolve()
    if mode not in {"full", "diff"}:
        raise ValueError("complexity mode must be full or diff")
    config = config or {}
    limits = analysis_limits(config)
    selected, unsafe = _selected_paths(root, paths, config)
    budget = AnalysisBudget(
        float(limits["complexity_timeout_seconds"]),
        int(limits["complexity_max_files"]),
        int(limits["complexity_max_total_bytes"]),
        int(limits["complexity_max_candidates"]),
    )
    max_file_bytes = max(1, int(limits["anti_slop_max_file_bytes"]))
    head_values, skipped, reason = _load_head_sources(
        root, selected, unsafe, head_contents, budget, max_file_bytes, source_kind,
    )
    functions, policies, parse_failed, parsed_paths, parse_reason = _extract_head_functions(
        root, head_values, budget, limits, source_kind,
    )
    reason = reason or parse_reason
    base_functions, base_reason = _base_functions(base_contents if mode == "diff" else None, selected, budget)
    reason = reason or base_reason
    candidates, unverified_ranges, candidate_reason = _build_candidates(
        functions,
        base_functions,
        mode=mode,
        changed_ranges=changed_ranges,
        policies=policies,
        limits=limits,
        budget=budget,
    )
    reason = reason or candidate_reason
    if unverified_ranges:
        reason = reason or "changed_ranges_unavailable"
    applicable = len(selected) + len(unsafe)
    checked = len(parsed_paths - unverified_ranges)
    skipped_files = min(applicable, max(skipped, applicable - checked))
    if not applicable:
        status = "not_applicable"
    elif skipped_files or parse_failed or reason:
        status = "partial"
    else:
        status = "complete"
    native_languages = sorted(
        language for language, policy in policies.items()
        if isinstance(policy, Mapping) and policy.get("source") == "repository"
    )
    policy_payload = {
        "fallback_tool": "lizard",
        "fallback_version": LIZARD_VERSION,
        "languages": policies,
        "backends": {
            "lizard-fallback": {"status": status, "languages": sorted(policies), "version": LIZARD_VERSION},
            "repository-native-complexity": {"status": "selected" if native_languages else "not_applicable", "languages": native_languages},
        },
    }
    return ComplexityResult(
        status, tuple(functions), tuple(candidates), policy_payload,
        applicable, max(0, checked), skipped_files, reason,
    )


def _match_base(
    function: ComplexityFunction,
    base_functions: Mapping[tuple[str, str, str], list[ComplexityFunction]],
) -> tuple[tuple[ComplexityFunction, ...], str]:
    """Match base functions without inventing a delta for an ambiguous map."""
    exact = tuple(base_functions.get((function.logical_path, function.qualified_name, function.signature), ()))
    if len(exact) == 1:
        return exact, "complete"
    if len(exact) > 1:
        return exact, "ambiguous"

    same_path_signature = tuple(
        item
        for (path, _name, signature), values in base_functions.items()
        if path == function.logical_path and signature == function.signature
        for item in values
    )
    if len(same_path_signature) == 1:
        return same_path_signature, "complete"
    if len(same_path_signature) > 1:
        return same_path_signature, "ambiguous"

    same_name_signature = tuple(
        item
        for (_path, name, signature), values in base_functions.items()
        if name == function.qualified_name and signature == function.signature
        for item in values
    )
    if len(same_name_signature) == 1:
        return same_name_signature, "complete"
    if len(same_name_signature) > 1:
        return same_name_signature, "ambiguous"
    return (), "complete"
