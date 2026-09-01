#!/usr/bin/env python3
"""Validate the review-context 1.2 shape and bounded evidence invariants."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from review_ledger import validate_candidate
from dissect_checks.test_integrity.model import INTERNAL_STATES, PUBLIC_STATES, SCENARIO_IDS
from validate_test_evidence import validate as validate_test_evidence


BACKEND_STATUSES = {"complete", "not_applicable", "partial", "unavailable", "failed", "planned"}
COMPLEXITY_STATUSES = {"complete", "partial", "not_applicable", "unavailable", "failed"}
REQUIRED = {
    "schema_version", "mode", "scope", "intent", "repository", "behavioural_units",
    "candidates", "commands", "coverage", "limitations", "test_evidence", "complexity",
}


def _non_negative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _sha256(value: Any, *, allow_empty: bool = False) -> bool:
    return allow_empty and value == "" or isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _validate_complexity_summary(complexity: dict[str, Any], errors: list[str]) -> None:
    summary = complexity.get("candidate_summary")
    if summary is None:
        errors.append("complexity candidate_summary is required")
        return
    if not isinstance(summary, dict):
        errors.append("complexity candidate_summary must be an object")
        return
    total = summary.get("total_candidates")
    emitted = summary.get("emitted_candidates")
    if not _non_negative_integer(total) or not _non_negative_integer(emitted):
        errors.append("complexity candidate_summary counts must be non-negative integers")
        return
    if emitted > total or emitted != len(complexity.get("candidates", [])):
        errors.append("complexity candidate_summary counts do not match candidates")
    if summary.get("truncated") is not (total > emitted):
        errors.append("complexity candidate_summary truncated flag does not match counts")
    if summary.get("truncated") and summary.get("reason_code") != "max_candidates":
        errors.append("truncated complexity candidate_summary requires max_candidates reason")


def _safe_relative_path(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    path = Path(value.replace("\\", "/"))
    return not path.is_absolute() and bool(path.parts) and ".." not in path.parts


def _forbidden_output(value: Any, path: str = "") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            lower = str(key).lower()
            current = f"{path}.{key}" if path else str(key)
            if lower in {"raw_output", "command_output", "stdout", "stderr", "raw_patch", "full_patch"}:
                errors.append(f"unbounded command or patch output is not allowed: {current}")
            errors.extend(_forbidden_output(child, current))
    elif isinstance(value, list):
        if path.lower() == "environment" or path.lower().endswith(".environment"):
            for item in value:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name", "")).lower()
                value_text = item.get("value")
                if any(token in name for token in ("token", "secret", "password", "private_key", "api_key", "access_key")) and not (
                    isinstance(value_text, str) and value_text.startswith("[REDACTED")
                ):
                    errors.append(f"raw secret-bearing environment value is not allowed: {path}")
        if path.lower() == "bindings" or path.lower().endswith(".bindings"):
            for item in value:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name", "")).lower()
                value_text = item.get("value")
                if (
                    any(token in name for token in ("token", "secret", "password", "private_key", "api_key", "access_key"))
                    and not (isinstance(value_text, str) and value_text.startswith("[REDACTED"))
                ):
                    errors.append(f"raw secret-bearing execution binding is not allowed: {path}")
        for index, child in enumerate(value):
            errors.extend(_forbidden_output(child, f"{path}[{index}]"))
    return errors


def validate(data: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["review context must be an object"]
    errors.extend(f"missing field: {key}" for key in sorted(REQUIRED - data.keys()))
    if data.get("schema_version") != "1.2":
        errors.append("schema_version must be 1.2")
    if data.get("mode") not in {"diff", "full"}:
        errors.append("mode must be diff or full")
    coverage = data.get("coverage")
    if not isinstance(coverage, dict):
        errors.append("coverage must be an object")
    else:
        for required_family in ("test-integrity", "complexity"):
            if required_family not in coverage:
                errors.append(f"coverage is missing {required_family}")
        for name, record in coverage.items():
            if not isinstance(record, dict):
                errors.append(f"coverage {name} must be an object")
                continue
            if record.get("state") not in PUBLIC_STATES:
                errors.append(f"coverage {name} has an invalid state")
            if not isinstance(record.get("reason"), str) or not record["reason"]:
                errors.append(f"coverage {name} must have a reason")
            backends = record.get("backends")
            if backends is None:
                continue
            if not isinstance(backends, dict):
                errors.append(f"coverage {name}.backends must be an object")
                continue
            for backend_id, backend in backends.items():
                if not isinstance(backend, dict):
                    errors.append(f"backend {backend_id} must be an object")
                    continue
                if backend.get("state") not in PUBLIC_STATES:
                    errors.append(f"backend {backend_id} has an invalid state")
                if backend.get("level") != "structural":
                    errors.append(f"backend {backend_id} must be structural")
                if not isinstance(backend.get("languages"), list) or not all(isinstance(item, str) for item in backend["languages"]):
                    errors.append(f"backend {backend_id} languages must be an array of strings")
                counts = {key: backend.get(key) for key in ("applicable_files", "checked_files", "skipped_files")}
                for key, value in counts.items():
                    if not _non_negative_integer(value):
                        errors.append(f"backend {backend_id} {key} must be a non-negative integer")
                if all(_non_negative_integer(value) for value in counts.values()):
                    if counts["checked_files"] > counts["applicable_files"]:
                        errors.append(f"backend {backend_id} checked_files exceeds applicable_files")
                    if counts["checked_files"] + counts["skipped_files"] > counts["applicable_files"]:
                        errors.append(f"backend {backend_id} checked_files exceeds applicable_files when combined with skipped_files")
                    if backend.get("status") == "complete" and (
                            counts["checked_files"] != counts["applicable_files"]
                            or counts["skipped_files"] != 0
                    ):
                        errors.append(f"backend {backend_id} complete status has incomplete file counts")
                    if backend.get("status") == "not_applicable" and any(counts.values()):
                        errors.append(f"backend {backend_id} not_applicable status has applicable files")
                if not isinstance(backend.get("reason"), str) or not backend["reason"]:
                    errors.append(f"backend {backend_id} must have a reason")
                status = backend.get("status")
                if status is not None and status not in BACKEND_STATUSES and status not in INTERNAL_STATES:
                    errors.append(f"backend {backend_id} has an invalid internal status")
                if status == "complete" and backend.get("state") != "Checked":
                    errors.append(f"backend {backend_id} complete status must use Checked")
                if status == "not_applicable" and backend.get("state") != "Not applicable":
                    errors.append(f"backend {backend_id} not_applicable status must use Not applicable")
                if status in {"partial", "planned", "unavailable", "failed"} and backend.get("state") != "Not verified":
                    errors.append(f"backend {backend_id} incomplete status must use Not verified")

    candidates = data.get("candidates")
    candidate_ids: set[str] = set()
    if not isinstance(candidates, list):
        errors.append("candidates must be an array")
    else:
        for candidate in candidates:
            if not isinstance(candidate, dict):
                errors.append("candidate must be an object")
                continue
            candidate_id = candidate.get("id")
            if not isinstance(candidate_id, str) or not candidate_id:
                errors.append("candidate id must be a non-empty string")
            elif candidate_id in candidate_ids:
                errors.append(f"duplicate candidate id: {candidate_id}")
            else:
                candidate_ids.add(candidate_id)
            errors.extend(f"candidate {candidate_id or '<missing>'}: {error}" for error in validate_candidate(candidate))
            related_values = candidate.get("related_candidate_ids", [])
            if not isinstance(related_values, list):
                errors.append(f"candidate {candidate_id or '<missing>'} related_candidate_ids must be an array")
                related_values = []
            for related in related_values:
                if not isinstance(related, str):
                    errors.append(f"candidate {candidate_id or '<missing>'} has an invalid related candidate ID")
                    continue
                if related == candidate_id:
                    errors.append(f"candidate {candidate_id} relates to itself")
                elif related not in candidate_ids and related not in {item.get("id") for item in candidates if isinstance(item, dict)}:
                    errors.append(f"candidate {candidate_id or '<missing>'} relates to an unknown candidate: {related}")

    test_evidence = data.get("test_evidence")
    errors.extend(f"test_evidence: {error}" for error in validate_test_evidence(test_evidence))
    complexity = data.get("complexity")
    if not isinstance(complexity, dict):
        errors.append("complexity must be an object")
    else:
        if complexity.get("status") not in COMPLEXITY_STATUSES:
            errors.append("complexity has an invalid internal status")
        expected_state = "Checked" if complexity.get("status") == "complete" else "Not applicable" if complexity.get("status") == "not_applicable" else "Not verified"
        if complexity.get("state") not in {None, expected_state}:
            errors.append("complexity state does not match its internal status")
        counts = {key: complexity.get(key, 0) for key in ("applicable_files", "checked_files", "skipped_files")}
        for key, value in counts.items():
            if not _non_negative_integer(value):
                errors.append(f"complexity {key} must be a non-negative integer")
        if all(_non_negative_integer(value) for value in counts.values()):
            if counts["checked_files"] > counts["applicable_files"]:
                errors.append("complexity checked_files exceeds applicable_files")
            if counts["checked_files"] + counts["skipped_files"] > counts["applicable_files"]:
                errors.append("complexity checked_files plus skipped_files exceeds applicable_files")
            if complexity.get("status") == "complete" and (
                counts["checked_files"] != counts["applicable_files"]
                or counts["skipped_files"] != 0
            ):
                errors.append("complexity complete status has incomplete file counts")
            if complexity.get("status") == "not_applicable" and any(counts.values()):
                errors.append("complexity not_applicable status has applicable files")
        functions = complexity.get("functions", [])
        candidates = complexity.get("candidates", [])
        _validate_complexity_summary(complexity, errors)
        parse_states = complexity.get("parse_states", {})
        if not isinstance(parse_states, dict) or any(
            not _safe_relative_path(path)
            or state not in {"complete", "failed", "not_verified", "not_run"}
            for path, state in parse_states.items()
        ):
            errors.append("complexity parse_states must contain recognised states")
        if not isinstance(complexity.get("parse_errors", []), list):
            errors.append("complexity parse_errors must be an array")
        if complexity.get("status") == "not_applicable" and (functions or candidates):
            errors.append("complexity not_applicable status cannot contain functions or candidates")
        for function in functions if isinstance(functions, list) else []:
            if not isinstance(function, dict):
                errors.append("complexity function must be an object")
                continue
            if not _safe_relative_path(function.get("logical_path")):
                errors.append("complexity function path must be repository-relative")
            if not _sha256(function.get("content_sha256")):
                errors.append("complexity function has an invalid content hash")
            if not _non_negative_integer(function.get("start_line")) or function.get("start_line", 0) < 1:
                errors.append("complexity function has an invalid start line")
            if not _non_negative_integer(function.get("end_line")) or function.get("end_line", 0) < function.get("start_line", 1):
                errors.append("complexity function has an invalid end line")
            threshold = function.get("threshold")
            if threshold is not None and (not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1):
                errors.append("complexity function has an invalid threshold")
            if threshold is not None and (
                not isinstance(function.get("threshold_source"), str)
                or not function.get("threshold_source")
            ):
                errors.append("complexity function has an invalid threshold source")
            for key in ("cyclomatic", "nloc", "token_count", "parameter_count"):
                value = function.get(key)
                if not _non_negative_integer(value) or (key == "cyclomatic" and value < 1):
                    errors.append(f"complexity function has an invalid {key}")
        for candidate in candidates if isinstance(candidates, list) else []:
            if isinstance(candidate, dict):
                if not isinstance(candidate.get("candidate_id"), str) or not candidate.get("candidate_id"):
                    errors.append("complexity candidate requires a candidate_id")
                if not isinstance(candidate.get("reason_code"), str) or not candidate.get("reason_code"):
                    errors.append("complexity candidate requires a reason_code")
                candidate_threshold = candidate.get("threshold")
                if not _non_negative_integer(candidate_threshold) or candidate_threshold < 1:
                    errors.append("complexity candidate has an invalid threshold")
                if not isinstance(candidate.get("threshold_source"), str) or not candidate.get("threshold_source"):
                    errors.append("complexity candidate has an invalid threshold source")
                for key in ("head_complexity", "base_complexity", "delta"):
                    value = candidate.get(key)
                    if key == "base_complexity" and value is None:
                        continue
                    if key == "delta" and value is None:
                        continue
                    if not isinstance(value, int) or isinstance(value, bool):
                        errors.append(f"complexity candidate has an invalid {key}")
                function = candidate.get("function", {})
                if not isinstance(function, dict):
                    errors.append("complexity candidate requires a function object")
                elif function.get("content_sha256") and not _sha256(function.get("content_sha256")):
                    errors.append("complexity candidate has an invalid content hash")
    errors.extend(_forbidden_output(data))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("context", type=Path)
    args = parser.parse_args()
    try:
        data = json.loads(args.context.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"invalid review context: {error}")
        return 1
    errors = validate(data)
    if errors:
        print("\n".join(errors))
        return 1
    print("Review context is valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
