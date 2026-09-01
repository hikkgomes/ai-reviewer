#!/usr/bin/env python3
"""Validate collected self-review evidence against an approved baseline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dissect_checks.redaction import redact_sensitive_text  # noqa: E402
from validate_review_context import validate as validate_context  # noqa: E402
from validate_test_evidence import validate as validate_test_evidence  # noqa: E402


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _candidate_key(candidate: Mapping[str, Any]) -> str:
    evidence = candidate.get("supporting_evidence")
    first = evidence[0] if isinstance(evidence, list) and evidence and isinstance(evidence[0], Mapping) else {}
    return json.dumps({
        "source": candidate.get("source", ""),
        "trigger_path": candidate.get("trigger_path", []),
        "file": first.get("file", ""),
        "line": first.get("line"),
        "change_kind": first.get("change_kind", ""),
    }, sort_keys=True, separators=(",", ":"))


def _high_confidence_candidates(payload: Mapping[str, Any]) -> set[str]:
    result: set[str] = set()
    values = payload.get("candidates", [])
    if not isinstance(values, list):
        return result
    for candidate in values:
        if not isinstance(candidate, Mapping):
            continue
        evidence = candidate.get("supporting_evidence", [])
        evidence_values = evidence if isinstance(evidence, list) else []
        high = candidate.get("confidence") == "high" or any(
            isinstance(item, Mapping) and item.get("confidence") == "high"
            for item in evidence_values
        )
        if high:
            result.add(_candidate_key(candidate))
    return result


def _not_verified_backends(payload: Mapping[str, Any]) -> set[str]:
    result: set[str] = set()
    coverage = payload.get("coverage", {})
    if not isinstance(coverage, Mapping):
        return result
    for family, record in coverage.items():
        if not isinstance(record, Mapping):
            continue
        backends = record.get("backends")
        if not isinstance(backends, Mapping):
            continue
        for backend, value in backends.items():
            if isinstance(value, Mapping) and value.get("state") == "Not verified":
                result.add(f"{family}:{backend}")
    return result


def _complexity_saturated(payload: Mapping[str, Any]) -> bool:
    summary = payload.get("candidate_summary", {})
    return isinstance(summary, Mapping) and summary.get("truncated") is True


def _complexity_summary_error(payload: Mapping[str, Any]) -> str | None:
    summary = payload.get("candidate_summary")
    if not isinstance(summary, Mapping):
        return "complexity candidate_summary is missing"
    total = summary.get("total_candidates")
    emitted = summary.get("emitted_candidates")
    if not isinstance(total, int) or isinstance(total, bool) or total < 0 or not isinstance(emitted, int) or isinstance(emitted, bool) or emitted < 0:
        return "complexity candidate_summary counts are invalid"
    if emitted > total or emitted != len(payload.get("candidates", [])):
        return "complexity candidate_summary counts do not match candidates"
    return None


def _unreviewed_complexity(payload: Mapping[str, Any]) -> list[str]:
    result: list[str] = []
    candidates = payload.get("candidates", [])
    if not isinstance(candidates, list):
        return result
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            continue
        function = candidate.get("function")
        if not isinstance(function, Mapping) or function.get("is_test") is True:
            continue
        delta = candidate.get("delta")
        if isinstance(delta, int) and delta > 0:
            result.append(f"{function.get('logical_path')}:{function.get('start_line')}")
    return sorted(set(result))


def _malformed_production_fixtures(payload: Mapping[str, Any]) -> list[str]:
    result: list[str] = []
    values = payload.get("static_candidates", [])
    if not isinstance(values, list):
        return result
    for candidate in values:
        if not isinstance(candidate, Mapping):
            continue
        evidence = candidate.get("supporting_evidence", [])
        first = evidence[0] if isinstance(evidence, list) and evidence and isinstance(evidence[0], Mapping) else {}
        if first.get("rule_id") == "GOV-TESTS-007":
            path = str(first.get("file", ""))
            if not (path.startswith("tests/fixtures/") or "/fixtures/" in path):
                result.append(path)
    return sorted(set(result))


def validate(
    context: Mapping[str, Any],
    test_evidence: Mapping[str, Any],
    complexity: Mapping[str, Any],
    baseline: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    if baseline.get("schema_version") != "1.0":
        errors.append("self-review baseline schema_version must be 1.0")
    errors.extend(f"context: {error}" for error in validate_context(context))
    errors.extend(f"test evidence: {error}" for error in validate_test_evidence(test_evidence))
    summary_error = _complexity_summary_error(complexity)
    if summary_error is not None:
        errors.append(summary_error)
    expected_high = baseline.get("high_confidence_candidate_keys", [])
    if not isinstance(expected_high, list) or not all(isinstance(item, str) for item in expected_high):
        errors.append("baseline high_confidence_candidate_keys must be an array of strings")
        expected_high = []
    new_high = _high_confidence_candidates(context) - set(expected_high)
    if new_high:
        errors.append(f"new high-confidence self-review candidates: {len(new_high)}")
    expected_backends = baseline.get("allowed_not_verified_backends", [])
    if not isinstance(expected_backends, list) or not all(isinstance(item, str) for item in expected_backends):
        errors.append("baseline allowed_not_verified_backends must be an array of strings")
        expected_backends = []
    unexpected = _not_verified_backends(context) - set(expected_backends)
    if unexpected:
        errors.append("unexpected Not verified backends: " + ", ".join(sorted(unexpected)))
    if _complexity_saturated(complexity) or _complexity_saturated(context.get("complexity", {})):
        errors.append("complexity candidate limit is saturated")
    unreviewed = _unreviewed_complexity(complexity)
    allowed_complexity = baseline.get("allowed_complexity_increases", [])
    if not isinstance(allowed_complexity, list) or not all(isinstance(item, str) for item in allowed_complexity):
        errors.append("baseline allowed_complexity_increases must be an array of strings")
        allowed_complexity = []
    new_complexity = set(unreviewed) - set(allowed_complexity)
    if new_complexity:
        errors.append("unreviewed complexity increase: " + ", ".join(sorted(new_complexity)))
    malformed = _malformed_production_fixtures(test_evidence)
    if malformed:
        errors.append("malformed fixture in production scope: " + ", ".join(malformed))
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--test-evidence", type=Path, required=True)
    parser.add_argument("--complexity", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        errors = validate(
            _load(args.context),
            _load(args.test_evidence),
            _load(args.complexity),
            _load(args.baseline),
        )
    except (OSError, ValueError) as error:
        print(redact_sensitive_text(str(error)))
        return 1
    if errors:
        print("\n".join(errors))
        return 1
    print("Self-review evidence gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
