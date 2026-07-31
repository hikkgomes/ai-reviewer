#!/usr/bin/env python3
"""Score reviewer results against an offline benchmark without a composite score."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _finding_key(item: dict[str, Any]) -> str:
    return str(item.get("id") or item.get("check_id") or item.get("title") or "")


def score(expected: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    if result.get("status") in {"not_run", "agent_failed", "invalid_agent_output", "invalid_result"}:
        return {"benchmark_id": expected.get("id", ""), "status": "not_scorable", "reason": result.get("status"), "provenance_present": bool(result.get("provenance"))}
    expected_items = expected.get("expected_findings", [])
    actual = result.get("findings", [])
    expected_ids = {_finding_key(item) for item in expected_items}
    matched: set[str] = set()
    match_methods: dict[str, str] = {}
    used_actual: set[int] = set()
    for expected_item in expected_items:
        expected_id = _finding_key(expected_item)
        for index, actual_item in enumerate(actual):
            if index in used_actual:
                continue
            if _finding_key(actual_item) == expected_id:
                matched.add(expected_id); match_methods[expected_id] = "id"; used_actual.add(index); break
            expected_location = str(expected_item.get("location", ""))
            actual_location = str(actual_item.get("location", ""))
            if expected_location and expected_location in actual_location:
                matched.add(expected_id); match_methods[expected_id] = "location"; used_actual.add(index); break
    unsupported = [item for index, item in enumerate(actual) if index not in used_actual]
    critical_high = {item["id"] for item in expected_items if item.get("severity") in {"critical", "high"}}
    meaningful_medium = {item["id"] for item in expected_items if item.get("severity") == "medium"}
    def recall(ids: set[str]) -> float:
        return len(ids & actual_ids) / len(ids) if ids else 1.0
    locations = []
    severities = []
    for item in expected_items:
        found = next((value for value in actual if _finding_key(value) == item.get("id") or str(item.get("location", "")) in str(value.get("location", ""))), None)
        if found:
            locations.append(str(item.get("location", "")) in str(found.get("location", "")))
            severities.append(found.get("severity") in set(expected.get("expected_severity", {}).get(item["id"], [item.get("severity")])) )
    actual_ids = {_finding_key(item) for item in actual}
    duplicate_rate = (len(actual) - len(actual_ids)) / len(actual) if actual else 0.0
    false_positive_rate = len(unsupported) / len(actual) if actual else 0.0
    not_verified = set(result.get("not_verified", []))
    required_not_verified = set(expected.get("required_not_verified", []))
    return {
        "benchmark_id": expected.get("id", ""),
        "finding_precision": len(matched) / len(actual) if actual else (1.0 if not expected_ids else 0.0),
        "critical_high_recall": recall(critical_high),
        "meaningful_medium_recall": recall(meaningful_medium),
        "unsupported_finding_rate": false_positive_rate,
        "false_positive_rate": false_positive_rate,
        "location_accuracy": sum(locations) / len(locations) if locations else 1.0,
        "severity_accuracy": sum(severities) / len(severities) if severities else 1.0,
        "duplicate_finding_rate": duplicate_rate,
        "not_verified_recall": len(required_not_verified & not_verified) / len(required_not_verified) if required_not_verified else 1.0,
        "matched_findings": sorted(matched),
        "match_methods": match_methods,
        "unsupported_findings": [_finding_key(item) for item in unsupported],
        "provenance_present": isinstance(result.get("provenance"), dict) and bool(result.get("provenance", {}).get("skill_sha256")),
        "ledger_verified_findings": sum(1 for item in result.get("ledger", []) if item.get("status") == "verified") if isinstance(result.get("ledger"), list) else 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        expected = json.loads(args.expected.read_text(encoding="utf-8"))
        result = json.loads(args.results.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"invalid scoring input: {error}")
        return 1
    payload = score(expected, result)
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
