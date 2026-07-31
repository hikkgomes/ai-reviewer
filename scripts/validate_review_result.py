#!/usr/bin/env python3
"""Validate the stable, concise user-facing review-result shape offline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from review_ledger import validate_ledger  # noqa: E402

FINDING_FIELDS = {"id", "severity", "confidence", "location", "contract", "trigger_path", "impact", "evidence", "fix", "verification"}


def validate(data: dict) -> list[str]:
    errors = []
    required = {"schema_version", "mode", "findings", "open_questions", "not_verified", "coverage", "provenance", "candidates", "ledger"}
    errors.extend(f"missing field: {key}" for key in sorted(required - data.keys()))
    if data.get("schema_version") != "1.0":
        errors.append("schema_version must be 1.0")
    if data.get("mode") not in {"diff", "full"}:
        errors.append("mode must be diff or full")
    provenance = data.get("provenance")
    required_provenance = {"generator", "skill_path", "skill_sha256", "installed_skill_tree_sha256", "installed_skill_manifest", "invocation", "context_path", "raw_output_path", "final_output_path", "reviewer_source_commit", "reviewer_source_dirty", "benchmark_id", "benchmark_manifest_sha256", "benchmark_fixture_sha256", "intent_sha256", "codex_executable", "codex_version", "started_at", "completed_at"}
    if not isinstance(provenance, dict):
        errors.append("provenance must be an object")
    else:
        errors.extend(f"provenance missing {key}" for key in sorted(required_provenance - provenance.keys()))
    if not isinstance(data.get("candidates"), list) or not isinstance(data.get("ledger"), list):
        errors.append("candidates and ledger must be arrays")
    else:
        if data["candidates"] != data["ledger"]:
            errors.append("candidates and ledger must contain the same candidate records")
        errors.extend(f"ledger: {error}" for error in validate_ledger({"candidates": data["ledger"]}))
    verified = {item.get("id") for item in data.get("ledger", []) if isinstance(item, dict) and item.get("status") == "verified"}
    findings = data.get("findings", [])
    if not isinstance(findings, list):
        errors.append("findings must be an array")
        return errors
    ids = set()
    for finding in findings:
        if not isinstance(finding, dict):
            errors.append("finding must be an object")
            continue
        errors.extend(f"finding {finding.get('id', '<unknown>')}: missing {key}" for key in sorted(FINDING_FIELDS - finding.keys()))
        if finding.get("id") in ids:
            errors.append(f"duplicate finding id: {finding.get('id')}")
        ids.add(finding.get("id"))
        if finding.get("severity") not in {"critical", "high", "medium", "low"}:
            errors.append(f"finding {finding.get('id')}: invalid severity")
        if not finding.get("candidate_id"):
            errors.append(f"finding {finding.get('id')}: missing candidate_id")
        elif finding.get("candidate_id") not in verified:
            errors.append(f"finding {finding.get('id')}: candidate_id is not verified in ledger")
    for key in ("open_questions", "not_verified"):
        if not isinstance(data.get(key), list) or not all(isinstance(value, str) for value in data[key]):
            errors.append(f"{key} must be an array of strings")
    if not isinstance(data.get("coverage"), dict):
        errors.append("coverage must be an object")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("result", type=Path)
    args = parser.parse_args()
    try:
        data = json.loads(args.result.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"invalid result: {error}")
        return 1
    errors = validate(data)
    if errors:
        print("\n".join(errors))
        return 1
    print("Review result is valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
