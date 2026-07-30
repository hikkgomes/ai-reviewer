#!/usr/bin/env python3
"""Validate the stable, concise user-facing review-result shape offline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

FINDING_FIELDS = {"id", "severity", "confidence", "location", "contract", "trigger_path", "impact", "evidence", "fix", "verification"}


def validate(data: dict) -> list[str]:
    errors = []
    required = {"schema_version", "mode", "findings", "open_questions", "not_verified", "coverage"}
    errors.extend(f"missing field: {key}" for key in sorted(required - data.keys()))
    if data.get("schema_version") != "1.0":
        errors.append("schema_version must be 1.0")
    if data.get("mode") not in {"diff", "full"}:
        errors.append("mode must be diff or full")
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
