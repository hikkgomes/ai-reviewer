#!/usr/bin/env python3
"""Validate the review-context 1.1 shape and backend coverage invariants."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from review_ledger import validate_candidate

STATES = {"Finding", "Checked", "Not applicable", "Not verified"}
BACKEND_STATUSES = {"complete", "not_applicable", "partial", "unavailable", "failed"}
REQUIRED = {
    "schema_version", "mode", "scope", "intent", "repository", "behavioural_units",
    "candidates", "commands", "coverage", "limitations",
}


def _non_negative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def validate(data: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["review context must be an object"]
    errors.extend(f"missing field: {key}" for key in sorted(REQUIRED - data.keys()))
    if data.get("schema_version") != "1.1":
        errors.append("schema_version must be 1.1")
    if data.get("mode") not in {"diff", "full"}:
        errors.append("mode must be diff or full")
    coverage = data.get("coverage")
    if not isinstance(coverage, dict):
        errors.append("coverage must be an object")
        return errors
    for name, record in coverage.items():
        if not isinstance(record, dict):
            errors.append(f"coverage {name} must be an object")
            continue
        if record.get("state") not in STATES:
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
            if backend.get("state") not in STATES:
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
                if counts["checked_files"] + counts["skipped_files"] > counts["applicable_files"]:
                    errors.append(f"backend {backend_id} checked_files exceeds applicable_files when combined with skipped_files")
            if not isinstance(backend.get("reason"), str) or not backend["reason"]:
                errors.append(f"backend {backend_id} must have a reason")
            status = backend.get("status")
            if status is not None and status not in BACKEND_STATUSES:
                errors.append(f"backend {backend_id} has an invalid internal status")
    candidates = data.get("candidates")
    if not isinstance(candidates, list):
        errors.append("candidates must be an array")
    else:
        ids: set[Any] = set()
        for candidate in candidates:
            if not isinstance(candidate, dict):
                errors.append("candidate must be an object")
                continue
            candidate_id = candidate.get("id")
            if not isinstance(candidate_id, str) or not candidate_id:
                errors.append("candidate id must be a non-empty string")
            elif candidate_id in ids:
                errors.append(f"duplicate candidate id: {candidate_id}")
            ids.add(candidate_id)
            errors.extend(f"candidate {candidate_id or '<missing>'}: {error}" for error in validate_candidate(candidate))
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
