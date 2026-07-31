#!/usr/bin/env python3
"""Small, versioned candidate ledger used by semantic review workflows."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

STATUSES = {"candidate", "verified", "disproved", "not_verifiable", "duplicate"}
TERMINAL = {"verified", "disproved", "not_verifiable", "duplicate"}
TRANSITIONS = {
    "candidate": TERMINAL,
    "verified": set(), "disproved": set(), "not_verifiable": set(), "duplicate": set(),
}


def blank_candidate(candidate_id: str, *, source: str, claim: str, contract: str = "") -> dict[str, Any]:
    return {
        "id": candidate_id, "source": source, "claim": claim, "contract": contract,
        "trigger_path": [], "impact": "", "supporting_evidence": [],
        "contradicting_evidence": [], "verification_attempts": [],
        "falsification_attempts": [], "status": "candidate",
    }


def validate_candidate(candidate: dict[str, Any], *, require_verified_evidence: bool = False) -> list[str]:
    required = {"id", "source", "claim", "contract", "trigger_path", "impact", "supporting_evidence", "contradicting_evidence", "verification_attempts", "falsification_attempts", "status"}
    errors = [f"missing field: {key}" for key in sorted(required - candidate.keys())]
    if candidate.get("status") not in STATUSES:
        errors.append("invalid status")
    if not isinstance(candidate.get("id"), str) or not candidate.get("id"):
        errors.append("id must be a non-empty string")
    for key in ("trigger_path", "supporting_evidence", "contradicting_evidence", "verification_attempts", "falsification_attempts"):
        if not isinstance(candidate.get(key), list):
            errors.append(f"{key} must be an array")
    if candidate.get("status") == "verified" and require_verified_evidence:
        if not candidate.get("falsification_attempts"):
            errors.append("verified candidate requires a falsification attempt")
        if not candidate.get("verification_attempts"):
            errors.append("verified candidate requires a verification attempt")
    return errors


def transition(candidate: dict[str, Any], status: str, *, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    current = candidate.get("status", "candidate")
    if status not in STATUSES:
        raise ValueError(f"unknown candidate status: {status}")
    if status not in TRANSITIONS.get(current, set()):
        raise ValueError(f"invalid candidate transition: {current} -> {status}")
    updated = dict(candidate)
    updated["status"] = status
    if evidence is not None:
        key = "verification_attempts" if status == "verified" else "falsification_attempts" if status in {"disproved", "not_verifiable", "duplicate"} else "supporting_evidence"
        updated[key] = [*updated.get(key, []), evidence]
    errors = validate_candidate(updated, require_verified_evidence=True)
    if errors:
        raise ValueError("; ".join(errors))
    return updated


def final_findings(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [candidate for candidate in candidates if candidate.get("status") == "verified"]


def validate_ledger(data: dict[str, Any]) -> list[str]:
    errors = []
    candidates = data.get("candidates")
    if not isinstance(candidates, list):
        return ["candidates must be an array"]
    ids = set()
    for candidate in candidates:
        if not isinstance(candidate, dict):
            errors.append("candidate must be an object")
            continue
        errors.extend(f"{candidate.get('id', '<unknown>')}: {error}" for error in validate_candidate(candidate, require_verified_evidence=True))
        if candidate.get("id") in ids:
            errors.append(f"duplicate candidate id: {candidate['id']}")
        ids.add(candidate.get("id"))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        data = json.loads(args.ledger.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"invalid ledger: {error}")
        return 1
    errors = validate_ledger(data)
    if errors:
        print("\n".join(errors))
        return 1
    print(json.dumps({"candidates": len(data["candidates"]), "verified": len(final_findings(data["candidates"]))}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
