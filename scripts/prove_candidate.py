#!/usr/bin/env python3
"""Create an inert, approval-bound proof-test plan for one context candidate."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dissect_checks.redaction import redact_payload, redact_sensitive_text  # noqa: E402
from dissect_checks.test_integrity.proof_test import build_proof_test_plan  # noqa: E402


def _config(root: Path) -> dict[str, Any]:
    try:
        value = json.loads((root / ".ai-review" / "local.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _command(root: Path, config: dict[str, Any]) -> str | None:
    commands = config.get("commands") if isinstance(config.get("commands"), dict) else {}
    options = config.get("review_options") if isinstance(config.get("review_options"), dict) else {}
    value = commands.get("test") or options.get("test_command")
    if isinstance(value, str) and value.strip():
        return value.strip()
    try:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "detect_commands.py")],
            cwd=root, capture_output=True, text=True, check=False, timeout=5,
        )
        payload = json.loads(result.stdout) if result.returncode == 0 else {}
        detected = payload.get("commands", {}).get("test") if isinstance(payload, dict) else None
        return detected.strip() if isinstance(detected, str) and detected.strip() else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _find_candidate(context: dict[str, Any], candidate_id: str) -> dict[str, Any] | None:
    def walk(value: Any) -> dict[str, Any] | None:
        if isinstance(value, dict):
            if value.get("id", value.get("candidate_id")) == candidate_id:
                return value
            for child in value.values():
                found = walk(child)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = walk(child)
                if found is not None:
                    return found
        return None
    return walk(context)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--test-patch", required=True, type=Path)
    parser.add_argument("--format", choices=("json",), default="json")
    parser.add_argument("--oracle-kind")
    parser.add_argument("--oracle-reference")
    parser.add_argument("--expected-current-result", choices=("pass", "fail"))
    parser.add_argument("--control", choices=("base", "known_good", "targeted_mutant"))
    parser.add_argument("--focal-subject", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        context = json.loads(args.context.read_text(encoding="utf-8"))
        if not isinstance(context, dict):
            raise ValueError("context must be a JSON object")
        candidate = _find_candidate(context, args.candidate_id)
        if candidate is None:
            raise ValueError(f"candidate was not found: {args.candidate_id}")
        candidate = dict(candidate)
        oracle = dict(candidate.get("oracle_source", {})) if isinstance(candidate.get("oracle_source"), dict) else {}
        if args.oracle_kind:
            oracle["kind"] = args.oracle_kind
        if args.oracle_reference:
            oracle["reference"] = args.oracle_reference
        if oracle:
            candidate["oracle_source"] = oracle
        if args.expected_current_result:
            candidate["expected_current_result"] = args.expected_current_result
        if args.control:
            candidate["control"] = args.control
        if args.focal_subject:
            candidate["focal_subjects"] = args.focal_subject
        root_value = context.get("scope", {}).get("root") if isinstance(context.get("scope"), dict) else None
        root = Path(root_value) if isinstance(root_value, str) and root_value else args.context.parent
        patch = args.test_patch.read_text(encoding="utf-8")
        config = _config(root)
        plan = build_proof_test_plan(root, patch, candidate, command=_command(root, config))
        print(json.dumps(redact_payload(plan.as_dict()), indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(redact_sensitive_text(str(error)), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
