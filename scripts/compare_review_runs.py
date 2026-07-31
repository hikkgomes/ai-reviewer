#!/usr/bin/env python3
"""Compare two provenance-backed benchmark runs without claiming a safety score."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


METRICS = ("finding_precision", "critical_high_recall", "meaningful_medium_recall", "unsupported_finding_rate", "location_accuracy", "severity_accuracy", "duplicate_finding_rate", "not_verified_recall")


def load(directory: Path) -> dict[str, dict[str, Any]]:
    values = {}
    for path in directory.glob("score-*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        values[data.get("benchmark_id", path.stem)] = data
    return values


def compare(new: dict[str, dict[str, Any]], baseline: dict[str, dict[str, Any]]) -> dict[str, Any]:
    cases = []
    for benchmark_id in sorted(set(new) | set(baseline)):
        current, old = new.get(benchmark_id, {}), baseline.get(benchmark_id, {})
        if current.get("status") == "not_scorable" or old.get("status") == "not_scorable":
            cases.append({"benchmark_id": benchmark_id, "status": "not_comparable", "new": current.get("reason"), "baseline": old.get("reason")})
            continue
        cases.append({"benchmark_id": benchmark_id, "status": "comparable", "delta": {metric: current.get(metric, 0) - old.get(metric, 0) for metric in METRICS}})
    return {"schema_version": "1.0", "comparison": "review-quality", "cases": cases, "composite_score": None}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--new", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = compare(load(args.new), load(args.baseline))
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
