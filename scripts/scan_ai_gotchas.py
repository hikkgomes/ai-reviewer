#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from dissect_checks.engine import history_scan_available, options_from_environment, scan_paths


SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SCHEMA_VERSION = "1.0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Dissect deterministic checks.")
    parser.add_argument("--format", choices=("text", "json"), default=None)
    parser.add_argument("--fail-on", choices=("none", "low", "medium", "high", "critical"), default=None)
    parser.add_argument("--include-generated", action="store_true")
    parser.add_argument("--history", action="store_true", help="Scan recent Git revisions; disabled by default.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        local = json.loads((Path.cwd() / ".ai-review" / "local.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        local = {}
    review_options = local.get("review_options") or {}
    output_format = args.format or review_options.get("deterministic_output", "text")
    fail_on = args.fail_on or review_options.get("fail_on_severity", "none")
    if output_format not in {"text", "json"}:
        output_format = "text"
    if fail_on not in {"none", "low", "medium", "high", "critical"}:
        fail_on = "none"
    options = options_from_environment(
        Path.cwd(),
        include_generated=args.include_generated,
        include_history=args.history,
    )
    findings = scan_paths(options)
    complete = history_scan_available(options)
    if output_format == "json":
        print(json.dumps({
            "schema_version": SCHEMA_VERSION,
            "scanner": "dissect",
            "complete": complete,
            "options": {
                "generated_bundles": options.include_generated,
                "git_history": options.include_history,
                "git_history_depth": options.history_depth if options.include_history else 0,
            },
            "summary": {
                "findings": sum(1 for item in findings if item.disposition == "finding"),
                "review_candidates": sum(1 for item in findings if item.disposition == "review-candidate"),
                "by_severity": {
                    level: sum(1 for item in findings if item.severity == level)
                    for level in ("critical", "high", "medium", "low")
                },
            },
            "findings": [item.as_dict() for item in findings],
        }, indent=2, sort_keys=True))
    elif not findings:
        print("No deterministic findings detected.")
    else:
        for item in findings:
            print(
                f"[{item.disposition.upper()}][{item.severity.upper()}][{item.check_id}][{item.confidence}] "
                f"{item.path}:{item.line} :: {item.evidence}"
            )

    if fail_on != "none":
        threshold = SEVERITY[fail_on]
        if any(
            item.disposition == "finding" and SEVERITY[item.severity] >= threshold
            for item in findings
        ):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
