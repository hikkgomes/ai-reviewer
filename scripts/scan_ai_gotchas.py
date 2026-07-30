#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

if sys.version_info < (3, 11):
    raise SystemExit("Dissect requires Python 3.11 or newer.")

from dissect_checks.engine import options_from_environment, scan_report
from dissect_checks.fixtures import (
    is_trusted_self_review,
    trusted_self_review_digest,
    trusted_self_review_plan,
)
from dissect_checks.redaction import redact_sensitive_text


SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SCHEMA_VERSION = "3.0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Dissect deterministic checks.")
    parser.add_argument("--format", choices=("text", "json"), default=None)
    parser.add_argument("--fail-on", choices=("none", "low", "medium", "high", "critical"), default=None)
    parser.add_argument("--include-generated", action="store_true")
    parser.add_argument("--history", action="store_true", help="Scan recent Git revisions; disabled by default.")
    parser.add_argument(
        "--plan-self-review",
        action="store_true",
        help="Print an inert trusted-self-review plan and approval digest, then exit.",
    )
    parser.add_argument(
        "--approve-self-review",
        default="",
        metavar="SHA256",
        help="Enable exact fixture masking only for the matching checkout-bound plan.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path.cwd()
    if args.plan_self_review:
        plan = trusted_self_review_plan(root)
        digest = trusted_self_review_digest(root)
        if plan is None or digest is None:
            print(json.dumps({
                "self_review_plan": None,
                "error": "Target is not a complete Git checkout matching the installed fixture manifest.",
            }, indent=2, sort_keys=True))
            return 1
        safe_plan = dict(plan)
        safe_plan["checkout"] = dict(plan["checkout"])
        safe_plan["checkout"]["root"] = redact_sensitive_text(
            str(plan["checkout"]["root"])
        )
        print(json.dumps({
            "self_review_plan": safe_plan,
            "approval_digest": digest,
            "executed": False,
        }, indent=2, sort_keys=True))
        return 0
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
    self_review_approval = (
        args.approve_self_review
        or os.environ.get("DISSECT_SELF_REVIEW_APPROVAL", "")
    )
    self_review_enabled = is_trusted_self_review(root, self_review_approval)
    options = options_from_environment(
        root,
        include_generated=args.include_generated,
        include_history=args.history,
        self_review_approval=(
            self_review_approval if self_review_enabled else ""
        ),
    )
    report = scan_report(options)
    findings = report.findings
    if output_format == "json":
        print(json.dumps({
            "schema_version": SCHEMA_VERSION,
            "scanner": "dissect",
            "complete": report.complete,
            "coverage_errors": list(report.coverage_errors),
            "options": {
                "generated_bundles": options.include_generated,
                "git_history": options.include_history,
                "git_history_depth": options.history_depth if options.include_history else 0,
                "trusted_self_review": self_review_enabled,
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
                f"{item.path}:{item.line} :: {item.evidence} :: source={item.source}"
            )
            for historical in item.historical_sources:
                print(
                    f"  historical-source: {historical.source} "
                    f"{historical.path}:{historical.line}"
                )
    if output_format == "text" and report.coverage_errors:
        for error in report.coverage_errors:
            print(f"[INCOMPLETE] {error}", file=sys.stderr)

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
