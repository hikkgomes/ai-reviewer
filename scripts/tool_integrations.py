#!/usr/bin/env python3
"""Plan or execute repository-configured tools through exact-plan approval."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys

if sys.version_info < (3, 11):
    raise SystemExit("Dissect requires Python 3.11 or newer.")

from dissect_checks.execution_plan import (
    ExecutionPlan,
    build_execution_plan,
    execute_approved_plan,
    valid_approval_digest,
)
from dissect_checks.redaction import redact_sensitive_text


KNOWN_TOOLS = ("gitleaks", "trufflehog", "semgrep", "trivy", "pip-audit")


def load_config() -> dict:
    try:
        return json.loads(
            (Path.cwd() / ".ai-review" / "local.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        return {}


def _configured_tools(config: dict) -> dict:
    configured = (config.get("security_review") or {}).get("tool_commands") or {}
    return configured if isinstance(configured, dict) else {}


def _parse_tool(
    name: str,
    raw_config: object,
) -> tuple[list[str], set[int], str | None]:
    if raw_config is None:
        return [], set(), None
    if not isinstance(raw_config, dict):
        return [], set(), (
            "use an object with a non-empty string argv array; "
            "shell command strings are rejected"
        )
    raw_argv = raw_config.get("argv")
    if not (
        isinstance(raw_argv, list)
        and raw_argv
        and all(isinstance(value, str) and value for value in raw_argv)
    ):
        return [], set(), "execution plan requires a non-empty string argv array"
    finding_exit_codes = {
        int(code)
        for code in raw_config.get("finding_exit_codes", [])
        if isinstance(code, int) or (isinstance(code, str) and code.isdigit())
    }
    return list(raw_argv), finding_exit_codes, None


def build_tool_plans(config: dict) -> tuple[dict[str, ExecutionPlan], dict[str, str]]:
    plans = {}
    errors = {}
    for name, raw_config in _configured_tools(config).items():
        argv, finding_exit_codes, parse_error = _parse_tool(str(name), raw_config)
        if parse_error:
            errors[str(name)] = parse_error
            continue
        plan, plan_error = build_execution_plan(
            kind="tool",
            name=str(name),
            argv=argv,
            working_directory=Path.cwd(),
            finding_exit_codes=finding_exit_codes,
        )
        if plan_error:
            errors[str(name)] = plan_error
        elif plan:
            plans[str(name)] = plan
    return plans, errors


def _base_result(
    name: str,
    *,
    configured: bool,
    detected: bool,
) -> dict:
    return {
        "tool": redact_sensitive_text(name),
        "detected": detected,
        "configured": configured,
        "plan": None,
        "approved": False,
        "executed": False,
        "execution_completed": False,
        "exit_code": None,
        "complete": False,
        "passed": None,
        "findings_produced": None,
        "coverage_complete": None,
        "output": "",
    }


def _execute_current_plan(
    name: str,
    approval: str,
) -> tuple[ExecutionPlan | None, object | None, str | None]:
    # Reload repository configuration and rebuild every execution-affecting field.
    current_plans, current_errors = build_tool_plans(load_config())
    if name in current_errors:
        return None, None, current_errors[name]
    plan = current_plans.get(name)
    if plan is None:
        return None, None, "approved tool plan no longer exists"
    completed, execution_error = execute_approved_plan(plan, approval)
    return plan, completed, execution_error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--approve-plan",
        action="append",
        default=[],
        metavar="SHA256",
        help="Execute only a currently configured plan with this exact approval digest.",
    )
    args = parser.parse_args()
    approvals = set(args.approve_plan)
    approvals.update(
        value.strip()
        for value in os.environ.get("AI_REVIEW_APPROVED_PLANS", "").split(",")
        if value.strip()
    )
    malformed = sorted(value for value in approvals if not valid_approval_digest(value))

    config = load_config()
    configured = _configured_tools(config)
    plans, plan_errors = build_tool_plans(config)
    known_or_configured = sorted(set(KNOWN_TOOLS) | set(configured))
    results = []
    matched_approvals = set()

    for name in known_or_configured:
        configured_entry = name in configured
        plan = plans.get(name)
        detected = bool(
            plan
            or (
                not configured_entry
                and shutil.which(name)
            )
        )
        result = _base_result(
            name,
            configured=configured_entry,
            detected=detected,
        )
        if plan:
            result["plan"] = plan.redacted_payload()
        if name in plan_errors:
            result["output"] = f"Configured check was not run: {plan_errors[name]}."
        elif plan and plan.approval_digest in approvals:
            matched_approvals.add(plan.approval_digest)
            current_plan, completed, execution_error = _execute_current_plan(
                name,
                plan.approval_digest,
            )
            if current_plan:
                result["plan"] = current_plan.redacted_payload()
            if execution_error:
                result["output"] = (
                    f"Configured check was not run: {redact_sensitive_text(execution_error)}."
                )
            elif completed is not None and current_plan is not None:
                finding_codes = set(current_plan.finding_exit_codes)
                result.update({
                    "approved": True,
                    "executed": True,
                    "execution_completed": True,
                    "exit_code": completed.returncode,
                    "complete": True,
                    "passed": completed.returncode == 0,
                    "findings_produced": (
                        completed.returncode in finding_codes
                        if finding_codes
                        else (False if completed.returncode == 0 else None)
                    ),
                    "coverage_complete": (
                        completed.returncode == 0
                        or completed.returncode in finding_codes
                    ),
                    "output": redact_sensitive_text(
                        (completed.stdout + completed.stderr).strip()
                    )[-4000:],
                })
        elif plan:
            result["output"] = (
                "Planned but not executed. Review the redacted canonical plan, then pass "
                f"--approve-plan {plan.approval_digest} from a trusted local invocation."
            )
        elif detected:
            result["output"] = (
                "Detected but not executed; configure an argv array to generate a reviewable plan."
            )
        results.append(result)

    approval_errors = [
        "Malformed execution-plan approval digest."
        for _value in malformed
    ]
    approval_errors.extend(
        "Unknown or stale execution-plan approval digest."
        for _value in sorted(approvals - matched_approvals - set(malformed))
    )

    if args.format == "json":
        print(json.dumps(
            {"tools": results, "approval_errors": approval_errors},
            indent=2,
            sort_keys=True,
        ))
    else:
        for result in results:
            if not result["detected"] and not result["configured"]:
                continue
            print(
                f"[tool] {result['tool']}: detected={str(result['detected']).lower()} "
                f"configured={str(result['configured']).lower()} "
                f"approved={str(result['approved']).lower()} "
                f"executed={str(result['executed']).lower()} "
                f"exit={result['exit_code'] if result['exit_code'] is not None else 'n/a'}"
            )
            if result["plan"]:
                print(f"  plan: {json.dumps(result['plan'], sort_keys=True)}")
            if result["output"]:
                print(f"  output: {result['output']}")
        for error in approval_errors:
            print(f"[approval rejected] {error}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
