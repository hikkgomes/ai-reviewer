#!/usr/bin/env python3
"""Plan and explicitly execute exact repository review-command invocations."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
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


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _workspace(name: str, payload: object) -> dict:
    item = dict(payload) if isinstance(payload, dict) else {}
    item.setdefault("root", "." if name == "root" else name)
    item.setdefault("commands", {})
    return item


def _workspaces(data: dict) -> dict[str, dict]:
    raw = data.get("workspaces") or {}
    if not isinstance(raw, dict):
        return {}
    return {str(name): _workspace(str(name), payload) for name, payload in raw.items()}


def _command_keys(scope: str, run_install: bool) -> list[str]:
    if scope == "diff":
        return ["lint", "typecheck"]
    keys = ["lint", "typecheck", "test", "build", "format"]
    return ["install", *keys] if run_install else keys


def _resolved_commands(
    local_scope: dict,
    detected_scope: dict,
    local_defaults: dict,
    detected_defaults: dict,
    keys: list[str],
) -> dict[str, str]:
    commands = {}
    for key in keys:
        candidates = (
            (local_scope.get("commands") or {}).get(key),
            (detected_scope.get("commands") or {}).get(key),
            (local_defaults.get("commands") or {}).get(key),
            (detected_defaults.get("commands") or {}).get(key),
        )
        commands[key] = next(
            (
                str(value).strip()
                for value in candidates
                if isinstance(value, str) and value.strip()
            ),
            "",
        )
    return commands


def build_review_plans(
    *,
    root: Path,
    scope: str,
    detected_path: Path | None = None,
) -> tuple[dict[str, ExecutionPlan], list[str]]:
    local = _load_json(root / ".ai-review" / "local.json")
    detected = _load_json(detected_path) if detected_path else {}
    local_workspaces = _workspaces(local)
    detected_workspaces = _workspaces(detected)
    run_install = bool(
        (local.get("review_options") or {}).get("run_install_on_review", False)
    )
    keys = _command_keys(scope, run_install)
    plans = {}
    errors = []

    workspace_names = list(dict.fromkeys([
        *detected_workspaces.keys(),
        *local_workspaces.keys(),
    ]))
    scopes: list[tuple[str, Path, dict, dict]] = [
        ("root", root, local, detected),
    ]
    for name in workspace_names:
        local_scope = local_workspaces.get(name) or {}
        detected_scope = detected_workspaces.get(name) or {}
        workspace = local_scope or detected_scope
        rel_root = str(workspace.get("root") or name or ".").strip() or "."
        scopes.append((name, root / rel_root, local_scope, detected_scope))

    for label, cwd, local_scope, detected_scope in scopes:
        commands = _resolved_commands(
            local_scope,
            detected_scope,
            local,
            detected,
            keys,
        )
        for category, command in commands.items():
            if not command:
                continue
            name = f"{scope}:{label}:{category}"
            plan, error = build_execution_plan(
                kind="review-command",
                name=name,
                argv=["/bin/sh", "-c", command],
                working_directory=cwd,
            )
            if error:
                errors.append(f"{name}: {error}")
            elif plan:
                plans[name] = plan
    return plans, errors


def _approvals(cli_values: list[str]) -> set[str]:
    values = set(cli_values)
    values.update(
        value.strip()
        for value in os.environ.get("AI_REVIEW_APPROVED_PLANS", "").split(",")
        if value.strip()
    )
    return values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope", choices=("full", "diff"), required=True)
    parser.add_argument("--detected-json", type=Path)
    parser.add_argument("--approve-plan", action="append", default=[])
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args()
    root = Path.cwd().resolve()
    approvals = _approvals(args.approve_plan)
    plans, errors = build_review_plans(
        root=root,
        scope=args.scope,
        detected_path=args.detected_json,
    )
    results = []
    matched = set()

    for name, planned in plans.items():
        result = {
            "name": redact_sensitive_text(name),
            "plan": planned.redacted_payload(),
            "approved": False,
            "executed": False,
            "exit_code": None,
            "output": "",
        }
        if planned.approval_digest in approvals:
            matched.add(planned.approval_digest)
            # Reload both repository and detected configuration immediately before use.
            current_plans, current_errors = build_review_plans(
                root=root,
                scope=args.scope,
                detected_path=args.detected_json,
            )
            current = current_plans.get(name)
            if current_errors:
                result["output"] = redact_sensitive_text("; ".join(current_errors))
            elif current is None:
                result["output"] = "Approved review-command plan no longer exists."
            else:
                result["plan"] = current.redacted_payload()
                completed, execution_error = execute_approved_plan(
                    current,
                    planned.approval_digest,
                )
                if execution_error:
                    result["output"] = redact_sensitive_text(execution_error)
                elif completed is not None:
                    result.update({
                        "approved": True,
                        "executed": True,
                        "exit_code": completed.returncode,
                        "output": redact_sensitive_text(
                            (completed.stdout + completed.stderr).strip()
                        )[-4000:],
                    })
        else:
            result["output"] = (
                "Planned but not executed. Approve this exact digest through "
                "--approve-plan or trusted-local AI_REVIEW_APPROVED_PLANS."
            )
        results.append(result)

    approval_errors = [
        "Malformed review-command approval digest."
        for value in approvals
        if not valid_approval_digest(value)
    ]
    approval_errors.extend(
        "Unknown or stale review-command approval digest."
        for _value in sorted(approvals - matched)
        if valid_approval_digest(_value)
    )
    approval_errors.extend(redact_sensitive_text(error) for error in errors)

    if args.format == "json":
        print(json.dumps(
            {"commands": results, "approval_errors": approval_errors},
            indent=2,
            sort_keys=True,
        ))
    elif not results:
        print("No review commands configured.")
    else:
        for result in results:
            print(f"[review-command] {result['name']}")
            print(f"  plan: {json.dumps(result['plan'], sort_keys=True)}")
            print(
                f"  approved={str(result['approved']).lower()} "
                f"executed={str(result['executed']).lower()} "
                f"exit={result['exit_code'] if result['exit_code'] is not None else 'n/a'}"
            )
            if result["output"]:
                print(f"  output: {result['output']}")
        for error in approval_errors:
            print(f"[approval rejected] {error}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
