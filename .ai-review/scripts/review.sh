#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

DETECTED_JSON="$(mktemp /tmp/ai_review_detected.XXXXXX.json 2>/dev/null || mktemp -t ai_review_detected)"
export DETECTED_JSON
trap 'rm -f "$DETECTED_JSON"' EXIT

python3 .ai-review/scripts/detect_commands.py >"$DETECTED_JSON" 2>/dev/null || true

python3 - <<'PY'
import json
import os
import pathlib
import subprocess

root = pathlib.Path.cwd()
local_path = root / ".ai-review" / "local.json"
detected_path = pathlib.Path(os.environ.get("DETECTED_JSON", "/tmp/ai_review_detected.json"))

def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}

def normalize_workspace(name, payload):
    item = dict(payload or {})
    item.setdefault("root", "." if name == "root" else name)
    item.setdefault("commands", {})
    item.setdefault("paths", {})
    item.setdefault("risk", {})
    item.setdefault("stack", [])
    item.setdefault("package_managers", [])
    return item

def collect_workspaces(data):
    workspaces = data.get("workspaces") or {}
    return {name: normalize_workspace(name, payload) for name, payload in workspaces.items()}

def get_run_order(local_data, detected_data):
    local_workspaces = collect_workspaces(local_data)
    detected_workspaces = collect_workspaces(detected_data)
    names = list(dict.fromkeys([*detected_workspaces.keys(), *local_workspaces.keys()]))
    if not names:
        return []
    order = []
    root_seen = False
    for name in names:
        workspace = local_workspaces.get(name) or detected_workspaces.get(name) or {}
        rel_root = (workspace.get("root") or name or ".").strip()
        if rel_root in {".", ""} and not root_seen:
            order.append(("root", normalize_workspace("root", workspace)))
            root_seen = True
            continue
        order.append((name, normalize_workspace(name, workspace)))
    return order

def resolve_workspace_path(workspace):
    rel_root = (workspace.get("root") or ".").strip() or "."
    return root / rel_root

def resolve_commands(local_scope, detected_scope, local_defaults, detected_defaults, run_install):
    command_keys = ["lint", "typecheck", "test", "build", "format"]
    if run_install:
        command_keys = ["install"] + command_keys
    commands = {}
    for key in command_keys:
        value = (((local_scope.get("commands") or {}).get(key)) or "").strip()
        if not value:
            value = (((detected_scope.get("commands") or {}).get(key)) or "").strip()
        if not value:
            value = (((local_defaults.get("commands") or {}).get(key)) or "").strip()
        if not value:
            value = (((detected_defaults.get("commands") or {}).get(key)) or "").strip()
        commands[key] = value
    return commands

def run_scope(label, cwd, commands):
    print(f"== Scope: {label} ==")
    print(f"Path: {cwd}")
    print()
    any_commands = False
    for key, cmd in commands.items():
        if not cmd:
            continue
        any_commands = True
        print(f"$ {cmd}")
        result = subprocess.run(cmd, shell=True, cwd=cwd)
        print(f"[exit {result.returncode}] {key}")
        print()
    if not any_commands:
        print("No commands configured.")
        print()

local = load_json(local_path)
detected = load_json(detected_path)
run_install = (local.get("review_options") or {}).get("run_install_on_review", False)

print("== Universal AI Review: full repo ==")
print(f"Repo: {root}")
print()

workspace_order = get_run_order(local, detected)

root_commands = resolve_commands(local, detected, {}, {}, run_install)
if workspace_order:
    if any(root_commands.values()):
        run_scope("root", root, root_commands)
    for name, workspace in workspace_order:
        cwd = resolve_workspace_path(workspace)
        if not cwd.exists():
            print(f"== Scope: {name} ==")
            print(f"Skipping missing workspace path: {cwd}")
            print()
            continue
        local_scope = (collect_workspaces(local).get(name) or {})
        detected_scope = (collect_workspaces(detected).get(name) or {})
        commands = resolve_commands(local_scope, detected_scope, local, detected, run_install)
        run_scope(name, cwd, commands)
else:
    run_scope("root", root, root_commands)
PY

echo "== Heuristic scan =="
python3 .ai-review/scripts/scan_ai_gotchas.py || true
