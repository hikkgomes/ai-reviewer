#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

echo "== Universal AI Review: changed scope =="

CHANGED="$( (git diff --name-only --cached; git diff --name-only; git ls-files --others --exclude-standard) 2>/dev/null | sort -u )"

if [ -z "${CHANGED}" ]; then
  echo "No staged, modified, or untracked files detected."
else
  echo "Changed files:"
  echo "${CHANGED}"
fi

echo
python3 - <<'PY'
import json
import pathlib
import subprocess
import sys

root = pathlib.Path.cwd()
local_path = root / ".ai-review" / "local.json"


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def normalize_workspace(name, payload):
    item = dict(payload or {})
    item.setdefault("root", "." if name == "root" else name)
    item.setdefault("commands", {})
    return item


def command_pair(scope):
    commands = scope.get("commands") or {}
    return {
        "lint": (commands.get("lint") or "").strip(),
        "typecheck": (commands.get("typecheck") or "").strip(),
    }


def run_scope(label, cwd, commands):
    configured = [(name, cmd) for name, cmd in commands.items() if cmd]
    if not configured:
        return False

    print(f"== Fast checks: {label} ==")
    print(f"Path: {cwd}")
    print()
    for key, cmd in configured:
        print(f"$ {cmd}")
        sys.stdout.flush()
        result = subprocess.run(cmd, shell=True, cwd=cwd)
        print(f"[exit {result.returncode}] {key}")
        print()
    return True


local = load_json(local_path)
ran_any = False

ran_any = run_scope("root", root, command_pair(local)) or ran_any

for name, payload in (local.get("workspaces") or {}).items():
    workspace = normalize_workspace(name, payload)
    rel_root = (workspace.get("root") or name or ".").strip() or "."
    cwd = root / rel_root
    if not cwd.exists():
        print(f"== Fast checks: {name} ==")
        print(f"Skipping missing workspace path: {cwd}")
        print()
        continue
    ran_any = run_scope(name, cwd, command_pair(workspace)) or ran_any

if not ran_any:
    print("== Fast checks ==")
    print("No lint or typecheck commands configured in .ai-review/local.json.")
    print()
PY

echo "== Heuristic scan =="
python3 .ai-review/scripts/scan_ai_gotchas.py
