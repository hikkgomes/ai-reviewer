#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(pwd)"
cd "$ROOT"

BASE_REF="${1:-${AI_REVIEW_BASE:-}}"

if [ -z "$BASE_REF" ] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  BASE_REF="$(git rev-parse --abbrev-ref --symbolic-full-name @{upstream} 2>/dev/null || true)"
fi

if [ -z "$BASE_REF" ] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  for candidate in origin/main origin/master main master; do
    if git rev-parse --verify "$candidate" >/dev/null 2>&1; then
      BASE_REF="$candidate"
      break
    fi
  done
fi

CHANGED_FILE_LIST="$(mktemp /tmp/ai_review_changed.XXXXXX 2>/dev/null || mktemp -t ai_review_changed)"
export AI_REVIEW_FILE_LIST="$CHANGED_FILE_LIST"
trap 'rm -f "$CHANGED_FILE_LIST"' EXIT

if [ -n "$BASE_REF" ] && git rev-parse --verify "$BASE_REF" >/dev/null 2>&1; then
  MERGE_BASE="$(git merge-base "$BASE_REF" HEAD 2>/dev/null || true)"
  if [ -n "$MERGE_BASE" ]; then
    (
      git diff --name-only "$MERGE_BASE...HEAD"
      git diff --name-only --cached
      git diff --name-only
      git ls-files --others --exclude-standard
    ) 2>/dev/null | sort -u >"$CHANGED_FILE_LIST"
    echo "== AI Review: diff scope =="
    echo "Base: $BASE_REF"
    echo "Merge base: $MERGE_BASE"
  else
    (
      git diff --name-only "$BASE_REF"
      git diff --name-only --cached
      git diff --name-only
      git ls-files --others --exclude-standard
    ) 2>/dev/null | sort -u >"$CHANGED_FILE_LIST"
    echo "== AI Review: diff scope =="
    echo "Base: $BASE_REF"
  fi
else
  (
    git diff --name-only --cached
    git diff --name-only
    git ls-files --others --exclude-standard
  ) 2>/dev/null | sort -u >"$CHANGED_FILE_LIST"
  echo "== AI Review: local diff scope =="
  if [ -n "$BASE_REF" ]; then
    echo "Base not found: $BASE_REF"
  else
    echo "Base: not detected"
  fi
fi

CHANGED="$(cat "$CHANGED_FILE_LIST")"

if [ -z "${CHANGED}" ]; then
  echo "No diff, staged, modified, or untracked files detected."
else
  echo "Changed files:"
  echo "${CHANGED}"
fi

echo
echo "== Detected languages =="
python3 - <<'PY'
import pathlib
import subprocess

EXTENSIONS = {
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".py": "python",
    ".sql": "sql",
    ".java": "java-csharp",
    ".cs": "java-csharp",
    ".go": "go",
    ".rs": "rust",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".h": "cpp",
    ".c": "cpp",
    ".php": "php",
}

try:
    changed = subprocess.check_output(
        "(git diff --name-only --cached; git diff --name-only; git ls-files --others --exclude-standard) 2>/dev/null | sort -u",
        shell=True,
        text=True,
    ).splitlines()
except Exception:
    changed = []

languages = sorted({EXTENSIONS.get(pathlib.Path(path).suffix.lower()) for path in changed} - {None})
print(", ".join(languages) if languages else "none")
print()
PY

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
python3 "$SCRIPT_DIR/scan_ai_gotchas.py"
