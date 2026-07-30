#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export DISSECT_SCRIPT_DIR="$SCRIPT_DIR"
ROOT="$(pwd)"
cd "$ROOT"

if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Dissect requires Python 3.11 or newer." >&2
  exit 1
fi

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

COMMITTED_RANGE=""
if [ -n "$BASE_REF" ] && git rev-parse --verify "$BASE_REF" >/dev/null 2>&1; then
  MERGE_BASE="$(git merge-base "$BASE_REF" HEAD 2>/dev/null || true)"
  if [ -n "$MERGE_BASE" ]; then
    COMMITTED_RANGE="$MERGE_BASE...HEAD"
    echo "== AI Review: diff scope =="
    echo "Base: $BASE_REF"
    echo "Merge base: $MERGE_BASE"
  else
    COMMITTED_RANGE="$BASE_REF"
    echo "== AI Review: diff scope =="
    echo "Base: $BASE_REF"
  fi
else
  echo "== AI Review: local diff scope =="
  if [ -n "$BASE_REF" ]; then
    echo "Base not found: $BASE_REF"
  else
    echo "Base: not detected"
  fi
fi

CHANGED_FILE_LIST="$(mktemp /tmp/ai_review_changed.XXXXXX 2>/dev/null || mktemp -t ai_review_changed)"
export AI_REVIEW_FILE_LIST="$CHANGED_FILE_LIST"
trap 'rm -f "$CHANGED_FILE_LIST"' EXIT
if ! python3 "$SCRIPT_DIR/diff_file_list.py" --range "$COMMITTED_RANGE" >"$CHANGED_FILE_LIST"; then
  exit 1
fi

if [ ! -s "$CHANGED_FILE_LIST" ]; then
  echo "No diff, staged, modified, or untracked files detected."
else
  echo "Changed files:"
  python3 "$SCRIPT_DIR/diff_file_list.py" --display "$CHANGED_FILE_LIST"
fi

CONTEXT_PATH="${AI_REVIEW_CONTEXT_PATH:-$(mktemp /tmp/ai_review_context.XXXXXX 2>/dev/null || mktemp -t ai_review_context)}"
python3 "$SCRIPT_DIR/build_review_context.py" \
  --root "$ROOT" --mode diff --base "${MERGE_BASE:-$BASE_REF}" \
  --file-list "$CHANGED_FILE_LIST" --output "$CONTEXT_PATH" >/dev/null
echo "Review context: $CONTEXT_PATH"

echo
echo "== Detected languages =="
python3 - <<'PY'
import os
from pathlib import Path
import sys

sys.path.insert(0, os.environ["DISSECT_SCRIPT_DIR"])
from diff_file_list import read_file_list

extensions = {
    ".ts": "typescript", ".tsx": "typescript", ".js": "javascript",
    ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".py": "python", ".sql": "sql", ".java": "java-csharp",
    ".cs": "java-csharp", ".go": "go", ".rs": "rust", ".cpp": "cpp",
    ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".h": "cpp", ".c": "cpp", ".php": "php",
}
changed = read_file_list(Path(os.environ["AI_REVIEW_FILE_LIST"]))
languages = {
    extensions[Path(path).suffix.lower()]
    for path in changed
    if Path(path).suffix.lower() in extensions
}
print(", ".join(sorted(languages)) if languages else "none")
print()
PY

echo "== Review command plans =="
python3 "$SCRIPT_DIR/review_commands.py" --scope diff
echo

echo "== Deterministic scan =="
python3 "$SCRIPT_DIR/scan_ai_gotchas.py"
SCAN_STATUS=$?

echo
echo "== Optional tool integrations =="
python3 "$SCRIPT_DIR/tool_integrations.py"

exit "$SCAN_STATUS"
