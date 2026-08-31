#!/usr/bin/env bash
set -uo pipefail

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
CONTEXT_PID=""
WATCHDOG_PID=""
cleanup() {
  if [ -n "$CONTEXT_PID" ]; then kill -TERM "$CONTEXT_PID" 2>/dev/null || true; fi
  if [ -n "$WATCHDOG_PID" ]; then kill -TERM "$WATCHDOG_PID" 2>/dev/null || true; fi
  rm -f "$CHANGED_FILE_LIST"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
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
CONTEXT_COMMAND=(python3 "$SCRIPT_DIR/build_review_context.py" --root "$ROOT" --mode diff --base "${MERGE_BASE:-$BASE_REF}" --file-list "$CHANGED_FILE_LIST" --output "$CONTEXT_PATH")
if [ -n "${AI_REVIEW_CONTEXT_TIMEOUT_SECONDS:-}" ]; then
  CONTEXT_COMMAND+=(--timeout "$AI_REVIEW_CONTEXT_TIMEOUT_SECONDS")
fi
CALLER_PID="$PPID"
"${CONTEXT_COMMAND[@]}" >/dev/null &
CONTEXT_PID=$!
(
  while kill -0 "$CALLER_PID" 2>/dev/null; do sleep 1; done
  kill -TERM "$CONTEXT_PID" 2>/dev/null || true
) &
WATCHDOG_PID=$!
if wait "$CONTEXT_PID"; then
  CONTEXT_STATUS=0
else
  CONTEXT_STATUS=$?
fi
CONTEXT_PID=""
kill -TERM "$WATCHDOG_PID" 2>/dev/null || true
wait "$WATCHDOG_PID" 2>/dev/null || true
WATCHDOG_PID=""
if [ "$CONTEXT_STATUS" -ne 0 ]; then exit "$CONTEXT_STATUS"; fi
echo "Review context: $CONTEXT_PATH"

echo
echo "== Detected languages =="
if python3 "$SCRIPT_DIR/detect_languages.py" \
  --root "$ROOT" --entries-from "$CHANGED_FILE_LIST"; then
  :
else
  DETECT_STATUS=$?
  echo "Dissect language detection failed (exit $DETECT_STATUS)." >&2
  exit "$DETECT_STATUS"
fi
echo

echo "== Review command plans =="
python3 "$SCRIPT_DIR/review_commands.py" --scope diff
echo

echo "== Deterministic scan =="
python3 "$SCRIPT_DIR/scan_ai_gotchas.py"
SCAN_STATUS=$?

echo
echo "== Optional tool integrations =="
python3 "$SCRIPT_DIR/tool_integrations.py"

if [ -n "${AI_REVIEW_RESULT_PATH:-}" ]; then
  python3 "$SCRIPT_DIR/validate_review_result.py" "$AI_REVIEW_RESULT_PATH"
  RESULT_STATUS=$?
  if [ "$RESULT_STATUS" -ne 0 ]; then exit "$RESULT_STATUS"; fi
fi

exit "$SCAN_STATUS"
