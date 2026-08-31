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

DETECTED_JSON="$(mktemp /tmp/ai_review_detected.XXXXXX.json 2>/dev/null || mktemp -t ai_review_detected)"
trap 'rm -f "$DETECTED_JSON"' EXIT
python3 "$SCRIPT_DIR/detect_commands.py" >"$DETECTED_JSON" 2>/dev/null || true

CONTEXT_PATH="${AI_REVIEW_CONTEXT_PATH:-$(mktemp /tmp/ai_review_context.XXXXXX 2>/dev/null || mktemp -t ai_review_context)}"
CONTEXT_COMMAND=(python3 "$SCRIPT_DIR/build_review_context.py" --root "$ROOT" --mode full --output "$CONTEXT_PATH")
if [ -n "${AI_REVIEW_CONTEXT_TIMEOUT_SECONDS:-}" ]; then
  CONTEXT_COMMAND+=(--timeout "$AI_REVIEW_CONTEXT_TIMEOUT_SECONDS")
fi
if "${CONTEXT_COMMAND[@]}" >/dev/null; then
  :
else
  CONTEXT_STATUS=$?
  echo "Dissect context construction failed (exit $CONTEXT_STATUS)." >&2
  exit "$CONTEXT_STATUS"
fi
echo "Review context: $CONTEXT_PATH"

echo "== Universal AI Review: full repo =="
echo "Repo: $ROOT"
echo
echo "== Detected languages =="
if python3 "$SCRIPT_DIR/detect_languages.py" --root "$ROOT"; then
  :
else
  DETECT_STATUS=$?
  echo "Dissect language detection failed (exit $DETECT_STATUS)." >&2
  exit "$DETECT_STATUS"
fi
echo

echo "== Review command plans =="
python3 "$SCRIPT_DIR/review_commands.py" \
  --scope full \
  --detected-json "$DETECTED_JSON"
echo

echo "== Deterministic scan =="
export AI_REVIEW_SCOPE=full
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
