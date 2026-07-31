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

DETECTED_JSON="$(mktemp /tmp/ai_review_detected.XXXXXX.json 2>/dev/null || mktemp -t ai_review_detected)"
trap 'rm -f "$DETECTED_JSON"' EXIT
python3 "$SCRIPT_DIR/detect_commands.py" >"$DETECTED_JSON" 2>/dev/null || true

CONTEXT_PATH="${AI_REVIEW_CONTEXT_PATH:-$(mktemp /tmp/ai_review_context.XXXXXX 2>/dev/null || mktemp -t ai_review_context)}"
python3 "$SCRIPT_DIR/build_review_context.py" \
  --root "$ROOT" --mode full --output "$CONTEXT_PATH" >/dev/null
echo "Review context: $CONTEXT_PATH"

echo "== Universal AI Review: full repo =="
echo "Repo: $ROOT"
echo
echo "== Detected languages =="
python3 - <<'PY'
from pathlib import Path

extensions = {
    ".ts": "typescript", ".tsx": "typescript", ".js": "javascript",
    ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".py": "python", ".sql": "sql", ".java": "java-csharp",
    ".cs": "java-csharp", ".go": "go", ".rs": "rust", ".cpp": "cpp",
    ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".h": "cpp", ".c": "cpp", ".php": "php",
}
ignored = {".git", "node_modules", "vendor", "dist", "build", "target", ".next"}
languages = {
    extensions[path.suffix.lower()]
    for path in Path.cwd().rglob("*")
    if path.is_file()
    and not any(part in ignored for part in path.parts)
    and path.suffix.lower() in extensions
}
print(", ".join(sorted(languages)) if languages else "none")
print()
PY

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
