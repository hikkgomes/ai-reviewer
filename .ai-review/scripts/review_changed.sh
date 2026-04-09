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
python3 .ai-review/scripts/scan_ai_gotchas.py
