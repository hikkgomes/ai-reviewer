#!/usr/bin/env python3
from pathlib import Path
import json
import shutil
import sys

ROOT = Path(__file__).resolve().parents[2]
LOCAL = ROOT / ".ai-review" / "local.json"

MODE = (sys.argv[1] if len(sys.argv) > 1 else "").strip().lower()

TO_DELETE = {
    "codex": [
        ROOT / ".ai-review" / "bootstrap" / "CODEX.md",
    ],
    "claude": [
        ROOT / ".ai-review" / "bootstrap" / "CLAUDE.md",
    ],
    "final": [
        ROOT / ".ai-review" / "bootstrap" / "COMMON.md",
        ROOT / ".ai-review" / "bootstrap" / "cleanup.py",
        ROOT / ".ai-review" / "bootstrap" / "claude-instructions.md",
        ROOT / ".ai-review" / "bootstrap" / "codex-instructions.md",
        ROOT / ".ai-review" / "scripts" / "install_config.py",
        ROOT / "FIRST_RUN.txt",
    ],
}

def rm(path: Path):
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
    elif path.exists():
        path.unlink(missing_ok=True)

def maybe_remove_empty_bootstrap_dir():
    d = ROOT / ".ai-review" / "bootstrap"
    if d.exists() and d.is_dir() and not any(d.iterdir()):
        d.rmdir()

def load_flags():
    try:
        data = json.loads(LOCAL.read_text(encoding="utf-8"))
        bootstrap = data.get("bootstrap") or {}
        return bool(bootstrap.get("codex_done")), bool(bootstrap.get("claude_done"))
    except Exception:
        return False, False

if MODE not in TO_DELETE:
    print("Usage: python3 .ai-review/bootstrap/cleanup.py [codex|claude|final]")
    sys.exit(1)

for p in TO_DELETE[MODE]:
    rm(p)

codex_done, claude_done = load_flags()

if codex_done and claude_done:
    for p in TO_DELETE["final"]:
        rm(p)
    try:
        data = json.loads(LOCAL.read_text(encoding="utf-8"))
        bootstrap = data.get("bootstrap") or {}
        template_folder = (bootstrap.get("template_folder") or "").strip()
        if template_folder:
            template_path = ROOT / template_folder
            if template_path.exists() and template_path != ROOT:
                shutil.rmtree(template_path, ignore_errors=True)
                print(f"Removed template folder: {template_folder}")
            bootstrap.pop("template_folder", None)
            data["bootstrap"] = bootstrap
            LOCAL.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except Exception:
        pass

maybe_remove_empty_bootstrap_dir()
print(f"Bootstrap cleanup complete for: {MODE}")
