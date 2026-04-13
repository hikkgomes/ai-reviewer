#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import json
import shutil
import subprocess
import sys


SCRIPT_ROOT = Path(__file__).resolve().parents[2]
SENTINEL_START = "<!-- AI-REVIEWER-START -->"
SENTINEL_END = "<!-- AI-REVIEWER-END -->"
CLAUDE_SETTINGS_TEMPLATE = {}
VSCODE_TASKS_TEMPLATE = {
    "version": "2.0.0",
    "tasks": [
        {
            "label": "AI Review: Changed",
            "type": "shell",
            "command": "bash .ai-review/scripts/review_changed.sh",
            "problemMatcher": [],
        },
        {
            "label": "AI Review: Full",
            "type": "shell",
            "command": "bash .ai-review/scripts/review.sh",
            "problemMatcher": [],
        },
    ],
}
ADDITIVE_FILES = {
    ".claude/commands/ai-review.md": """Review the current changes using the universal reviewer.

Steps:
1. Read `.ai-review/SKILL.md`.
2. Read `.ai-review/local.json` if present.
3. Run `.ai-review/scripts/review_changed.sh`.
4. Return the report using `.ai-review/templates/review-report.md`.
""",
    ".claude/commands/ai-review-staged.md": """Review the current repository changes using the universal reviewer, focused on staged, modified, and untracked files first.

Steps:
1. Read `.ai-review/SKILL.md`.
2. Read `.ai-review/local.json`.
3. Run `.ai-review/scripts/review_changed.sh`.
4. Use `.ai-review/templates/review-report.md`.
""",
    ".claude/agents/universal-code-reviewer.md": """---
name: universal-code-reviewer
description: Use this agent when the user wants a careful code review of AI-written code, especially for correctness, security, edge cases, regressions, and missed constraints.
---

You are a focused code reviewer.

Workflow:
1. Read `.ai-review/SKILL.md`.
2. Read `.ai-review/local.json` if present.
3. Prefer `.ai-review/scripts/review_changed.sh`.
4. Use `.ai-review/scripts/review.sh` when broader validation is needed.
5. Follow `.ai-review/templates/review-report.md`.
6. Be explicit about uncertainty and unverified claims.
""",
}


def find_target_root() -> Path:
    """Resolve the repo root for both template-folder and installed modes."""
    if (SCRIPT_ROOT / "FIRST_RUN.txt").exists():
        return SCRIPT_ROOT.parent
    return SCRIPT_ROOT


ROOT = find_target_root()


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def is_empty_value(value) -> bool:
    return value == "" or value == [] or value == {} or value is False


def fill_if_empty(existing, detected):
    if isinstance(existing, dict) and isinstance(detected, dict):
        result = dict(existing)
        for key, value in detected.items():
            if key not in result or is_empty_value(result[key]):
                result[key] = value
            elif isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = fill_if_empty(result[key], value)
        return result
    return detected if is_empty_value(existing) else existing


def deep_merge_missing(existing: dict, template: dict) -> dict:
    result = dict(existing)
    for key, value in template.items():
        if key not in result:
            result[key] = value
            continue
        if isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_missing(result[key], value)
    return result


def wrap_with_sentinels(content: str) -> str:
    body = content.strip()
    return f"{SENTINEL_START}\n{body}\n{SENTINEL_END}\n"


def install_reviewer_files(template_root: Path, target_root: Path) -> list[str]:
    """Copy .ai-review/ from a dropped template folder into the repo root."""
    if template_root == target_root:
        return ["already installed"]

    messages = []
    src = template_root / ".ai-review"
    dst = target_root / ".ai-review"
    if not src.exists():
        return ["skipped .ai-review install (missing source)"]

    if dst.exists():
        for item in src.rglob("*"):
            if not item.is_file():
                continue
            rel = item.relative_to(src)
            target_file = dst / rel
            if not target_file.exists():
                target_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, target_file)
                messages.append(f"copied {rel.as_posix()}")
            else:
                messages.append(f"kept existing {rel.as_posix()}")
    else:
        shutil.copytree(src, dst)
        messages.append("copied .ai-review/")

    local_path = target_root / ".ai-review" / "local.json"
    local_data = read_json(local_path) or read_json(template_root / ".ai-review" / "local.json")
    bootstrap = local_data.setdefault("bootstrap", {})
    try:
        bootstrap["template_folder"] = template_root.relative_to(target_root).as_posix()
    except ValueError:
        bootstrap["template_folder"] = template_root.as_posix()
    write_json(local_path, local_data)
    return messages


def run_json_script(args: list[str], cwd: Path) -> dict:
    try:
        result = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        return {}
    if result.returncode != 0:
        return {}
    try:
        return json.loads(result.stdout)
    except Exception:
        return {}


def run_auto_detection(target: Path) -> dict:
    detected: dict = {}
    scripts_dir = target / ".ai-review" / "scripts"

    commands = run_json_script([sys.executable, str(scripts_dir / "detect_commands.py")], target)
    if commands:
        detected = fill_if_empty(detected, commands)

    architecture = run_json_script(
        [sys.executable, str(scripts_dir / "detect_architecture.py"), "--dir", "."],
        target,
    )
    if architecture:
        detected = fill_if_empty(detected, architecture)

    return detected


def populate_local_json(target: Path, detected: dict) -> str:
    if not detected:
        return "skipped"

    local_path = target / ".ai-review" / "local.json"
    local_data = read_json(local_path)
    if not local_data:
        local_data = {}

    write_json(local_path, fill_if_empty(local_data, detected))
    return "populated"


def merge_text_file(target: Path, source_text: str) -> str:
    wrapped = wrap_with_sentinels(source_text)
    if not target.exists():
        target.write_text(wrapped, encoding="utf-8")
        return "created"

    existing = read_text(target)
    if SENTINEL_START in existing and SENTINEL_END in existing:
        start = existing.index(SENTINEL_START)
        end = existing.index(SENTINEL_END) + len(SENTINEL_END)
        updated = existing[:start] + wrapped.rstrip("\n") + existing[end:]
        if not updated.endswith("\n"):
            updated += "\n"
        target.write_text(updated, encoding="utf-8")
        return "updated"

    suffix = "" if existing.endswith("\n") else "\n"
    target.write_text(existing + suffix + "\n" + wrapped, encoding="utf-8")
    return "appended"


def merge_settings() -> str:
    path = ROOT / ".claude" / "settings.json"
    merged = deep_merge_missing(read_json(path), CLAUDE_SETTINGS_TEMPLATE)
    write_json(path, merged)
    return "merged"


def merge_vscode_tasks() -> str:
    path = ROOT / ".vscode" / "tasks.json"
    existing = read_json(path)
    if not existing:
        existing = {"version": VSCODE_TASKS_TEMPLATE["version"], "tasks": []}

    tasks = existing.get("tasks")
    if not isinstance(tasks, list):
        tasks = []
    seen = {task.get("label") for task in tasks if isinstance(task, dict)}
    for task in VSCODE_TASKS_TEMPLATE["tasks"]:
        if task["label"] not in seen:
            tasks.append(task)
            seen.add(task["label"])

    merged = dict(existing)
    merged.setdefault("version", VSCODE_TASKS_TEMPLATE["version"])
    merged["tasks"] = tasks
    write_json(path, merged)
    return "merged"


def ensure_additive_files() -> list[str]:
    messages = []
    for rel_path, text in ADDITIVE_FILES.items():
        target = ROOT / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            messages.append(f"kept {rel_path}")
            continue
        target.write_text(text.rstrip() + "\n", encoding="utf-8")
        messages.append(f"created {rel_path}")
    return messages


def main() -> None:
    target = find_target_root()
    for message in install_reviewer_files(SCRIPT_ROOT, target):
        print(message)
    detected = run_auto_detection(target)
    print(f".ai-review/local.json: {populate_local_json(target, detected)} from auto-detection")

    claude_source = read_text(ROOT / ".ai-review" / "bootstrap" / "claude-instructions.md")
    codex_source = read_text(ROOT / ".ai-review" / "bootstrap" / "codex-instructions.md")

    if claude_source:
        print(f"CLAUDE.md: {merge_text_file(ROOT / 'CLAUDE.md', claude_source)}")
    else:
        print("CLAUDE.md: skipped (missing template)")

    if codex_source:
        print(f"AGENTS.md: {merge_text_file(ROOT / 'AGENTS.md', codex_source)}")
    else:
        print("AGENTS.md: skipped (missing template)")

    print(f".claude/settings.json: {merge_settings()}")
    print(f".vscode/tasks.json: {merge_vscode_tasks()}")
    for message in ensure_additive_files():
        print(message)


if __name__ == "__main__":
    main()
