#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import sys
import termios
import tty
from dataclasses import dataclass
from pathlib import Path


SKILL_NAME = "ai-reviewer"
CODEX_SKILL_NAMES = ("ai-review", "ai-review-universal")
SOURCE_ROOT = Path(__file__).resolve().parents[1]
ADAPTERS_ROOT = SOURCE_ROOT / "adapters"
CURSOR_ADAPTER = ADAPTERS_ROOT / "cursor-rules.md"
CURSOR_START = "<!-- AI-REVIEWER-START -->"
CURSOR_END = "<!-- AI-REVIEWER-END -->"
SKILL_ITEMS = [
    "SKILL.md",
    "README.md",
    "LICENSE",
    "commands",
    "agents",
    "reference",
    "scripts",
    "config",
]


@dataclass(frozen=True)
class InstallOption:
    key: str
    label: str
    detail: str
    detected: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install ai-reviewer as a machine-level skill.")
    parser.add_argument(
        "--install",
        default="",
        help="Non-interactive comma-separated install keys: claude,codex,cursor,all",
    )
    parser.add_argument("--yes", action="store_true", help="Install all detected skills.")
    return parser.parse_args()


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def copy_item(src: Path, dst: Path) -> None:
    if src.is_dir():
        shutil.copytree(
            src,
            dst,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__", ".DS_Store", "*.pyc"),
        )
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def install_skill(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for item in SKILL_ITEMS:
        copy_item(SOURCE_ROOT / item, destination / item)


def install_claude() -> None:
    claude_base = Path.home() / ".claude"
    skill_destination = claude_base / "skills" / SKILL_NAME
    install_skill(skill_destination)

    commands_dir = claude_base / "commands"
    agents_dir = claude_base / "agents"
    commands_dir.mkdir(parents=True, exist_ok=True)
    agents_dir.mkdir(parents=True, exist_ok=True)
    for command in (SOURCE_ROOT / "commands").glob("*.md"):
        shutil.copy2(command, commands_dir / command.name)
    for agent in (SOURCE_ROOT / "agents").glob("*.md"):
        shutil.copy2(agent, agents_dir / agent.name)

    print(f"Installed Claude Code skill: {skill_destination}")
    print(f"Installed Claude Code commands: {commands_dir}")
    print(f"Installed Claude Code agents: {agents_dir}")


def codex_skill_entrypoint(name: str) -> str:
    if name == "ai-review":
        return """---
name: ai-review
description: Diff review for AI-assisted code. Use to review new changes against a branch, PR base, staged/unstaged files, or explicit diff scope.
---

# ai-review

Review only new changes against a base branch, PR base, or explicitly requested diff scope.

Workflow:

1. Read `reference/methodology.md`, `reference/risk-weights.md`, and `reference/report-template.md` from this skill.
2. Read the target repository's `.ai-review/local.json` if present.
3. Determine the diff scope from the prompt: named branch, PR base, upstream/base branch, staged/unstaged files, or untracked files.
4. Detect languages in changed files and read matching modules under `reference/lang/`.
5. Run `scripts/review_changed.sh <base-branch>` when a base branch is known; otherwise run it without an argument.
6. Review only changed/new behavior, opening surrounding code only for contracts, callers, and invariants.
7. Apply all six methodology layers and report findings first.
"""
    return """---
name: ai-review-universal
description: Universal review for AI-assisted code. Use to review the whole repository or prompt-scoped existing code regardless of whether it changed recently.
---

# ai-review-universal

Review the whole repository, or the repo areas named in the prompt, regardless of whether the code is new.

Workflow:

1. Read `reference/methodology.md`, `reference/risk-weights.md`, and `reference/report-template.md` from this skill.
2. Read the target repository's `.ai-review/local.json` if present.
3. Determine scope from the prompt: whole repo, specific paths, modules, features, languages, or risk domains.
4. Detect languages in scope and read matching modules under `reference/lang/`.
5. Run `scripts/review.sh` from this skill.
6. Apply all six methodology layers to selected existing code and report findings first.
"""


def install_codex_skill(name: str, codex_base: Path) -> None:
    destination = codex_base / "skills" / name
    install_skill(destination)
    (destination / "SKILL.md").write_text(codex_skill_entrypoint(name), encoding="utf-8")
    print(f"Installed Codex skill: {destination}")


def remove_legacy_codex_skill(codex_base: Path) -> None:
    legacy = codex_base / "skills" / SKILL_NAME
    skill_file = legacy / "SKILL.md"
    if not skill_file.exists():
        return
    try:
        content = skill_file.read_text(encoding="utf-8")
    except Exception:
        return
    if "name: ai-reviewer" in content and "AI Reviewer" in content:
        shutil.rmtree(legacy)
        print(f"Removed legacy Codex skill: {legacy}")


def install_codex() -> None:
    codex_base = Path.home() / ".codex"
    for name in CODEX_SKILL_NAMES:
        install_codex_skill(name, codex_base)
    remove_legacy_codex_skill(codex_base)


def merge_block(existing: str, incoming: str, start: str, end: str) -> str:
    if start in incoming and end in incoming:
        block = incoming[incoming.index(start) : incoming.index(end) + len(end)]
    else:
        block = f"{start}\n{incoming.rstrip()}\n{end}"

    if start in existing and end in existing and existing.index(start) < existing.index(end):
        s = existing.index(start)
        e = existing.index(end) + len(end)
        merged = existing[:s].rstrip()
        suffix = existing[e:].lstrip()
        if merged:
            merged += "\n\n"
        merged += block
        if suffix:
            merged += "\n\n" + suffix
        return merged.rstrip() + "\n"

    base = existing.rstrip()
    if base:
        base += "\n\n"
    return f"{base}{block}\n"


def install_cursor() -> None:
    cursor_base = Path.home() / ".cursor"
    target = cursor_base / "rules" / "ai-reviewer.mdc"
    incoming = CURSOR_ADAPTER.read_text(encoding="utf-8").rstrip()
    wrapped = f"{CURSOR_START}\n{incoming}\n{CURSOR_END}\n"

    if target.exists():
        existing = target.read_text(encoding="utf-8")
        merged = merge_block(existing, wrapped, CURSOR_START, CURSOR_END)
    else:
        merged = wrapped

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(merged, encoding="utf-8")
    print(f"Installed Cursor rules: {target}")


INSTALLERS = {
    "claude": install_claude,
    "codex": install_codex,
    "cursor": install_cursor,
}


def detected_options() -> list[InstallOption]:
    claude_detected = command_exists("claude") or (Path.home() / ".claude").exists()
    codex_detected = command_exists("codex") or (Path.home() / ".codex").exists()
    cursor_detected = command_exists("cursor") or (Path.home() / ".cursor").exists()
    return [
        InstallOption("claude", "Claude Code skill", "~/.claude/skills/ai-reviewer", claude_detected),
        InstallOption("codex", "Codex skills", "~/.codex/skills/ai-review and ai-review-universal", codex_detected),
        InstallOption("cursor", "Cursor rules", "~/.cursor/rules/ai-reviewer.mdc", cursor_detected),
    ]


def read_key() -> str:
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            ch += sys.stdin.read(2)
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def clear_screen() -> None:
    print("\x1b[2J\x1b[H", end="")


def select_options(options: list[InstallOption]) -> list[str]:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SystemExit("Interactive terminal is unavailable. Use --install <claude,codex,cursor,all>.")

    selected = {index for index, option in enumerate(options) if option.detected}
    cursor = 0

    while True:
        clear_screen()
        print("AI Reviewer installer\n")
        print("Use ↑/↓ to move, Space to toggle, Enter to install, a to toggle all, q to cancel.\n")
        for index, option in enumerate(options):
            pointer = "›" if index == cursor else " "
            checked = "●" if index in selected else "○"
            status = "detected" if option.detected else "not detected"
            print(f"{pointer} {checked} {option.label} ({status})")
            print(f"    {option.detail}")

        key = read_key()
        if key in {"\x1b[A", "k"}:
            cursor = (cursor - 1) % len(options)
        elif key in {"\x1b[B", "j"}:
            cursor = (cursor + 1) % len(options)
        elif key == " ":
            if cursor in selected:
                selected.remove(cursor)
            else:
                selected.add(cursor)
        elif key in {"a", "A"}:
            if len(selected) == len(options):
                selected.clear()
            else:
                selected = set(range(len(options)))
        elif key in {"\r", "\n"}:
            clear_screen()
            return [options[index].key for index in range(len(options)) if index in selected]
        elif key in {"q", "Q", "\x03"}:
            clear_screen()
            return []


def parse_non_interactive(value: str, options: list[InstallOption]) -> list[str]:
    if value == "all":
        return [option.key for option in options]
    selected = [item.strip() for item in value.split(",") if item.strip()]
    invalid = [item for item in selected if item not in INSTALLERS]
    if invalid:
        raise SystemExit(f"Invalid install target(s): {', '.join(invalid)}")
    return list(dict.fromkeys(selected))


def run_install(selected: list[str]) -> None:
    if not selected:
        print("No install targets selected.")
        return
    for key in selected:
        try:
            INSTALLERS[key]()
        except PermissionError as exc:
            raise SystemExit(f"Permission denied while installing {key}: {exc}") from exc
    print("Install complete. Restart installed AI editors to reload skills.")


def main() -> None:
    args = parse_args()
    options = detected_options()

    if args.yes:
        selected = [option.key for option in options if option.detected]
    elif args.install:
        selected = parse_non_interactive(args.install, options)
    else:
        selected = select_options(options)

    run_install(selected)


if __name__ == "__main__":
    main()
