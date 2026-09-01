#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import csv
import json
import hashlib
import os
import re
import shutil
import subprocess
import sys
import termios
import tty
from dataclasses import dataclass
from pathlib import Path


SKILL_NAME = "dissect"
CODEX_SKILL_NAMES = ("dissect-diff", "dissect-full")
SOURCE_ROOT = Path(__file__).resolve().parents[1]
ADAPTERS_ROOT = SOURCE_ROOT / "adapters"
CURSOR_ADAPTER = ADAPTERS_ROOT / "cursor-rules.md"
CURSOR_START = "<!-- DISSECT-START -->"
CURSOR_END = "<!-- DISSECT-END -->"
MIN_NODE = (22, 18)
OXLINT_VERSION = "1.78.0"
AST_GREP_VERSION = "0.45.2"
LIZARD_VERSION = "1.24.0"
LIZARD_WHEEL_SHA256 = "a688bc607a891ff4a7836826f25742dc9c1bf648da3075dbd495e199e8848602"
SKILL_ITEMS = [
    "SKILL.md",
    "README.md",
    "LICENSE",
    "commands",
    "agents",
    "adapters",
    "reference",
    "scripts",
    "config",
    "tests",
]


@dataclass(frozen=True)
class InstallOption:
    key: str
    label: str
    detail: str
    detected: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install dissect as a machine-level skill.")
    parser.add_argument(
        "--install",
        default="",
        help="Non-interactive comma-separated install keys: claude,codex,cursor,all",
    )
    parser.add_argument("--yes", action="store_true", help="Install all detected skills.")
    return parser.parse_args()


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def node_version(node: str) -> tuple[int, int, int] | None:
    try:
        result = subprocess.run([node, "--version"], capture_output=True, text=True, check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = result.stdout or result.stderr or ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    match = re.search(r"v?(\d+)\.(\d+)(?:\.(\d+))?", value.strip())
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def provision_anti_slop(skill_root: Path) -> bool:
    """Install and verify analyser dependencies in this skill copy."""
    vendor = skill_root / "scripts" / "vendor" / "anti-slop"
    if not vendor.is_dir():
        return False
    node = shutil.which("node")
    npm = shutil.which("npm")
    if node is None:
        raise RuntimeError("Node.js is unavailable; anti-slop runtime provisioning failed")
    version = node_version(node)
    if version is None or version[:2] < MIN_NODE:
        raise RuntimeError("Node.js 22.18 or newer is required for anti-slop runtime provisioning")
    if npm is None:
        raise RuntimeError("npm is unavailable; anti-slop runtime provisioning failed")
    try:
        result = subprocess.run(
            [npm, "ci"],
            cwd=vendor,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise RuntimeError(f"could not provision anti-slop: {error}") from error
    if result.returncode:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        suffix = f" {detail[-1]}" if detail else ""
        raise RuntimeError(f"npm ci for anti-slop failed.{suffix}")

    binaries = {
        "Oxlint": (vendor / "node_modules" / ".bin" / "oxlint", OXLINT_VERSION),
        "ast-grep": (vendor / "node_modules" / ".bin" / "ast-grep", AST_GREP_VERSION),
    }
    for label, (binary, expected) in binaries.items():
        if not binary.is_file():
            raise RuntimeError(f"{label} binary was not provisioned at {binary}")
        try:
            check = subprocess.run([str(binary), "--version"], capture_output=True, text=True, check=False)
        except OSError as error:
            raise RuntimeError(f"could not execute provisioned {label} binary {binary}: {error}") from error
        reported = f"{check.stdout}\n{check.stderr}"
        if check.returncode != 0 or expected not in reported:
            raise RuntimeError(f"provisioned {label} binary reported an unexpected version: {reported.strip()}")
    print(f"Provisioned anti-slop runtime: {vendor}")
    print(f"  Oxlint: {binaries['Oxlint'][0]}")
    print(f"  ast-grep: {binaries['ast-grep'][0]}")
    return True


def provision_complexity(skill_root: Path) -> bool:
    """Verify the skill-local Lizard lock and bounded fallback implementation."""
    vendor = skill_root / "scripts" / "vendor" / "lizard"
    requirements = vendor / "requirements.txt"
    provenance = vendor / "PROVENANCE.json"
    backend = skill_root / "scripts" / "dissect_checks" / "complexity" / "lizard_backend.py"
    if not vendor.is_dir() or not requirements.is_file() or not provenance.is_file() or not backend.is_file():
        raise RuntimeError("Lizard fallback files are missing")
    try:
        metadata = json.loads(provenance.read_text(encoding="utf-8"))
        locked = requirements.read_text(encoding="utf-8")
    except (OSError, ValueError) as error:
        raise RuntimeError(f"could not read Lizard provenance: {error}") from error
    if metadata.get("version") != LIZARD_VERSION or metadata.get("sha256") != LIZARD_WHEEL_SHA256:
        raise RuntimeError("Lizard provenance does not match the exact pinned release")
    if LIZARD_VERSION not in locked or LIZARD_WHEEL_SHA256 not in locked:
        raise RuntimeError("Lizard requirement is not exact-pinned with its distribution hash")
    if f'LIZARD_VERSION = "{LIZARD_VERSION}"' not in backend.read_text(encoding="utf-8"):
        raise RuntimeError("complexity backend does not declare the pinned Lizard version")
    for distribution, expected_version in (
        ("lizard-1.24.0.dist-info", "1.24.0"),
        ("pathspec-1.1.1.dist-info", "1.1.1"),
        ("pygments-2.21.0.dist-info", "2.21.0"),
    ):
        metadata_path = vendor / "site-packages" / distribution / "METADATA"
        record_path = vendor / "site-packages" / distribution / "RECORD"
        if not metadata_path.is_file() or not record_path.is_file():
            raise RuntimeError(f"vendored distribution metadata is missing: {distribution}")
        metadata = metadata_path.read_text(encoding="utf-8")
        if f"\nVersion: {expected_version}\n" not in f"\n{metadata}\n":
            raise RuntimeError(f"vendored distribution version is unexpected: {distribution}")
        for row in csv.reader(record_path.read_text(encoding="utf-8").splitlines()):
            if len(row) < 3 or not row[1].startswith("sha256="):
                continue
            file_path = vendor / "site-packages" / row[0]
            if not file_path.is_file():
                raise RuntimeError(f"vendored distribution file is missing: {row[0]}")
            digest = base64.urlsafe_b64encode(hashlib.sha256(file_path.read_bytes()).digest()).decode().rstrip("=")
            if digest != row[1].split("=", 1)[1] or str(file_path.stat().st_size) != row[2]:
                raise RuntimeError(f"vendored distribution file hash mismatch: {row[0]}")
    print(f"Verified skill-local complexity runtime: Lizard {LIZARD_VERSION} ({LIZARD_WHEEL_SHA256})")
    return True


def copy_item(src: Path, dst: Path) -> None:
    if src.is_dir():
        shutil.copytree(
            src,
            dst,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__", ".DS_Store", "*.pyc", "node_modules"),
        )
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def install_skill(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for item in SKILL_ITEMS:
        copy_item(SOURCE_ROOT / item, destination / item)


def symlink_force(src: Path, dst: Path) -> None:
    if dst.is_symlink() or dst.exists():
        if dst.is_symlink() or dst.is_file():
            dst.unlink()
        else:
            shutil.rmtree(dst)
    os.symlink(src, dst)


def install_claude() -> None:
    claude_base = Path.home() / ".claude"
    skill_destination = claude_base / "skills" / SKILL_NAME
    skill_destination.parent.mkdir(parents=True, exist_ok=True)
    symlink_force(SOURCE_ROOT, skill_destination)
    provision_anti_slop(SOURCE_ROOT)
    provision_complexity(SOURCE_ROOT)

    commands_dir = claude_base / "commands"
    agents_dir = claude_base / "agents"
    commands_dir.mkdir(parents=True, exist_ok=True)
    agents_dir.mkdir(parents=True, exist_ok=True)
    for command in (SOURCE_ROOT / "commands").glob("*.md"):
        symlink_force(command, commands_dir / command.name)
    for agent in (SOURCE_ROOT / "agents").glob("*.md"):
        symlink_force(agent, agents_dir / agent.name)

    print(f"Installed Claude Code skill: {skill_destination} -> {SOURCE_ROOT}")
    print(f"Installed Claude Code commands: {commands_dir}")
    print(f"Installed Claude Code agents: {agents_dir}")


def codex_skill_entrypoint(name: str) -> str:
    if name == "dissect-diff":
        return """---
name: dissect-diff
description: Diff review for AI-assisted code. Use to review new changes against a branch, PR base, staged/unstaged files, or explicit diff scope.
---

# dissect-diff

Resolve all `reference/` and `scripts/` paths below from the directory
containing this installed `SKILL.md`, not from the repository under review.

Use `reference/review-workflow.md` as the canonical workflow. Establish intent,
build behavioural units, identify contracts, trace credible blast radius,
generate candidates, falsify every candidate, verify survivors, and report only
verified findings. Run `scripts/review_changed.sh <base-branch>` to create
context outside the checkout. Load only relevant language/framework packs and
use the concise diff report. Deterministic matches are candidates, not
findings; exclude unrelated pre-existing defects.
"""
    return """---
name: dissect-full
description: Full review for AI-assisted code. Use to review the whole repository or prompt-scoped existing code regardless of whether it changed recently.
---

# dissect-full

Resolve all `reference/` and `scripts/` paths below from the directory
containing this installed `SKILL.md`, not from the repository under review.

Use `reference/review-workflow.md` as the canonical workflow. Establish intent
and scope, build behavioural/system units, identify contracts, trace credible
blast radius, generate and falsify candidates, verify survivors, and report
only verified findings. Run `scripts/review.sh` to create context outside the
checkout and activate the architecture detector. Use the full report additions
only when useful; distinguish findings, open questions, and Not verified areas.
"""


def install_codex_skill(name: str, agents_base: Path) -> None:
    destination = agents_base / "skills" / name
    install_skill(destination)
    (destination / "SKILL.md").write_text(codex_skill_entrypoint(name), encoding="utf-8")
    provision_anti_slop(destination)
    provision_complexity(destination)
    print(f"Installed Codex skill: {destination}")


def remove_legacy_codex_skill() -> None:
    for base in (Path.home() / ".codex", Path.home() / ".agents"):
        for name in ("ai-reviewer", "ai-review", "ai-review-universal"):
            legacy = base / "skills" / name
            skill_file = legacy / "SKILL.md"
            if not skill_file.exists():
                continue
            try:
                content = skill_file.read_text(encoding="utf-8")
            except Exception:
                continue
            if "name: ai-reviewer" in content or "name: ai-review" in content:
                shutil.rmtree(legacy)
                print(f"Removed legacy Codex skill: {legacy}")


def install_codex() -> None:
    agents_base = Path.home() / ".agents"
    for name in CODEX_SKILL_NAMES:
        install_codex_skill(name, agents_base)
    remove_legacy_codex_skill()


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
    target = cursor_base / "rules" / "dissect.mdc"
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
    codex_detected = command_exists("codex") or (Path.home() / ".codex").exists() or (Path.home() / ".agents").exists()
    cursor_detected = command_exists("cursor") or (Path.home() / ".cursor").exists()
    return [
        InstallOption("claude", "Claude Code skill", "~/.claude/skills/dissect", claude_detected),
        InstallOption("codex", "Codex skills", "~/.agents/skills/dissect-diff and dissect-full", codex_detected),
        InstallOption("cursor", "Cursor rules", "~/.cursor/rules/dissect.mdc", cursor_detected),
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
        print("Dissect installer\n")
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
        except RuntimeError as exc:
            raise SystemExit(f"Could not install {key}: {exc}") from exc
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
