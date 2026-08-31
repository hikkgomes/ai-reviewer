#!/usr/bin/env python3
"""Detect review languages from the canonical repository or diff scope."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from diff_file_list import DiffEntry, deserialize_entries  # noqa: E402
from file_paths import is_ignored_path, iter_files  # noqa: E402
from language_registry import detect_languages  # noqa: E402


def _relative(root: Path, value: str | Path) -> str:
    path = Path(value)
    if path.is_absolute():
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            return ""
    return path.as_posix()


def full_scope(root: Path) -> tuple[str, ...]:
    try:
        paths = [_relative(root, path) for path in iter_files(root)]
    except OSError as error:
        raise RuntimeError(f"could not traverse review root: {error}") from error
    return tuple(sorted(path for path in paths if path and not is_ignored_path(root, path)))


def diff_scope(root: Path, entries: Iterable[DiffEntry]) -> tuple[str, ...]:
    values: set[str] = set()
    for entry in entries:
        for value in (entry.old_path, entry.new_path):
            path = _relative(root, value)
            if path and not is_ignored_path(root, path):
                values.add(path)
    return tuple(sorted(values))


def _load_entries(path: str) -> list[DiffEntry]:
    raw = sys.stdin.buffer.read() if path == "-" else Path(path).read_bytes()
    for token in raw.split(b"\0"):
        if not token:
            continue
        try:
            value = json.loads(token.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as error:
            raise RuntimeError(f"invalid diff entry transport: {error}") from error
        required = {"status", "old_path", "new_path", "exists_in_worktree", "source_kind"}
        if not isinstance(value, dict) or not required <= value.keys():
            raise RuntimeError("invalid diff entry transport: expected DiffEntry object")
        if (
            not isinstance(value["status"], str)
            or not isinstance(value["old_path"], str)
            or not isinstance(value["new_path"], str)
            or not isinstance(value["exists_in_worktree"], bool)
            or not isinstance(value["source_kind"], str)
            or value["source_kind"] not in {"commit", "index", "working-tree", "untracked"}
        ):
            raise RuntimeError("invalid diff entry transport: invalid DiffEntry fields")
        for field in ("old_path", "new_path", "reviewed_path", "blob_path"):
            if field not in value:
                continue
            if not isinstance(value[field], str):
                raise RuntimeError(f"invalid diff entry transport: unsafe {field}")
            candidate = Path(value[field])
            if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts:
                raise RuntimeError(f"invalid diff entry transport: unsafe {field}")
        if "commit_revision" in value and not isinstance(value["commit_revision"], str):
            raise RuntimeError("invalid diff entry transport: invalid commit_revision")
        if "index_stage" in value and value["index_stage"] is not None and (
            isinstance(value["index_stage"], bool) or not isinstance(value["index_stage"], int)
        ):
            raise RuntimeError("invalid diff entry transport: invalid index_stage")
    try:
        return deserialize_entries(raw)
    except (TypeError, ValueError, UnicodeDecodeError) as error:
        raise RuntimeError(f"invalid diff entry transport: {error}") from error


def detect(root: Path, entries_from: str | None = None) -> tuple[str, ...]:
    root = root.resolve()
    if not root.is_dir():
        raise RuntimeError(f"review root is not a directory: {root}")
    paths = diff_scope(root, _load_entries(entries_from)) if entries_from is not None else full_scope(root)
    return detect_languages(paths)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--entries-from", metavar="FILE|-")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        languages = detect(args.root, args.entries_from)
        if args.format == "json":
            print(json.dumps(list(languages), separators=(",", ":")))
        else:
            print(", ".join(languages) if languages else "none")
        return 0
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
