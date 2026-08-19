"""Bounded repository file traversal helpers.

Path.rglob() filters paths after entering their directories.  These helpers
prune conventional dependency, build, cache, and VCS directories before the
walk descends into them.
"""
from __future__ import annotations

import fnmatch
import json
import os
from collections.abc import Callable, Iterator
from pathlib import Path


DEFAULT_IGNORED_DIRS = frozenset({
    ".git", ".hg", ".svn", ".idea", ".vscode", ".next", ".turbo",
    ".cache", ".venv", ".tox", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", "node_modules", "vendor", "dist", "build", "coverage",
    "target", "out", "tmp", "__pycache__",
})


def configured_ignore_patterns(root: Path) -> tuple[str, ...]:
    """Read repository path ignores without making malformed config fatal."""
    try:
        data = json.loads((root / ".ai-review" / "local.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ()
    paths = data.get("paths") if isinstance(data, dict) else None
    values = paths.get("ignore") if isinstance(paths, dict) else None
    if not isinstance(values, list):
        return ()
    return tuple(value.replace("\\", "/") for value in values if isinstance(value, str) and value)


def matches_ignore_pattern(relative: str, pattern: str) -> bool:
    """Match repository-relative paths and directory prefixes consistently."""
    value = relative.replace("\\", "/")
    clean = pattern.replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    while clean.startswith("./"):
        clean = clean[2:]
    clean = clean.rstrip("/")
    if not clean:
        return False
    return (
        value == clean
        or value.startswith(clean + "/")
        or fnmatch.fnmatchcase(value, clean)
        or fnmatch.fnmatchcase(value + "/", clean + "/")
    )


def is_ignored_path(
    root: Path,
    path: str | Path,
    *,
    ignored_paths: tuple[str, ...] | None = None,
) -> bool:
    """Apply built-in and configured path exclusions to one path."""
    root = root.absolute()
    candidate = Path(path)
    resolved = candidate if candidate.is_absolute() else root / candidate
    try:
        relative = resolved.absolute().relative_to(root).as_posix()
    except ValueError:
        return True
    if any(part in DEFAULT_IGNORED_DIRS for part in Path(relative).parts):
        return True
    patterns = configured_ignore_patterns(root) if ignored_paths is None else ignored_paths
    return any(matches_ignore_pattern(relative, pattern) for pattern in patterns)


def iter_files(
    root: Path,
    *,
    ignored_dirs: frozenset[str] = DEFAULT_IGNORED_DIRS,
    should_skip_dir: Callable[[Path], bool] | None = None,
    ignored_paths: tuple[str, ...] | None = None,
) -> Iterator[Path]:
    """Yield regular files while pruning ignored directories top-down."""
    # Preserve the caller's path spelling: on macOS ``/var`` resolves to
    # ``/private/var``, which breaks later ``Path.relative_to(root)`` calls.
    root = root.absolute()
    configured = configured_ignore_patterns(root) if ignored_paths is None else ignored_paths
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        parent = Path(directory)
        dirnames[:] = sorted(
            name for name in dirnames
            if name not in ignored_dirs
            and not (should_skip_dir and should_skip_dir(parent / name))
            and not any(
                matches_ignore_pattern((parent / name).relative_to(root).as_posix(), pattern)
                for pattern in configured
            )
        )
        for name in sorted(filenames):
            path = parent / name
            if path.is_file() and not any(
                matches_ignore_pattern(path.relative_to(root).as_posix(), pattern)
                for pattern in configured
            ):
                yield path
