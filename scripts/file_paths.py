"""Bounded repository file traversal helpers.

Path.rglob() filters paths after entering their directories.  These helpers
prune conventional dependency, build, cache, and VCS directories before the
walk descends into them.
"""
from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from pathlib import Path


DEFAULT_IGNORED_DIRS = frozenset({
    ".git", ".hg", ".svn", ".idea", ".vscode", ".next", ".turbo",
    ".cache", ".venv", ".tox", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", "node_modules", "vendor", "dist", "build", "coverage",
    "target", "out", "tmp", "__pycache__",
})


def iter_files(
    root: Path,
    *,
    ignored_dirs: frozenset[str] = DEFAULT_IGNORED_DIRS,
    should_skip_dir: Callable[[Path], bool] | None = None,
) -> Iterator[Path]:
    """Yield regular files while pruning ignored directories top-down."""
    # Preserve the caller's path spelling: on macOS ``/var`` resolves to
    # ``/private/var``, which breaks later ``Path.relative_to(root)`` calls.
    root = root.absolute()
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        parent = Path(directory)
        dirnames[:] = sorted(
            name for name in dirnames
            if name not in ignored_dirs
            and not (should_skip_dir and should_skip_dir(parent / name))
        )
        for name in sorted(filenames):
            path = parent / name
            if path.is_file():
                yield path
