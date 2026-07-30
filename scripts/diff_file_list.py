#!/usr/bin/env python3
"""Build and consume Dissect's canonical NUL-delimited diff file list."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys


def _git_paths(root: Path, arguments: list[str]) -> list[bytes]:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(message or f"git {' '.join(arguments)} failed")
    return [value for value in result.stdout.split(b"\0") if value]


def changed_paths(root: Path, committed_range: str = "") -> list[bytes]:
    paths = []
    if committed_range:
        paths.extend(_git_paths(
            root,
            ["diff", "--name-only", "-z", committed_range],
        ))
    paths.extend(_git_paths(root, ["diff", "--name-only", "-z", "--cached"]))
    paths.extend(_git_paths(root, ["diff", "--name-only", "-z"]))
    paths.extend(_git_paths(
        root,
        ["ls-files", "-z", "--others", "--exclude-standard"],
    ))
    return sorted(set(paths))


def read_file_list(path: Path) -> list[str]:
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    return [
        value.decode("utf-8", errors="surrogateescape")
        for value in raw.split(b"\0")
        if value
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--range", default="", dest="committed_range")
    parser.add_argument("--display", type=Path)
    args = parser.parse_args()
    if args.display:
        for path in read_file_list(args.display):
            print(json.dumps(path, ensure_ascii=True))
        return 0
    try:
        paths = changed_paths(Path.cwd(), args.committed_range)
    except RuntimeError as error:
        print(f"Could not build diff file list: {error}", file=sys.stderr)
        return 1
    if paths:
        sys.stdout.buffer.write(b"\0".join(paths) + b"\0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
