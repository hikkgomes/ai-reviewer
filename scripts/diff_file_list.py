#!/usr/bin/env python3
"""Build and consume a status-aware, NUL-delimited diff scope."""
import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import subprocess
import sys


@dataclass(frozen=True)
class DiffEntry:
    status: str
    old_path: str
    new_path: str
    exists_in_worktree: bool
    source_kind: str
    commit_revision: str = ""
    index_stage: int | None = None


def _git(root: Path, arguments: list[str]) -> bytes:
    result = subprocess.run(["git", *arguments], cwd=root, capture_output=True, check=False)
    if result.returncode:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(message or f"git {' '.join(arguments)} failed")
    return result.stdout


def _name_status(
    root: Path,
    arguments: list[str],
    source_kind: str,
    commit_revision: str = "",
    index_stage: int | None = None,
) -> list[DiffEntry]:
    values = [item for item in _git(root, arguments).split(b"\0") if item]
    entries: list[DiffEntry] = []
    index = 0
    while index < len(values):
        status = values[index].decode("ascii", errors="replace")
        index += 1
        count = 2 if status.startswith(("R", "C")) else 1
        if index + count > len(values):
            raise RuntimeError(f"truncated name-status record for {status!r}")
        paths = [value.decode("utf-8", errors="surrogateescape") for value in values[index:index + count]]
        index += count
        old_path, new_path = (paths[0], paths[-1])
        entries.append(DiffEntry(
            status=status,
            old_path=old_path,
            new_path=new_path,
            exists_in_worktree=not status.startswith("D") and (root / new_path).is_file(),
            source_kind=source_kind,
            commit_revision=commit_revision,
            index_stage=index_stage,
        ))
    return entries


def changed_entries(root: Path, committed_range: str = "") -> list[DiffEntry]:
    entries: list[DiffEntry] = []
    if committed_range:
        base = committed_range.split("...", 1)[0]
        entries.extend(_name_status(root, ["diff", "--name-status", "-z", "-M", "-C", "--find-copies-harder", committed_range], "commit", base))
    entries.extend(_name_status(root, ["diff", "--cached", "--name-status", "-z", "-M", "-C", "--find-copies-harder"], "commit", "HEAD"))
    entries.extend(_name_status(root, ["diff", "--name-status", "-z", "-M", "-C", "--find-copies-harder"], "index", index_stage=0))
    for raw in [value for value in _git(root, ["ls-files", "-z", "--others", "--exclude-standard"]).split(b"\0") if value]:
        path = raw.decode("utf-8", errors="surrogateescape")
        entries.append(DiffEntry("A", path, path, (root / path).is_file(), "untracked"))
    # Identical records from staged + worktree are redundant, but differently sourced
    # records remain because their historical base can be different.
    return sorted(set(entries), key=lambda item: (item.new_path, item.old_path, item.status, item.source_kind, item.commit_revision, item.index_stage or -1))


def changed_paths(root: Path, committed_range: str = "") -> list[bytes]:
    """Compatibility view used by integrations that only need path names."""
    paths = {path for entry in changed_entries(root, committed_range) for path in (entry.old_path, entry.new_path)}
    return sorted(path.encode("utf-8", errors="surrogateescape") for path in paths)


def serialize_entries(entries: list[DiffEntry]) -> bytes:
    return b"\0".join(
        json.dumps(asdict(entry), ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
        for entry in entries
    ) + (b"\0" if entries else b"")


def read_diff_entries(path: Path) -> list[DiffEntry]:
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    entries: list[DiffEntry] = []
    for value in raw.split(b"\0"):
        if not value:
            continue
        try:
            data = json.loads(value.decode("utf-8"))
            if "source_kind" not in data:
                # v1 records were always commit-backed and used base_revision.
                data = {
                    "status": data["status"], "old_path": data["old_path"],
                    "new_path": data["new_path"], "exists_in_worktree": data["exists_in_worktree"],
                    "source_kind": "commit", "commit_revision": data.get("base_revision", ""),
                }
            entries.append(DiffEntry(**data))
        except (TypeError, ValueError):
            # Legacy files remain accepted; they describe a current path only.
            name = value.decode("utf-8", errors="surrogateescape")
            entries.append(DiffEntry("M", name, name, True, "working-tree"))
    return entries


def read_file_list(path: Path) -> list[str]:
    return sorted({path for entry in read_diff_entries(path) for path in (entry.old_path, entry.new_path)})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--range", default="", dest="committed_range")
    parser.add_argument("--display", type=Path)
    args = parser.parse_args()
    if args.display:
        for entry in read_diff_entries(args.display):
            print(json.dumps(asdict(entry), ensure_ascii=True, sort_keys=True))
        return 0
    try:
        sys.stdout.buffer.write(serialize_entries(changed_entries(Path.cwd(), args.committed_range)))
    except RuntimeError as error:
        print(f"Could not build diff file list: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
