"""Change partitioning and exact source-state helpers for test evidence."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import subprocess
from typing import Any, Iterable, Mapping, Sequence

from diff_file_list import DiffEntry
from file_paths import is_generated_path, is_ignored_path
from .model import TestArtifact, TestChange, TestSubject, sha256_bytes


PARTITIONS = (
    "production patch",
    "test patch",
    "test-support patch",
    "shared configuration patch",
    "documentation or generated patch",
)


@dataclass(frozen=True)
class ChangePartition:
    production: tuple[str, ...]
    tests: tuple[str, ...]
    test_support: tuple[str, ...]
    shared_configuration: tuple[str, ...]
    documentation_or_generated: tuple[str, ...]
    uncertain: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "production_patch": list(self.production),
            "test_patch": list(self.tests),
            "test_support_patch": list(self.test_support),
            "shared_configuration_patch": list(self.shared_configuration),
            "documentation_or_generated_patch": list(self.documentation_or_generated),
            "uncertain": list(self.uncertain),
        }

    @property
    def all_paths(self) -> tuple[str, ...]:
        return tuple(sorted({
            *self.production, *self.tests, *self.test_support,
            *self.shared_configuration, *self.documentation_or_generated,
            *self.uncertain,
        }))


@dataclass(frozen=True)
class SourceState:
    logical_path: str
    source_kind: str
    revision: str
    data: bytes
    content_sha256: str
    exists: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "logical_path": self.logical_path,
            "source_kind": self.source_kind,
            "revision": self.revision,
            "content_sha256": self.content_sha256,
            "exists": self.exists,
        }


def _normalise(path: str | Path) -> str:
    return Path(path).as_posix()


def _artifact_role(path: str, inventory: Any) -> str:
    for artifact in getattr(inventory, "artifacts", ()):
        if artifact.logical_path == path:
            return artifact.role
    lower = path.lower()
    if any(token in lower for token in ("/test/", "/tests/", ".test.", ".spec.", "_test.")):
        return "test"
    if any(token in lower for token in ("fixture", "snapshot", "golden")):
        return "fixture"
    if Path(path).suffix.lower() in {".md", ".rst", ".txt"}:
        return "documentation"
    if Path(path).stem.lower().startswith(("config", "settings")) or any(token in lower.split("/") for token in ("config", "configs", "configuration")):
        return "shared build or manifest file"
    if any(token in lower for token in ("package.json", "pyproject.toml", "go.mod", "cargo.toml", "pom.xml", ".github/")):
        return "shared build or manifest file"
    return "production source"


def partition_diff(
    root: Path,
    paths: Iterable[str | Path],
    *,
    inventory: Any | None = None,
    entries: Sequence[DiffEntry] = (),
    config: Mapping[str, Any] | None = None,
) -> ChangePartition:
    root = root.resolve()
    groups: dict[str, list[str]] = {key: [] for key in PARTITIONS}
    uncertain: list[str] = []
    for raw in sorted({_normalise(path) for path in paths}):
        if not raw or Path(raw).is_absolute() or ".." in Path(raw).parts:
            continue
        if is_ignored_path(root, raw):
            continue
        role = _artifact_role(raw, inventory)
        physical = root / raw
        if is_generated_path(root, physical, dict(config or {})):
            groups["documentation or generated patch"].append(raw)
        elif role in {"test", "test configuration", "CI test command", "snapshot or golden file"}:
            groups["test patch"].append(raw)
        elif role in {"test helper", "fixture"}:
            groups["test-support patch"].append(raw)
        elif role == "shared build or manifest file" or role == "production source" and (
            Path(raw).name.lower() in {"package.json", "pyproject.toml", "go.mod", "cargo.toml", "pom.xml", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}
            or raw.startswith(".github/")
            or raw.endswith((".toml", ".ini", ".cfg")) and "test" in raw.lower()
        ):
            groups["shared configuration patch"].append(raw)
        elif role == "documentation":
            groups["documentation or generated patch"].append(raw)
        elif role == "unknown":
            uncertain.append(raw)
        else:
            groups["production patch"].append(raw)
    return ChangePartition(
        tuple(sorted(set(groups["production patch"]))),
        tuple(sorted(set(groups["test patch"]))),
        tuple(sorted(set(groups["test-support patch"]))),
        tuple(sorted(set(groups["shared configuration patch"]))),
        tuple(sorted(set(groups["documentation or generated patch"]))),
        tuple(sorted(set(uncertain))),
    )


def _git_blob(root: Path, revision: str, path: str, *, max_bytes: int) -> bytes | None:
    if not revision:
        return None
    try:
        ref = f":{path}" if revision == ":" else f"{revision}:{path}"
        size_result = subprocess.run(
            ["git", "cat-file", "-s", ref],
            cwd=root, capture_output=True, text=True, check=False,
        )
        size = int(size_result.stdout.strip()) if size_result.returncode == 0 else -1
        if size < 0 or size > max_bytes:
            return None
        process = subprocess.Popen(
            ["git", "show", "--format=", ref],
            cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except OSError:
        return None
    try:
        data = process.stdout.read(max_bytes + 1) if process.stdout is not None else b""
        if len(data) > max_bytes:
            process.kill()
            process.wait(timeout=1)
            return None
        process.wait(timeout=1)
        return data if process.returncode == 0 and len(data) == size else None
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            pass
        return None
    finally:
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass


def read_source_state(root: Path, entry: DiffEntry, *, max_bytes: int = 5 * 1024 * 1024) -> SourceState | None:
    path = _normalise(entry.reviewed_path)
    data: bytes | None
    revision = entry.commit_revision
    if entry.source_kind == "working-tree" or entry.source_kind == "untracked":
        try:
            with (root / path).open("rb") as handle:
                data = handle.read(max_bytes + 1)
        except OSError:
            data = None
    elif entry.source_kind == "index":
        data = _git_blob(root, ":", entry.blob_path or path, max_bytes=max_bytes)
    else:
        data = _git_blob(root, revision or "HEAD", entry.blob_path or path, max_bytes=max_bytes)
    if data is None:
        return None
    if len(data) > max_bytes:
        return SourceState(path, entry.source_kind, revision, data[:max_bytes + 1], sha256_bytes(data[:max_bytes + 1]), False)
    return SourceState(path, entry.source_kind, revision, data, sha256_bytes(data), True)


def exact_source_states(
    root: Path,
    entries: Sequence[DiffEntry],
    *,
    max_bytes: int = 5 * 1024 * 1024,
) -> tuple[SourceState, ...]:
    states: list[SourceState] = []
    for entry in sorted(entries, key=lambda item: (item.reviewed_path, item.source_kind, item.commit_revision, item.blob_path)):
        state = read_source_state(root, entry, max_bytes=max_bytes)
        if state is not None:
            states.append(state)
    return tuple(states)


def patch_digest(states: Iterable[SourceState]) -> str:
    payload = "\n".join(
        f"{state.logical_path}\0{state.source_kind}\0{state.revision}\0{state.content_sha256}"
        for state in sorted(states, key=lambda item: (item.logical_path, item.source_kind, item.revision))
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def changed_line_ranges(diff_text: str) -> dict[str, tuple[tuple[int, int], ...]]:
    current: str | None = None
    ranges: dict[str, list[tuple[int, int]]] = {}
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
            ranges.setdefault(current, [])
            continue
        if line.startswith("@@"):
            match = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if match and current is not None:
                start = int(match.group(1))
                count = int(match.group(2) or "1")
                if count:
                    ranges[current].append((start, start + count - 1))
    return {path: tuple(values) for path, values in sorted(ranges.items())}


def map_test_changes(
    artifacts: Iterable[TestArtifact],
    subjects: Iterable[TestSubject],
    *,
    changed_paths: Iterable[str],
    base_contents: Mapping[str, str] | None = None,
    head_contents: Mapping[str, str] | None = None,
) -> tuple[TestChange, ...]:
    changed = set(changed_paths)
    subjects_by_name = tuple(subjects)
    output: list[TestChange] = []
    for artifact in sorted(artifacts, key=lambda item: item.logical_path):
        if artifact.logical_path not in changed:
            continue
        before = (base_contents or {}).get(artifact.logical_path, "")
        after = (head_contents or {}).get(artifact.logical_path, "")
        kinds: list[str] = []
        if not before and after:
            kinds.append("added")
        elif before and not after:
            kinds.append("deleted")
        else:
            kinds.append("modified")
        if artifact.role == "test configuration":
            kinds.append("discovery_configuration")
        if re.search(r"\b(?:skip|todo|xfail|ignore|disabled|continue-on-error|passWithNoTests)\b", after, re.I) and not re.search(r"\b(?:skip|todo|xfail|ignore|disabled|continue-on-error|passWithNoTests)\b", before, re.I):
            kinds.append("disabled_or_bypassed")
        affected = tuple(
            subject for subject in subjects_by_name
            if re.search(rf"(?<!\w){re.escape(subject.qualified_name.rsplit('.', 1)[-1])}(?!\w)", after or before)
        )
        oracle_match = re.search(
            r"(?im)^\s*(?:#|//|/\*+|\*)\s*oracle(?:[-_ ]source)?\s*:\s*([a-z_]+)\s+(.+?)\s*(?:\*/)?$",
            after,
        )
        oracle_source = (
            {"kind": oracle_match.group(1), "reference": oracle_match.group(2)}
            if oracle_match is not None else
            {"kind": "not_recorded", "reference": "No independent contract or oracle was attached to this test change."}
        )
        output.append(TestChange(
            artifact,
            tuple(dict.fromkeys(kinds)),
            affected,
            (
                {"kind": "changed_path", "path": artifact.logical_path},
                {"kind": "oracle_source", **oracle_source},
            ),
            oracle_source,
        ))
    return tuple(output)
