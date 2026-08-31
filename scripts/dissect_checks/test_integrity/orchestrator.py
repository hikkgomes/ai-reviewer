"""Coordinate static test checks and approval-bound dynamic evidence."""
from __future__ import annotations

from dataclasses import dataclass
import json
import subprocess
from pathlib import Path
import sys
from typing import Any, Iterable, Mapping, Sequence

from analysis_budget import AnalysisBudget, analysis_limits
from diff_file_list import DiffEntry
from file_paths import iter_files
from .change_analysis import ChangePartition, exact_source_states, map_test_changes, partition_diff
from .evidence_matrix import EvidenceMatrix, _repository_ci_test_command, build_matrix
from .inventory import InventoryResult, build_inventory
from .model import TestChange, public_state
from .mutation import MutationRun, generate_mutations, run_mutations
from .static_analysis import StaticAnalysisResult, analyse_static


MAX_SOURCE_MAP_BYTES = 5 * 1024 * 1024


def _enabled(config: Mapping[str, Any], name: str, default: bool = True) -> bool:
    options = config.get("review_options")
    if not isinstance(options, Mapping):
        return default
    value = options.get(name)
    return value if isinstance(value, bool) else default


def _command(root: Path, config: Mapping[str, Any]) -> str | None:
    commands = config.get("commands")
    if isinstance(commands, Mapping) and isinstance(commands.get("test"), str) and commands["test"].strip():
        return str(commands["test"]).strip()
    options = config.get("review_options")
    if isinstance(options, Mapping) and isinstance(options.get("test_command"), str) and options["test_command"].strip():
        return str(options["test_command"]).strip()
    workflow_command = _repository_ci_test_command(root)
    if workflow_command is not None:
        return workflow_command
    try:
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[2] / "detect_commands.py")],
            cwd=root, capture_output=True, text=True, check=False, timeout=5,
        )
        payload = json.loads(result.stdout) if result.returncode == 0 else {}
        detected = payload.get("commands", {}).get("test") if isinstance(payload, dict) else None
        if isinstance(detected, str) and detected.strip():
            return detected.strip()
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return None


def _build_command(config: Mapping[str, Any]) -> str | None:
    commands = config.get("commands")
    if not isinstance(commands, Mapping):
        return None
    for name in ("build", "typecheck"):
        value = commands.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


@dataclass
class TestIntegrityResult:
    status: str
    inventory: InventoryResult
    partition: ChangePartition
    static: StaticAnalysisResult
    changes: tuple[TestChange, ...]
    matrix: EvidenceMatrix | None
    mutations: MutationRun | None
    proof_tests: tuple[Mapping[str, Any], ...]
    reason_code: str | None = None

    def as_dict(self) -> dict[str, Any]:
        static = self.static.as_dict()
        matrix_object = self.matrix
        matrix = matrix_object.as_dict() if matrix_object is not None else {"status": "not_applicable", "reason_code": "disabled", "scenarios": []}
        if matrix_object is not None:
            matrix_object.close()
        mutations = self.mutations.as_dict() if self.mutations is not None else {
            "status": "not_applicable", "reason_code": "disabled", "results": [],
            "kill_sets": {}, "unique_kill_sets": {},
        }
        return {
            "status": self.status,
            "state": public_state(self.status, applicable=bool(self.inventory.artifacts or self.inventory.subjects)),
            "reason_code": self.reason_code,
            "inventory": self.inventory.as_dict(),
            "partition": self.partition.as_dict(),
            "changes": [item.as_dict() for item in self.changes],
            "static_analysis": static,
            "dynamic_matrix": matrix,
            "targeted_mutation": mutations,
            "proof_tests": [dict(item) for item in self.proof_tests],
            "artifacts": [item.as_dict() for item in self.inventory.artifacts],
            "subjects": [item.as_dict() for item in self.inventory.subjects],
            "relations": [dict(item) for item in self.inventory.relations],
            "static_candidates": list(self.static.candidates),
            "matrix": matrix.get("scenarios", []),
            "mutations": mutations.get("results", []),
        }


def _git_text(root: Path, revision: str, path: str, *, limit: int = MAX_SOURCE_MAP_BYTES) -> str | None:
    if not revision:
        return None
    try:
        process = subprocess.Popen(
            ["git", "show", "--format=", f"{revision}:{path}"],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError:
        return None
    try:
        data = process.stdout.read(limit + 1) if process.stdout is not None else b""
        if len(data) > limit:
            process.kill()
            process.wait(timeout=1)
            return None
        process.wait(timeout=1)
        if process.returncode != 0:
            return None
        return data.decode("utf-8", errors="replace")
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


def _working_text(root: Path, path: str, *, limit: int = MAX_SOURCE_MAP_BYTES) -> str | None:
    path_object = Path(path)
    if path_object.is_absolute() or ".." in path_object.parts:
        return None
    physical = (root / path_object).resolve()
    try:
        physical.relative_to(root.resolve())
        size = physical.stat().st_size
        if size > limit:
            return None
        with physical.open("rb") as handle:
            data = handle.read(size)
        if len(data) != size or physical.stat().st_size != size:
            return None
    except OSError:
        return None
    return data.decode("utf-8", errors="replace")


def _source_maps(
    root: Path,
    entries: Sequence[DiffEntry],
    paths: Iterable[str],
    *,
    base_revision: str = "",
    head_revision: str = "HEAD",
) -> tuple[dict[str, str], dict[str, str]]:
    states = exact_source_states(root, entries)
    by_path: dict[str, list[Any]] = {}
    for state in states:
        by_path.setdefault(state.logical_path, []).append(state)
    base: dict[str, str] = {}
    head: dict[str, str] = {}
    requested = sorted(set(paths))
    for path in requested:
        candidates = by_path.get(path, [])
        state_by_kind = {state.source_kind: state for state in candidates}
        if base_revision:
            # Commit-range reviews compare the requested base with the exact
            # reviewed head. Do not use the current worktree as an implicit
            # third source layer.
            before = _git_text(root, base_revision, path)
            after = _git_text(root, head_revision, path)
            if "working-tree" in state_by_kind or "untracked" in state_by_kind:
                after_state = state_by_kind.get("working-tree") or state_by_kind.get("untracked")
                after = after_state.data.decode("utf-8", errors="replace") if after_state is not None else after
            if before is not None:
                base[path] = before
            if after is not None:
                head[path] = after
            continue

        # Local reviews use index as the base for an unstaged change and HEAD
        # as the base for a staged change. Untracked files have no base value.
        after_state = state_by_kind.get("working-tree") or state_by_kind.get("untracked") or state_by_kind.get("index")
        after_entry = next(
            (
                entry for entry in entries
                if entry.reviewed_path == path
                and entry.source_kind == (after_state.source_kind if after_state is not None else "")
            ),
            None,
        )
        if after_entry is not None and after_entry.status.startswith("D"):
            after_state = None
        before_state = state_by_kind.get("index")
        if before_state is None:
            before_state = next(
                (state for state in candidates if state.source_kind == "commit"),
                None,
            )
        if after_state is not None:
            head[path] = after_state.data.decode("utf-8", errors="replace")
        if before_state is not None and before_state.source_kind != "untracked":
            base[path] = before_state.data.decode("utf-8", errors="replace")
        if path not in head and not candidates:
            value = _working_text(root, path)
            if value is not None:
                head[path] = value
        if not entries and path not in base and path in head:
            base[path] = head[path]
    return base, head


def source_maps(
    root: Path,
    entries: Sequence[DiffEntry],
    paths: Iterable[str],
    *,
    base_revision: str = "",
    head_revision: str = "HEAD",
) -> tuple[dict[str, str], dict[str, str]]:
    """Return exact, bounded text snapshots for the base and head layers."""
    return _source_maps(
        root,
        entries,
        paths,
        base_revision=base_revision,
        head_revision=head_revision,
    )


def _prepare_inventory(
    root: Path,
    config: Mapping[str, Any],
    inventory_paths: Sequence[str],
    selected: Sequence[str] | None,
    entries: Sequence[DiffEntry],
    changed_paths: Sequence[str],
    mode: str,
    base_contents: Mapping[str, str] | None,
    head_contents: Mapping[str, str] | None,
    limits: Mapping[str, int | float],
    source_kind_by_path: Mapping[str, str] | None = None,
) -> tuple[InventoryResult, ChangePartition, StaticAnalysisResult, tuple[TestChange, ...]]:
    budget = AnalysisBudget(
        float(limits["test_integrity_timeout_seconds"]),
        max(1, min(20000, len(inventory_paths) or 20000)),
        256 * 1024 * 1024,
        500,
    )
    inventory_bytes = {
        path: value.encode("utf-8", errors="surrogatepass")
        for path, value in (head_contents or {}).items()
    }
    inventory = build_inventory(
        root,
        list(selected or inventory_paths),
        config=config,
        content_by_path=inventory_bytes,
        budget=budget,
        source_kind_by_path=source_kind_by_path,
    )
    if base_contents and head_contents is not None:
        missing_paths = sorted(set(base_contents) - set(head_contents))
        if missing_paths:
            base_inventory = build_inventory(
                root,
                missing_paths,
                source_kind="base",
                content_by_path={
                    path: value.encode("utf-8", errors="surrogatepass")
                    for path, value in base_contents.items()
                    if path in missing_paths
                },
                config=config,
                budget=budget,
            )
            inventory = InventoryResult(
                tuple(sorted((*inventory.artifacts, *base_inventory.artifacts), key=lambda item: (item.logical_path, item.source_kind, item.content_sha256))),
                tuple(sorted((*inventory.subjects, *base_inventory.subjects), key=lambda item: (item.logical_path, item.start_line, item.qualified_name, item.source_kind))),
                tuple(sorted((*inventory.relations, *base_inventory.relations), key=lambda item: (str(item.get("test_artifact_id")), str(item.get("subject_id"))))),
                "partial" if inventory.status != "complete" or base_inventory.status != "complete" else "complete",
                inventory.reason_code or base_inventory.reason_code,
                tuple(sorted((*inventory.skipped_paths, *base_inventory.skipped_paths))),
            )
    partition = partition_diff(
        root,
        changed_paths or [item.logical_path for item in inventory.artifacts],
        inventory=inventory,
        entries=entries,
        config=config,
    )
    static = analyse_static(
        root,
        inventory,
        paths=list(selected or [item.logical_path for item in inventory.artifacts]),
        base_contents=base_contents,
        head_contents=head_contents,
        changed_paths=changed_paths if mode == "diff" else None,
        budget=budget,
    ) if _enabled(config, "test_integrity") else StaticAnalysisResult("partial", 0, 0, 0, (), (), "disabled")
    changes = map_test_changes(
        inventory.artifacts,
        inventory.subjects,
        changed_paths=changed_paths,
        base_contents=base_contents,
        head_contents=head_contents,
    )
    return inventory, partition, static, changes


def _head_source_kinds(
    entries: Sequence[DiffEntry],
    paths: Iterable[str],
    base_revision: str,
) -> dict[str, str]:
    """Map each head text value to the source layer selected by Git state."""
    by_path: dict[str, list[DiffEntry]] = {}
    for entry in entries:
        by_path.setdefault(entry.reviewed_path, []).append(entry)
    priority = ("working-tree", "untracked", "index", "commit")
    result: dict[str, str] = {}
    for path in sorted(set(paths)):
        candidates = by_path.get(path, [])
        if base_revision:
            result[path] = next(
                (
                    layer for layer in ("working-tree", "untracked")
                    if any(
                        entry.source_kind == layer and not entry.status.startswith("D")
                        for entry in candidates
                    )
                ),
                "commit",
            )
            continue
        for layer in priority:
            if any(
                entry.source_kind == layer
                and not entry.status.startswith("D")
                for entry in candidates
            ):
                result[path] = layer
                break
        else:
            result[path] = "working-tree"
    return result


def analyse(
    root: Path,
    paths: Iterable[str | Path] | None = None,
    *,
    entries: Sequence[DiffEntry] = (),
    config: Mapping[str, Any] | None = None,
    mode: str = "full",
    base_contents: Mapping[str, str] | None = None,
    head_contents: Mapping[str, str] | None = None,
    approved_matrix_digests: Mapping[str, str] | None = None,
    approved_mutation_digests: Mapping[str, str] | None = None,
    prepare_dynamic_plans: bool = False,
    base_revision: str = "",
    head_revision: str = "HEAD",
) -> TestIntegrityResult:
    root = root.resolve()
    config = config or {}
    selected = tuple(sorted({Path(path).as_posix() for path in (paths or ())})) if paths is not None else None
    changed_paths = (
        tuple(sorted({entry.reviewed_path for entry in entries if entry.reviewed_path}))
        if mode == "diff" and entries
        else selected or tuple(entry.reviewed_path for entry in entries if entry.reviewed_path)
    )
    inventory_paths = selected or changed_paths or tuple(path.relative_to(root).as_posix() for path in iter_files(root))
    if base_contents is None or head_contents is None:
        detected_base, detected_head = _source_maps(
            root,
            entries,
            inventory_paths,
            base_revision=base_revision,
            head_revision=head_revision,
        )
        if base_contents is None:
            base_contents = detected_base
        if head_contents is None:
            head_contents = detected_head

    source_kind_by_path = _head_source_kinds(entries, inventory_paths, base_revision)

    limits = analysis_limits(config)
    inventory, partition, static, changes = _prepare_inventory(
        root, config, inventory_paths, selected, entries, changed_paths, mode,
        base_contents, head_contents, limits,
        source_kind_by_path,
    )
    matrix: EvidenceMatrix | None = None
    if _enabled(config, "dynamic_test_evidence"):
        matrix = build_matrix(
            root,
            partition,
            config=config,
            base_contents={key: value for key, value in (base_contents or {}).items()},
            head_contents={key: value for key, value in (head_contents or {}).items()},
            approved_digests=approved_matrix_digests,
            base_revision=base_revision,
            head_revision=head_revision,
            timeout_seconds=float(limits["test_matrix_timeout_seconds"]),
            create_plans=prepare_dynamic_plans or approved_matrix_digests is not None,
        )
    mutations: MutationRun | None = None
    if _enabled(config, "targeted_mutation"):
        specs = generate_mutations(
            partition,
            inventory.subjects,
            base_contents=base_contents or {},
            head_contents=head_contents or {},
            max_mutants=int(limits["mutation_max_mutants"]),
            max_per_function=int(limits["mutation_max_per_function"]),
        )
        mutations = run_mutations(
            root,
            specs,
            command=_command(root, config),
            build_command=_build_command(config),
            test_selection=partition.tests + partition.test_support,
            approved_digests=approved_mutation_digests,
            timeout_seconds=float(limits["mutation_timeout_seconds"]),
        )
    applicable = bool(inventory.artifacts or inventory.subjects)
    incomplete = inventory.status != "complete" or static.status != "complete"
    if partition.tests and not _enabled(config, "dynamic_test_evidence"):
        incomplete = True
    if partition.production and not _enabled(config, "targeted_mutation"):
        incomplete = True
    if matrix is not None and matrix.status not in {"complete", "not_applicable"} and partition.tests:
        incomplete = True
    if mutations is not None and mutations.status not in {"complete", "not_applicable"} and mutations.results:
        incomplete = True
    status = "not_applicable" if not applicable else "partial" if incomplete else "complete"
    reason = "no_test_or_subject_artifacts" if not applicable else "dynamic_evidence_not_verified" if incomplete else None
    return TestIntegrityResult(status, inventory, partition, static, changes, matrix, mutations, (), reason)


analyse_test_integrity = analyse
