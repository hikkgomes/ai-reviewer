"""Coordinate static test checks and approval-bound dynamic evidence."""
from __future__ import annotations

from dataclasses import dataclass, replace
import difflib
import hashlib
import json
import subprocess
from pathlib import Path
import re
import sys
from typing import Any, Iterable, Mapping, Sequence

from analysis_budget import AnalysisBudget, analysis_limits
from diff_file_list import DiffEntry
from file_paths import iter_files
from .change_analysis import ChangePartition, exact_source_states, map_test_changes, partition_diff
from .evidence_matrix import EvidenceMatrix, _repository_ci_test_command, build_matrix
from .inventory import InventoryResult, build_inventory
from .model import TestChange, USEFULNESS_DIMENSIONS, public_state
from .mutation import MutationRun, generate_mutations, run_mutations
from .static_analysis import StaticAnalysisResult, analyse_static


MAX_SOURCE_MAP_BYTES = 5 * 1024 * 1024
MAX_DIFF_COMPARISONS = 1_000_000
TEST_ROLES = frozenset({
    "test", "test helper", "fixture", "snapshot or golden file",
    "test configuration", "CI test command",
})
ORACLE_KINDS = frozenset({
    "user_intent", "public_contract", "existing_invariant", "external_spec",
    "independent_reference",
})


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


def _content_map_digest(values: Mapping[str, str | bytes] | None, paths: Iterable[str]) -> str:
    """Digest the exact selected source values for execution-plan binding."""
    payload = "\n".join(
        f"{path}\0{hashlib.sha256((values[path] if isinstance(values[path], bytes) else values[path].encode('utf-8', errors='surrogatepass'))).hexdigest()}"
        for path in sorted(set(paths))
        if values is not None and path in values
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _changed_ranges_from_contents(
    base_contents: Mapping[str, str],
    head_contents: Mapping[str, str],
) -> dict[str, tuple[tuple[int, int], ...] | None]:
    """Infer changed head lines when no Git hunk map was supplied."""
    output: dict[str, tuple[tuple[int, int], ...] | None] = {}
    for path in sorted(set(base_contents) | set(head_contents)):
        before = (base_contents.get(path) or "").splitlines()
        after = (head_contents.get(path) or "").splitlines()
        if path not in head_contents:
            output[path] = None
            continue
        if path not in base_contents:
            output[path] = ((1, max(1, len(after))),)
            continue
        if len(before) * len(after) > MAX_DIFF_COMPARISONS:
            output[path] = ((1, max(1, len(after))),)
            continue
        matcher = difflib.SequenceMatcher(a=before, b=after, autojunk=False)
        ranges: list[tuple[int, int]] = []
        for tag, _before_start, _before_end, after_start, after_end in matcher.get_opcodes():
            if tag != "equal" and after_end > after_start:
                ranges.append((after_start + 1, after_end))
        output[path] = tuple(ranges)
    return output


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

    def close(self) -> None:
        if self.matrix is not None:
            self.matrix.close()

    @property
    def applicable(self) -> bool:
        return bool(
            self.static.candidates
            or any(item.role in TEST_ROLES for item in self.inventory.artifacts)
        )

    def as_dict(self) -> dict[str, Any]:
        static = self.static.as_dict()
        matrix_object = self.matrix
        matrix = matrix_object.as_dict() if matrix_object is not None else {"status": "not_applicable", "reason_code": "disabled", "scenarios": []}
        mutations = self.mutations.as_dict() if self.mutations is not None else {
            "status": "not_applicable", "reason_code": "disabled", "results": [],
            "kill_sets": {}, "unique_kill_sets": {},
        }
        return {
            "status": self.status,
            "state": public_state(self.status, applicable=self.applicable),
            "reason_code": self.reason_code,
            "inventory": self.inventory.as_dict(),
            "partition": self.partition.as_dict(),
            "changes": [item.as_dict() for item in self.changes],
            "static_analysis": static,
            "dynamic_matrix": matrix,
            "targeted_mutation": mutations,
            "proof_tests": [dict(item) for item in self.proof_tests],
            "dynamic_candidates": [dict(item) for item in getattr(matrix_object, "dynamic_candidates", ())],
            "artifacts": [item.as_dict() for item in self.inventory.artifacts],
            "subjects": [item.as_dict() for item in self.inventory.subjects],
            "relations": [dict(item) for item in self.inventory.relations],
            "static_candidates": list(self.static.candidates),
            "matrix": matrix.get("scenarios", []),
            "mutations": mutations.get("results", []),
        }


def _usefulness_evidence(
    change: TestChange,
    matrix: EvidenceMatrix | None,
    mutations: MutationRun | None,
) -> dict[str, Any]:
    """Keep test-value dimensions separate; unknown evidence stays null."""
    evidence = {key: None for key in USEFULNESS_DIMENSIONS}
    independent = change.oracle_source.get("kind") in ORACLE_KINDS
    evidence["uses_independent_oracle"] = independent
    evidence["has_explicit_contract_source"] = independent
    if matrix is None:
        return evidence
    scenarios = {item.scenario_id: item for item in matrix.scenarios}
    head = scenarios.get("head-code-head-tests")
    if head is not None and head.result.completed:
        evidence["collects_or_compiles"] = True
        evidence["passes_on_head"] = head.result.passed
    interpretation = matrix.as_dict().get("interpretation", {})
    outcome = interpretation.get("outcome")
    if outcome == "distinguishes_base_and_head":
        evidence["distinguishes_base_and_head"] = True
    elif outcome in {"stable_contract", "contract_changed"}:
        evidence["distinguishes_base_and_head"] = False
    repeated = [
        scenario for scenario in matrix.scenarios
        if scenario.repeated_runs
    ]
    if repeated:
        evidence["stable_across_repeated_runs"] = all(
            scenario.as_dict()["flakiness"].get("status") == "stable"
            for scenario in repeated
        )
    if mutations is not None:
        test_name = change.test.logical_path
        kill_sets = mutations.kill_sets
        unique_sets = mutations.unique_kill_sets
        if test_name in kill_sets:
            evidence["kills_targeted_valid_mutant"] = bool(kill_sets[test_name])
            evidence["has_unique_mutation_kill_set"] = bool(unique_sets.get(test_name))
    return evidence


def _git_text(root: Path, revision: str, path: str, *, limit: int = MAX_SOURCE_MAP_BYTES) -> str | None:
    if not revision or revision.startswith("-"):
        return None
    path_object = Path(path)
    if path_object.is_absolute() or not path_object.parts or ".." in path_object.parts:
        return None
    try:
        process = subprocess.Popen(
            ["git", "show", "--format=", f"{revision}:{path_object.as_posix()}"],
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


def _looks_like_test_path(path: str) -> bool:
    lower = path.lower().replace("\\", "/")
    name = Path(lower).name
    wrapped = f"/{lower.strip('/')}/"
    return bool(
        any(f"/{token}/" in wrapped for token in ("test", "tests", "spec", "specs", "__tests__", "testdata", "fixtures", "unit", "integration", "e2e", "end-to-end"))
        or re.search(r"(?:^|[._-])(?:test|spec|unit|integration|e2e|end[-_]to[-_]end)(?:[._-]|$)", name)
        or name.endswith("_test.go")
        or name in {"pytest.ini", "tox.ini", "conftest.py", "jest.config.js", "jest.config.ts", "vitest.config.js", "vitest.config.ts"}
        or lower.startswith(".github/workflows/")
    )


def _unstaged_change_state(root: Path, path: str) -> bool | None:
    """Tell staged and worktree snapshots apart for one repository path.

    ``changed_entries`` can retain both layers so other analysers can inspect
    them independently.  The test matrix still needs one exact local head
    state: the index for a staged-only change, or the worktree when an
    unstaged change exists as well.  ``None`` means Git evidence was not
    available, so callers can use a conservative filesystem fallback.
    """
    path_object = Path(path)
    if path_object.is_absolute() or ".." in path_object.parts:
        return None
    try:
        result = subprocess.run(
            ["git", "diff", "--no-ext-diff", "--name-only", "-z", "--", path],
            cwd=root,
            capture_output=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return bool(result.stdout)


def _local_source_pair(
    root: Path,
    path: str,
    entries: Sequence[DiffEntry],
    states: Sequence[Any],
) -> tuple[str | None, str | None]:
    state_values = tuple(states)

    def state_for(kind: str) -> Any | None:
        candidates = [state for state in state_values if state.source_kind == kind]
        if not candidates:
            return None
        matching_entries = [
            entry for entry in entries
            if entry.reviewed_path == path and entry.source_kind == kind
        ]
        if matching_entries:
            revisions = {entry.commit_revision for entry in matching_entries}
            exact = [state for state in candidates if state.revision in revisions]
            if exact:
                candidates = exact
        return sorted(candidates, key=lambda state: (state.revision, state.content_sha256))[-1]

    worktree_state = state_for("working-tree")
    index_state = state_for("index")
    untracked_state = state_for("untracked")
    commit_state = state_for("commit")
    unstaged = _unstaged_change_state(root, path) if worktree_state is not None else False
    if unstaged is None:
        unstaged = worktree_state is not None and index_state is None
    after_state = (
        worktree_state if unstaged
        else untracked_state
        or index_state
        or worktree_state
        or commit_state
    )
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
    before_state = index_state if unstaged else commit_state
    if before_state is None and unstaged:
        before_state = commit_state
    before = before_state.data.decode("utf-8", errors="replace") if before_state is not None and before_state.source_kind != "untracked" else None
    after = after_state.data.decode("utf-8", errors="replace") if after_state is not None else None
    if after is None and not states:
        after = _working_text(root, path)
        before = _git_text(root, "HEAD", path)
    return before, after


def _source_maps(
    root: Path,
    entries: Sequence[DiffEntry],
    paths: Iterable[str],
    *,
    base_revision: str = "",
    head_revision: str = "HEAD",
    assume_base_equals_head: bool = False,
) -> tuple[dict[str, str], dict[str, str]]:
    states = exact_source_states(root, entries)
    by_path: dict[str, list[Any]] = {}
    for state in states:
        if not state.exists:
            continue
        by_path.setdefault(state.logical_path, []).append(state)
    base: dict[str, str] = {}
    head: dict[str, str] = {}
    requested = sorted(set(paths))
    for path in requested:
        candidates = by_path.get(path, [])
        if base_revision:
            # Commit-range reviews compare the requested base with the exact
            # reviewed head. Do not use the current worktree as an implicit
            # third source layer.
            base_path = path
            head_path = path
            entry = next(
                (
                    item for item in entries
                    if item.source_kind == "commit"
                    and item.reviewed_path == path
                ),
                None,
            )
            if entry is not None:
                base_path = entry.old_path if entry.status.startswith(("R", "C")) else path
                head_path = entry.new_path if not entry.status.startswith("D") else path
            before = _git_text(root, base_revision, base_path)
            after = _git_text(root, head_revision, head_path)
            if before is not None:
                base[path] = before
            if after is not None:
                head[path] = after
            continue

        before, after = _local_source_pair(root, path, entries, candidates)
        if before is not None:
            base[path] = before
        if after is not None:
            head[path] = after
        if assume_base_equals_head:
            # Full mode describes the selected current source state.  It must
            # not turn an unrelated dirty checkout into a historical
            # base/head comparison merely because HEAD happens to contain the
            # same path.
            if after is not None:
                base[path] = after
            else:
                base.pop(path, None)
    return base, head


def source_maps(
    root: Path,
    entries: Sequence[DiffEntry],
    paths: Iterable[str],
    *,
    base_revision: str = "",
    head_revision: str = "HEAD",
    assume_base_equals_head: bool = False,
) -> tuple[dict[str, str], dict[str, str]]:
    """Return exact, bounded text snapshots for the base and head layers."""
    return _source_maps(
        root,
        entries,
        paths,
        base_revision=base_revision,
        head_revision=head_revision,
        assume_base_equals_head=assume_base_equals_head,
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
    intent_text: str | None = None,
) -> tuple[InventoryResult, ChangePartition, StaticAnalysisResult, tuple[TestChange, ...]]:
    budget = AnalysisBudget(
        float(limits["test_integrity_timeout_seconds"]),
        max(
            1,
            len(
                set(inventory_paths)
                | set(base_contents or {})
                | set(head_contents or {})
            ),
        ),
        256 * 1024 * 1024,
        500,
    )
    inventory_bytes = {
        path: value if isinstance(value, bytes) else value.encode("utf-8", errors="surrogatepass")
        for path, value in (head_contents or {}).items()
    }
    known_head_absent = {
        item.reviewed_path
        for item in entries
        if item.status.startswith("D") and item.reviewed_path
    }
    head_inventory_paths = [
        path for path in (selected or inventory_paths)
        if path not in known_head_absent
    ]
    inventory = build_inventory(
        root,
        head_inventory_paths,
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
                    path: value if isinstance(value, bytes) else value.encode("utf-8", errors="surrogatepass")
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
    partition_paths = tuple(sorted({
        *changed_paths,
        *(
            item.logical_path for item in inventory.artifacts
            if item.role in TEST_ROLES
        ),
    }))
    partition = partition_diff(
        root,
        partition_paths or [item.logical_path for item in inventory.artifacts],
        inventory=inventory,
        entries=entries,
        config=config,
    )
    static = analyse_static(
        root,
        inventory,
        # Include production paths as well as test artefacts.  GOV-TESTS-006
        # cannot detect a test-only production seam when full-mode analysis
        # silently narrows the static pass to test files.
        paths=list(selected or inventory_paths),
        base_contents=base_contents,
        head_contents=head_contents,
        changed_paths=changed_paths if mode == "diff" else None,
        budget=budget,
        intent_text=intent_text,
        config=config,
        new_paths=tuple(
            entry.new_path
            for entry in entries
            if entry.new_path and entry.status.startswith(("A", "R", "C"))
        ),
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
    *,
    root: Path | None = None,
) -> dict[str, str]:
    """Map each head text value to the source layer selected by Git state."""
    by_path: dict[str, list[DiffEntry]] = {}
    for entry in entries:
        by_path.setdefault(entry.reviewed_path, []).append(entry)
    result: dict[str, str] = {}
    for path in sorted(set(paths)):
        result[path] = _head_layer_for_path(
            root, path, by_path.get(path, []), base_revision,
        )
    return result


def _head_layer_for_path(
    root: Path | None,
    path: str,
    candidates: Sequence[DiffEntry],
    base_revision: str,
) -> str:
    live = lambda layer: any(
        entry.source_kind == layer and not entry.status.startswith("D")
        for entry in candidates
    )
    if base_revision:
        return next((layer for layer in ("commit", "untracked", "working-tree") if live(layer)), "commit")
    if live("untracked"):
        return "untracked"
    has_worktree = live("working-tree")
    if has_worktree and (root is None or _unstaged_change_state(root, path) is not False):
        return "working-tree"
    if live("index"):
        return "index"
    return "commit" if live("commit") else "working-tree"


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
    changed_ranges: Mapping[str, Iterable[tuple[int, int]]] | None = None,
    reachability_by_scenario: Mapping[str, str] | None = None,
    reached_subjects_by_scenario: Mapping[str, Iterable[str]] | None = None,
    focal_subjects_by_scenario: Mapping[str, Iterable[str]] | None = None,
    intent_text: str | None = None,
) -> TestIntegrityResult:
    root = root.resolve()
    config = config or {}
    selected = tuple(sorted({Path(path).as_posix() for path in (paths or ())})) if paths is not None else None
    # Full mode inventories and challenges the selected repository, but does
    # not pretend that every existing test was changed.  This keeps the
    # changed-test oracle and mutation claims scoped to diff evidence.
    changed_paths = (
        tuple(sorted({entry.reviewed_path for entry in entries if entry.reviewed_path}))
        if mode == "diff" and entries else
        tuple(sorted(set(selected or ()))) if mode == "diff" else
        ()
    )
    if selected is not None:
        inventory_paths = selected
    elif mode == "diff":
        inventory_paths = tuple(sorted({
            *changed_paths,
            *(
                path.relative_to(root).as_posix()
                for path in iter_files(root)
                if _looks_like_test_path(path.relative_to(root).as_posix())
            ),
        }))
    else:
        inventory_paths = tuple(path.relative_to(root).as_posix() for path in iter_files(root))
    if base_contents is None or head_contents is None:
        detected_base, detected_head = _source_maps(
            root,
            entries,
            inventory_paths,
            base_revision=base_revision,
            head_revision=head_revision,
            assume_base_equals_head=mode == "full",
        )
        if base_contents is None:
            base_contents = detected_base
        if head_contents is None:
            head_contents = detected_head

    effective_changed_ranges = changed_ranges
    if mode == "diff" and effective_changed_ranges is None:
        effective_changed_ranges = _changed_ranges_from_contents(
            base_contents or {}, head_contents or {},
        )

    source_kind_by_path = _head_source_kinds(
        entries, inventory_paths, base_revision, root=root,
    )

    limits = analysis_limits(config)
    inventory, partition, static, changes = _prepare_inventory(
        root, config, inventory_paths, selected, entries, changed_paths, mode,
        base_contents, head_contents, limits,
        source_kind_by_path,
        intent_text,
    )
    matrix: EvidenceMatrix | None = None
    if _enabled(config, "dynamic_test_evidence"):
        mapped_subjects = tuple(sorted({
            subject.subject_id
            for change in changes
            for subject in change.affected_subjects
        }))
        focal_subjects = {
            scenario_id: mapped_subjects
            for scenario_id in (
                "base-code-base-tests", "base-code-head-tests",
                "head-code-base-tests", "head-code-head-tests",
            )
        }
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
            flaky_repetitions=int(limits["flaky_test_repetitions"]),
            reachability_by_scenario=reachability_by_scenario,
            reached_subjects_by_scenario=reached_subjects_by_scenario,
            focal_subjects_by_scenario=focal_subjects_by_scenario or focal_subjects,
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
            excluded_paths=partition.documentation_or_generated,
            changed_ranges=effective_changed_ranges,
        )
        mutations = run_mutations(
            root,
            specs,
            command=_command(root, config),
            build_command=_build_command(config),
            test_selection=partition.tests + partition.test_support,
            approved_digests=approved_mutation_digests,
            timeout_seconds=float(limits["mutation_timeout_seconds"]),
            source_overrides={
                path: value
                for path, value in (head_contents or {}).items()
            },
            source_revision=head_revision if mode == "diff" else "",
            production_patch_sha256=_content_map_digest(head_contents, partition.production),
            test_patch_sha256=_content_map_digest(head_contents, partition.tests + partition.test_support),
            shared_config_patch_sha256=_content_map_digest(head_contents, partition.shared_configuration),
        )
    changes = tuple(
        replace(item, usefulness=_usefulness_evidence(item, matrix, mutations))
        for item in changes
    )
    applicable = bool(
        static.candidates
        or any(item.role in TEST_ROLES for item in inventory.artifacts)
    )
    incomplete = inventory.status != "complete" or static.status != "complete"
    if partition.tests and not _enabled(config, "dynamic_test_evidence"):
        incomplete = True
    if partition.production and not _enabled(config, "targeted_mutation"):
        incomplete = True
    if matrix is not None and matrix.status not in {"complete", "not_applicable"} and partition.tests:
        incomplete = True
    if mutations is not None and mutations.status not in {"complete", "not_applicable"} and mutations.results:
        incomplete = True
    missing_oracle = any(
        change.oracle_source.get("kind") not in ORACLE_KINDS
        for change in changes
    )
    if missing_oracle:
        incomplete = True
    status = "not_applicable" if not applicable else "partial" if incomplete else "complete"
    reason = (
        "no_test_or_subject_artifacts" if not applicable else
        "oracle_not_recorded" if missing_oracle else
        "dynamic_evidence_not_verified" if incomplete else None
    )
    return TestIntegrityResult(status, inventory, partition, static, changes, matrix, mutations, (), reason)


analyse_test_integrity = analyse
