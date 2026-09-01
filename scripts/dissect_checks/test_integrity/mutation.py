"""Bounded changed-code reversion evidence."""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
import difflib
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
from typing import Any, Iterable, Mapping, Sequence

from analysis_budget import AnalysisBudget, AnalysisBudgetExceeded
from dissect_checks.execution_plan import build_execution_plan, execute_approved_plan
from dissect_checks.redaction import redact_sensitive_text
from .change_analysis import ChangePartition
from .evidence_matrix import _archive_revision
from .model import MutationResult, TestSubject, bounded_fingerprint, digest_payload, sha256_bytes
from ..source_validation import balanced_delimiter_error


@dataclass(frozen=True)
class MutationSpec:
    mutation_id: str
    subject: TestSubject
    mutation_kind: str
    logical_path: str
    original_sha256: str
    mutated_sha256: str
    mutated_source: str
    patch_sha256: str

    def __post_init__(self) -> None:
        if not self.mutation_id or not self.mutation_kind or not self.logical_path:
            raise ValueError("mutation specifications require an ID, kind, and path")
        path = Path(self.logical_path)
        if path.is_absolute() or not path.parts or ".." in path.parts:
            raise ValueError("mutation specification path must be repository-relative")
        for name, value in (("original_sha256", self.original_sha256), ("mutated_sha256", self.mutated_sha256), ("patch_sha256", self.patch_sha256)):
            if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
                raise ValueError(f"{name} must be a lowercase SHA-256")
        if self.subject.logical_path != self.logical_path:
            raise ValueError("mutation subject path must match the mutation path")
        if sha256_bytes(self.mutated_source.encode("utf-8", errors="surrogatepass")) != self.mutated_sha256:
            raise ValueError("mutation source does not match mutated_sha256")

    def as_dict(self) -> dict[str, Any]:
        return {
            "mutation_id": self.mutation_id,
            "subject": self.subject.as_dict(),
            "mutation_kind": self.mutation_kind,
            "logical_path": self.logical_path,
            "original_sha256": self.original_sha256,
            "mutated_sha256": self.mutated_sha256,
            "patch_sha256": self.patch_sha256,
        }


@dataclass(frozen=True)
class MutationRun:
    status: str
    results: tuple[MutationResult, ...]
    reason_code: str | None = None
    kill_sets: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    unique_kill_sets: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in {"complete", "partial", "not_applicable", "planned", "unavailable", "failed"}:
            raise ValueError("invalid mutation run status")
        identifiers = [item.mutation_id for item in self.results]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("mutation IDs must be unique within a run")
        result_ids = set(identifiers)
        for name, values in (("kill_sets", self.kill_sets), ("unique_kill_sets", self.unique_kill_sets)):
            if not isinstance(values, Mapping):
                raise ValueError(f"{name} must be a mapping")
            for test_name, mutant_ids in values.items():
                if not isinstance(test_name, str) or not test_name:
                    raise ValueError(f"{name} test identifiers must be non-empty strings")
                if not isinstance(mutant_ids, (tuple, list, set, frozenset)):
                    raise ValueError(f"{name} mutation identifiers must be an array")
                if any(not isinstance(mutant_id, str) or not mutant_id for mutant_id in mutant_ids):
                    raise ValueError(f"{name} mutation identifiers must be non-empty strings")
                if any(mutant_id not in result_ids for mutant_id in mutant_ids):
                    raise ValueError(f"{name} references an unknown mutation")
        for test_name, mutant_ids in self.unique_kill_sets.items():
            if not set(mutant_ids) <= set(self.kill_sets.get(test_name, ())):
                raise ValueError("unique kill sets must be subsets of kill sets")

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason_code": self.reason_code,
            "results": [item.as_dict() for item in self.results],
            "kill_sets": {key: list(value) for key, value in sorted(self.kill_sets.items())},
            "unique_kill_sets": {key: list(value) for key, value in sorted(self.unique_kill_sets.items())},
        }


def _line_slice(text: str, start: int, end: int) -> tuple[int, int]:
    lines = text.splitlines(keepends=True)
    start_index = max(0, min(len(lines), start - 1))
    end_index = max(start_index, min(len(lines), end))
    return sum(len(line) for line in lines[:start_index]), sum(len(line) for line in lines[:end_index])


def _valid_source(path: str, source: str) -> bool:
    return balanced_delimiter_error(path, source) is None


def _python_span(source: str, subject: TestSubject) -> tuple[int, int] | None:
    try:
        tree = ast.parse(source, filename=subject.logical_path, type_comments=True)
    except (SyntaxError, ValueError, TypeError):
        return None
    target = subject.qualified_name.split(".")
    found: tuple[int, int] | None = None

    def visit(node: ast.AST, prefix: tuple[str, ...] = ()) -> None:
        nonlocal found
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = (*prefix, child.name)
                if list(name) == target:
                    found = (child.lineno, getattr(child, "end_lineno", child.lineno))
                visit(child, name)
            else:
                visit(child, prefix)

    visit(tree)
    return found


def _brace_span(source: str, subject: TestSubject) -> tuple[int, int] | None:
    name = re.escape(subject.qualified_name.rsplit(".", 1)[-1].replace("::", "::"))
    match = re.search(rf"\b{ name }\s*\([^{{}};]*\)\s*[^{{}};]*\{{", source)
    if match is None:
        return None
    opening = source.find("{", match.start(), match.end())
    if opening < 0:
        return None
    pairs = {"{": "}", "(": ")", "[": "]"}
    stack: list[str] = []
    quote = ""
    escaped = False
    index = opening
    while index < len(source):
        char = source[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in {'"', "'", "`"}:
            quote = char
        elif char in pairs:
            stack.append(pairs[char])
        elif char in pairs.values():
            if not stack or stack.pop() != char:
                return None
            if not stack:
                return (source.count("\n", 0, match.start()) + 1, source.count("\n", 0, index) + 1)
        index += 1
    return None


def _subject_span(source: str, subject: TestSubject) -> tuple[int, int] | None:
    if Path(subject.logical_path).suffix.lower() in {".py", ".pyi"}:
        return _python_span(source, subject)
    return _brace_span(source, subject)


def revert_subject(head_source: str, base_source: str, subject: TestSubject) -> str | None:
    """Replace one changed function with the matching base function.

    Base line numbers are not reused because a preceding hunk may have moved
    the function. Matching the qualified declaration avoids reverting an
    unrelated function after a line insertion.
    """
    head_span = _subject_span(head_source, subject) or (subject.start_line, subject.end_line)
    base_span = _subject_span(base_source, subject)
    if base_span is None:
        return None
    head_start, head_end = _line_slice(head_source, *head_span)
    base_start, base_end = _line_slice(base_source, *base_span)
    if head_end <= head_start or base_end <= base_start:
        return None
    if head_source[head_start:head_end] == base_source[base_start:base_end]:
        return None
    return head_source[:head_start] + base_source[base_start:base_end] + head_source[head_end:]


def _mutated_spec(path: str, head: str, base: str, subject: TestSubject, index: int) -> MutationSpec | None:
    mutated = revert_subject(head, base, subject)
    if mutated is None or mutated == head or not _valid_source(path, mutated):
        return None
    original_hash = sha256_bytes(head.encode("utf-8", errors="surrogatepass"))
    mutated_hash = sha256_bytes(mutated.encode("utf-8", errors="surrogatepass"))
    patch_text = "".join(difflib.unified_diff(
        head.splitlines(keepends=True),
        mutated.splitlines(keepends=True),
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
    ))
    patch_hash = hashlib.sha256(patch_text.encode("utf-8", errors="surrogatepass")).hexdigest()
    mutation_id = digest_payload({
        "path": path, "subject": subject.qualified_name, "span": [subject.start_line, subject.end_line],
        "kind": "revert_changed_function", "patch": patch_hash, "index": index,
        "source_layer": subject.source_kind,
        "subject_content_sha256": subject.content_sha256,
    }, prefix="mutation-")
    return MutationSpec(mutation_id, subject, "revert_changed_function", path, original_hash, mutated_hash, mutated, patch_hash)


def _source_text(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def generate_mutations(
    partition: ChangePartition,
    subjects: Iterable[TestSubject],
    *,
    base_contents: Mapping[str, str],
    head_contents: Mapping[str, str],
    max_mutants: int = 25,
    max_per_function: int = 3,
    excluded_paths: Iterable[str] = (),
    changed_ranges: Mapping[str, Iterable[tuple[int, int]]] | None = None,
) -> tuple[MutationSpec, ...]:
    """Generate deterministic reversion mutants for changed production functions."""
    if max_mutants < 0 or max_per_function < 0:
        raise ValueError("mutation limits must not be negative")
    output: list[MutationSpec] = []
    counts: dict[str, int] = {}
    excluded = {Path(path).as_posix() for path in excluded_paths}
    for subject in sorted(subjects, key=lambda item: (item.logical_path, item.start_line, item.qualified_name)):
        if subject.logical_path not in partition.production:
            continue
        if changed_ranges is not None:
            ranges = tuple(changed_ranges.get(subject.logical_path) or ())
            if ranges is None or not any(
                subject.start_line <= int(end) and subject.end_line >= int(start)
                for start, end in ranges
            ):
                continue
        parts = set(Path(subject.logical_path).parts)
        if subject.logical_path in excluded or parts & {"vendor", "node_modules", "generated"}:
            continue
        key = f"{subject.logical_path}:{subject.source_kind}:{subject.content_sha256}:{subject.qualified_name}:{subject.start_line}"
        if counts.get(key, 0) >= max_per_function or len(output) >= max_mutants:
            continue
        spec = _mutated_spec(
            subject.logical_path,
            _source_text(head_contents.get(subject.logical_path)),
            _source_text(base_contents.get(subject.logical_path)),
            subject,
            counts.get(key, 0),
        )
        if spec is None:
            continue
        counts[key] = counts.get(key, 0) + 1
        output.append(spec)
    return tuple(output)


def _command_argv(command: str) -> list[str] | None:
    try:
        values = shlex.split(command)
    except ValueError:
        return None
    return values or None


def _isolated_environment(tree: Path) -> dict[str, str]:
    home = tree / ".dissect-home"
    temp = tree / ".dissect-tmp"
    home.mkdir(parents=True, exist_ok=True)
    temp.mkdir(parents=True, exist_ok=True)
    return {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(home), "TMPDIR": str(temp)}


def _repository_identity(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        value = result.stdout.strip() if result.returncode == 0 else root.resolve().as_posix()
    except (OSError, subprocess.SubprocessError):
        value = root.resolve().as_posix()
    return hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()


def _killing_tests(output: str, selection: Sequence[str]) -> tuple[str, ...]:
    if len(selection) == 1:
        return (selection[0],)
    values = set(re.findall(r"(?:FAILED|FAIL(?:ED)?[: ])\s*([\w./:-]+)", output, re.I))
    for selected in selection:
        if selected in output or Path(selected).name in output:
            values.add(selected)
    allowed = set(selection)
    return tuple(sorted(value for value in values if value in allowed))


def _copy_private_tree(root: Path, destination: Path, overrides: Mapping[str, str | bytes]) -> None:
    base_ignore = shutil.ignore_patterns(
        ".git", "node_modules", "__pycache__", "*.pyc", "target",
        ".env", ".env.*", "*.pem", "*.key", "credentials.json", "secrets.json",
    )
    def ignore(directory: str, names: list[str]) -> set[str]:
        ignored = set(base_ignore(directory, names))
        ignored.update(name for name in names if (Path(directory) / name).is_symlink())
        return ignored
    shutil.copytree(
        root,
        destination,
        ignore=ignore,
        dirs_exist_ok=True,
    )
    for path, source in overrides.items():
        path_object = Path(path)
        if path_object.is_absolute() or ".." in path_object.parts:
            raise ValueError(f"mutation override path is outside the private tree: {path}")
        target = destination / path_object
        if target.is_symlink():
            target.unlink()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source if isinstance(source, bytes) else source.encode("utf-8", errors="surrogatepass"))


def _is_git_repository(root: Path) -> bool:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and result.stdout.strip() == "true"


def _source_override_hashes(overrides: Mapping[str, str | bytes]) -> dict[str, str]:
    return {
        path: sha256_bytes(value if isinstance(value, bytes) else value.encode("utf-8", errors="surrogatepass"))
        for path, value in sorted(overrides.items())
    }


def _source_hash(root: Path, path: str) -> str | None:
    path_object = Path(path)
    if path_object.is_absolute() or not path_object.parts or ".." in path_object.parts:
        return None
    physical = (root / path_object).resolve()
    try:
        physical.relative_to(root.resolve())
        size = physical.stat().st_size
        if size > 5 * 1024 * 1024:
            return None
        with physical.open("rb") as handle:
            data = handle.read(size)
        if len(data) != size or physical.stat().st_size != size:
            return None
    except (OSError, ValueError):
        return None
    return sha256_bytes(data)


def _verify_source_overrides(tree: Path, expected: Mapping[str, str]) -> bool:
    for path, digest in expected.items():
        path_object = Path(path)
        if path_object.is_absolute() or not path_object.parts or ".." in path_object.parts:
            return False
        physical = (tree / path_object).resolve()
        try:
            physical.relative_to(tree.resolve())
            size = physical.stat().st_size
            if size > 5 * 1024 * 1024:
                return False
            with physical.open("rb") as handle:
                data = handle.read(size)
            if len(data) != size or physical.stat().st_size != size:
                return False
        except (OSError, ValueError):
            return False
        if sha256_bytes(data) != digest:
            return False
    return True


def _mutation_result(
    spec: MutationSpec,
    *,
    build_valid: bool | None,
    killed: bool | None,
    reason_code: str | None,
    command_plan_digest: str = "",
    build_command_plan_digest: str = "",
    killing_tests: Sequence[str] = (),
) -> MutationResult:
    return MutationResult(
        spec.mutation_id,
        spec.subject,
        spec.mutation_kind,
        spec.patch_sha256,
        build_valid,
        killed,
        tuple(killing_tests),
        reason_code,
        command_plan_digest,
        build_command_plan_digest,
    )


def _run_mutation_spec(
    root: Path,
    directory: Path,
    source_root: Path,
    spec: MutationSpec,
    *,
    argv: Sequence[str] | None,
    build_argv: Sequence[str] | None,
    build_command_configured: bool,
    test_selection: Sequence[str],
    approved_digests: Mapping[str, str],
    review_budget: AnalysisBudget,
    output_limit: int,
    source_overrides: Mapping[str, str | bytes],
    production_patch_sha256: str,
    test_patch_sha256: str,
    shared_config_patch_sha256: str,
    repository_id: str,
) -> tuple[MutationResult, str | None]:
    """Plan and, when approved, run one mutant in its private source tree."""
    if argv is None:
        return _mutation_result(spec, build_valid=None, killed=None, reason_code="command_not_configured"), "command_not_configured"
    if not _valid_source(spec.logical_path, spec.mutated_source):
        return _mutation_result(spec, build_valid=False, killed=None, reason_code="invalid_mutant"), "invalid_mutant"
    supplied_original = source_overrides.get(spec.logical_path)
    observed_original = (
        sha256_bytes(supplied_original if isinstance(supplied_original, bytes) else supplied_original.encode("utf-8", errors="surrogatepass"))
        if supplied_original is not None
        else _source_hash(source_root, spec.logical_path)
    )
    if observed_original != spec.original_sha256:
        return _mutation_result(spec, build_valid=None, killed=None, reason_code="source_snapshot_changed"), "source_snapshot_changed"
    tree = directory / spec.mutation_id
    overrides = dict(source_overrides)
    overrides[spec.logical_path] = spec.mutated_source
    override_hashes = _source_override_hashes(overrides)
    try:
        _copy_private_tree(source_root, tree, overrides)
    except (OSError, ValueError):
        return _mutation_result(spec, build_valid=None, killed=None, reason_code="private_tree_failure"), "private_tree_failure"
    if not source_overrides and _source_hash(source_root, spec.logical_path) != spec.original_sha256:
        return _mutation_result(spec, build_valid=None, killed=None, reason_code="source_snapshot_changed"), "source_snapshot_changed"
    if build_command_configured and build_argv is None:
        return _mutation_result(spec, build_valid=None, killed=None, reason_code="invalid_build_command"), "invalid_build_command"
    build_plan = None
    build_error: str | None = None
    if build_argv is not None:
        build_plan, build_error = build_execution_plan(
            kind="test-evidence",
            name=f"mutation-build:{spec.mutation_id}",
            argv=list(build_argv),
            working_directory=tree,
            environment=_isolated_environment(tree),
            timeout_seconds=max(0.001, review_budget.remaining_seconds()),
            output_limit=output_limit,
            bindings={
                "mutation_id": spec.mutation_id,
                "patch_sha256": spec.patch_sha256,
                "repository_id": repository_id,
                "source_path": spec.logical_path,
                "source_layer": spec.subject.source_kind,
                "original_sha256": spec.original_sha256,
                "mutated_sha256": spec.mutated_sha256,
                "phase": "build",
                "source_snapshot_sha256": digest_payload(override_hashes),
                "production_patch_sha256": production_patch_sha256,
                "test_patch_sha256": test_patch_sha256,
                "shared_config_patch_sha256": shared_config_patch_sha256,
            },
        )
        if build_plan is None:
            return _mutation_result(spec, build_valid=None, killed=None, reason_code=build_error or "plan_unavailable"), build_error or "plan_unavailable"
    plan, error = build_execution_plan(
        kind="test-evidence",
        name=f"mutation:{spec.mutation_id}",
        argv=list(argv),
        working_directory=tree,
        timeout_seconds=max(0.001, review_budget.remaining_seconds()),
        output_limit=output_limit,
        environment=_isolated_environment(tree),
        bindings={
            "mutation_id": spec.mutation_id,
            "patch_sha256": spec.patch_sha256,
            "subject_id": spec.subject.subject_id,
            "repository_id": repository_id,
            "source_path": spec.logical_path,
            "source_layer": spec.subject.source_kind,
            "original_sha256": spec.original_sha256,
            "mutated_sha256": spec.mutated_sha256,
            "test_selection": "\0".join(test_selection),
            "source_snapshot_sha256": digest_payload(override_hashes),
            "production_patch_sha256": production_patch_sha256,
            "test_patch_sha256": test_patch_sha256,
            "shared_config_patch_sha256": shared_config_patch_sha256,
        },
    )
    build_digest = build_plan.approval_digest if build_plan is not None else ""
    if plan is None:
        return _mutation_result(spec, build_valid=None, killed=None, reason_code=error or "plan_unavailable", build_command_plan_digest=build_digest), error or "plan_unavailable"
    approval = approved_digests.get(spec.mutation_id)
    build_approval = approved_digests.get(f"{spec.mutation_id}:build")
    if approval is None or (build_plan is not None and build_approval is None):
        return _mutation_result(
            spec, build_valid=None, killed=None, reason_code="not_approved",
            command_plan_digest=plan.approval_digest, build_command_plan_digest=build_digest,
        ), "not_approved"
    if not _verify_source_overrides(tree, override_hashes):
        return _mutation_result(
            spec, build_valid=None, killed=None, reason_code="source_snapshot_changed",
            command_plan_digest=plan.approval_digest, build_command_plan_digest=build_digest,
        ), "source_snapshot_changed"
    if build_plan is not None:
        build_completed, build_execution_error = execute_approved_plan(build_plan, build_approval)
        if build_completed is None or build_completed.returncode != 0:
            build_reason = (
                "build_timeout" if build_completed is not None and build_completed.returncode == 124
                else "invalid_mutant" if build_completed is not None
                else build_execution_error or "build_failed"
            )
            return _mutation_result(
                spec,
                build_valid=None if build_reason == "build_timeout" else False,
                killed=None,
                reason_code=build_reason,
                command_plan_digest=plan.approval_digest,
                build_command_plan_digest=build_digest,
            ), build_reason
    if not _verify_source_overrides(tree, override_hashes):
        return _mutation_result(
            spec, build_valid=None, killed=None, reason_code="source_snapshot_changed",
            command_plan_digest=plan.approval_digest, build_command_plan_digest=build_digest,
        ), "source_snapshot_changed"
    completed, execution_error = execute_approved_plan(plan, approval)
    if completed is None:
        reason = execution_error or "execution_failed"
        return _mutation_result(
            spec, build_valid=None, killed=None, reason_code=reason,
            command_plan_digest=plan.approval_digest, build_command_plan_digest=build_digest,
        ), reason
    output = redact_sensitive_text(((completed.stdout or "") + (completed.stderr or ""))[:output_limit])
    timed_out = completed.returncode == 124
    killed = None if timed_out else completed.returncode != 0
    reason = "test_timeout" if timed_out else None if completed.returncode == 0 else "mutant_killed"
    return _mutation_result(
        spec,
        build_valid=True,
        killed=killed,
        killing_tests=_killing_tests(output, test_selection) if killed else (),
        reason_code=reason,
        command_plan_digest=plan.approval_digest,
        build_command_plan_digest=build_digest,
    ), None


def _prepare_mutation_source(root: Path, directory: Path, source_revision: str) -> tuple[Path, str | None]:
    source_root = root
    if source_revision and _is_git_repository(root):
        archived = directory / "head-source"
        if not _archive_revision(root, source_revision, archived):
            return root, "source_snapshot_unavailable"
        source_root = archived
    return source_root, None


def _run_mutation_specs(
    root: Path,
    directory: Path,
    source_root: Path,
    specs: Sequence[MutationSpec],
    *,
    argv: Sequence[str] | None,
    build_argv: Sequence[str] | None,
    build_command_configured: bool,
    test_selection: Sequence[str],
    approved_digests: Mapping[str, str],
    review_budget: AnalysisBudget,
    output_limit: int,
    source_overrides: Mapping[str, str | bytes],
    production_patch_sha256: str,
    test_patch_sha256: str,
    shared_config_patch_sha256: str,
    repository_id: str,
) -> tuple[list[MutationResult], str | None]:
    results: list[MutationResult] = []
    reason: str | None = None
    for index, spec in enumerate(specs):
        try:
            review_budget.claim_file()
        except AnalysisBudgetExceeded as error:
            reason = reason or error.reason_code
            results.extend(
                _mutation_result(remaining, build_valid=None, killed=None, reason_code=error.reason_code)
                for remaining in specs[index:]
            )
            break
        result, result_reason = _run_mutation_spec(
            root, directory, source_root, spec,
            argv=argv,
            build_argv=build_argv,
            build_command_configured=build_command_configured,
            test_selection=test_selection,
            approved_digests=approved_digests,
            review_budget=review_budget,
            output_limit=output_limit,
            source_overrides=source_overrides,
            production_patch_sha256=production_patch_sha256,
            test_patch_sha256=test_patch_sha256,
            shared_config_patch_sha256=shared_config_patch_sha256,
            repository_id=repository_id,
        )
        results.append(result)
        reason = reason or result_reason
    return results, reason


def _mutation_status(results: Sequence[MutationResult], reason: str | None) -> str:
    if reason == "not_approved":
        return "planned"
    if reason == "command_not_configured":
        return "unavailable"
    if reason:
        return "partial"
    return "complete" if all(item.reason_code != "not_approved" for item in results) else "planned"


def _validate_mutation_request(
    specs: Sequence[MutationSpec],
    build_command: str | None,
    approved_digests: Mapping[str, str] | None,
    patch_hashes: Mapping[str, str],
) -> None:
    for name, value in patch_hashes.items():
        if value and (len(value) != 64 or any(character not in "0123456789abcdef" for character in value)):
            raise ValueError(f"{name} must be a lowercase SHA-256 or empty")
    if approved_digests is None:
        return
    expected_approvals = {spec.mutation_id for spec in specs}
    if build_command:
        expected_approvals.update(f"{spec.mutation_id}:build" for spec in specs)
    unknown_approvals = sorted(set(approved_digests) - expected_approvals)
    if unknown_approvals:
        raise ValueError(f"unknown mutation approval(s): {', '.join(unknown_approvals)}")


def run_mutations(
    root: Path,
    specs: Sequence[MutationSpec],
    *,
    command: str | None = None,
    build_command: str | None = None,
    test_selection: Sequence[str] = (),
    approved_digests: Mapping[str, str] | None = None,
    timeout_seconds: float = 300,
    output_limit: int = 64 * 1024,
    source_overrides: Mapping[str, str | bytes] | None = None,
    source_revision: str = "",
    production_patch_sha256: str = "",
    test_patch_sha256: str = "",
    shared_config_patch_sha256: str = "",
) -> MutationRun:
    """Plan every mutant and execute only an exact approved plan."""
    _validate_mutation_request(
        specs,
        build_command,
        approved_digests,
        {
            "production_patch_sha256": production_patch_sha256,
            "test_patch_sha256": test_patch_sha256,
            "shared_config_patch_sha256": shared_config_patch_sha256,
        },
    )
    if not specs:
        return MutationRun("not_applicable", ())
    argv = _command_argv(command) if command else None
    review_budget = AnalysisBudget(timeout_seconds, max_files=len(specs))
    with tempfile.TemporaryDirectory(prefix="dissect-mutations-") as directory:
        source_root, source_reason = _prepare_mutation_source(root, Path(directory), source_revision)
        if source_reason is not None:
            results = [
                _mutation_result(spec, build_valid=None, killed=None, reason_code=source_reason)
                for spec in specs
            ]
            return MutationRun("partial", tuple(results), source_reason, {}, {})
        source_values = source_overrides or {}
        build_argv = _command_argv(build_command) if build_command else None
        repository_id = _repository_identity(root)
        results, reason = _run_mutation_specs(
            root, Path(directory), source_root, specs,
            argv=argv,
            build_argv=build_argv,
            build_command_configured=bool(build_command),
            test_selection=test_selection,
            approved_digests=approved_digests or {},
            review_budget=review_budget,
            output_limit=output_limit,
            source_overrides=source_values,
            production_patch_sha256=production_patch_sha256,
            test_patch_sha256=test_patch_sha256,
            shared_config_patch_sha256=shared_config_patch_sha256,
            repository_id=repository_id,
        )
    status = _mutation_status(results, reason)
    mutation_results = tuple(results)
    return MutationRun(
        status,
        mutation_results,
        reason,
        {key: tuple(sorted(value)) for key, value in kill_sets(mutation_results).items()},
        {key: tuple(sorted(value)) for key, value in unique_kill_sets(mutation_results).items()},
    )


def kill_sets(results: Iterable[MutationResult]) -> dict[str, frozenset[str]]:
    output: dict[str, set[str]] = {}
    for result in results:
        for test in result.killing_tests:
            output.setdefault(test, set()).add(result.mutation_id)
    return {key: frozenset(value) for key, value in sorted(output.items())}


def unique_kill_sets(results: Iterable[MutationResult]) -> dict[str, frozenset[str]]:
    """Return mutants killed by one test and no other recorded test."""
    sets = kill_sets(results)
    output: dict[str, frozenset[str]] = {}
    for test, killed in sets.items():
        other = set().union(*(value for name, value in sets.items() if name != test))
        output[test] = frozenset(sorted(set(killed) - other))
    return {key: value for key, value in sorted(output.items())}


def removal_decision(
    *,
    has_unique_contract: bool,
    reaches_unique_subject: bool,
    unique_kills: bool,
    passes_reverted_hunk: bool,
    passes_base_and_head: bool,
    independent_oracle: bool,
    stable: bool,
    sole_structural_check: bool,
    execution_verified: bool,
) -> str:
    if not execution_verified:
        return "not verified"
    if has_unique_contract or reaches_unique_subject or unique_kills or sole_structural_check or not stable:
        return "keep"
    if not independent_oracle or not passes_base_and_head:
        return "strengthen"
    if not passes_reverted_hunk:
        return "keep"
    return "remove"
