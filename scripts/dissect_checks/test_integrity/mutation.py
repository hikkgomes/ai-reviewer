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
from .model import MutationResult, TestSubject, bounded_fingerprint, digest_payload, sha256_bytes


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
        for name, value in (("original_sha256", self.original_sha256), ("mutated_sha256", self.mutated_sha256), ("patch_sha256", self.patch_sha256)):
            if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
                raise ValueError(f"{name} must be a lowercase SHA-256")
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
    suffix = Path(path).suffix.lower()
    if suffix in {".py", ".pyi"}:
        try:
            ast.parse(source, filename=path)
        except (SyntaxError, ValueError, TypeError):
            return False
        return True
    if "\0" in source:
        return False
    pairs = {"{": "}", "(": ")", "[": "]"}
    stack: list[str] = []
    quote = ""
    escaped = False
    for char in source:
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {'"', "'", "`"}:
            quote = char
        elif char in pairs:
            stack.append(pairs[char])
        elif char in pairs.values():
            if not stack or stack.pop() != char:
                return False
    return not stack and not quote


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
    }, prefix="mutation-")
    return MutationSpec(mutation_id, subject, "revert_changed_function", path, original_hash, mutated_hash, mutated, patch_hash)


def generate_mutations(
    partition: ChangePartition,
    subjects: Iterable[TestSubject],
    *,
    base_contents: Mapping[str, str],
    head_contents: Mapping[str, str],
    max_mutants: int = 25,
    max_per_function: int = 3,
) -> tuple[MutationSpec, ...]:
    """Generate deterministic reversion mutants for changed production functions."""
    if max_mutants < 0 or max_per_function < 0:
        raise ValueError("mutation limits must not be negative")
    output: list[MutationSpec] = []
    counts: dict[str, int] = {}
    for subject in sorted(subjects, key=lambda item: (item.logical_path, item.start_line, item.qualified_name)):
        if subject.logical_path not in partition.production:
            continue
        key = f"{subject.logical_path}:{subject.qualified_name}:{subject.start_line}"
        if counts.get(key, 0) >= max_per_function or len(output) >= max_mutants:
            continue
        spec = _mutated_spec(
            subject.logical_path,
            head_contents.get(subject.logical_path, ""),
            base_contents.get(subject.logical_path, ""),
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
    values = set(re.findall(r"(?:FAILED|FAIL(?:ED)?[: ])\s*([\w./:-]+)", output, re.I))
    if not values and len(selection) == 1:
        values.add(selection[0])
    return tuple(sorted(values))


def _copy_private_tree(root: Path, destination: Path, overrides: Mapping[str, str]) -> None:
    shutil.copytree(
        root,
        destination,
        ignore=shutil.ignore_patterns(
            ".git", "node_modules", "__pycache__", "*.pyc", "target",
            ".env", ".env.*", "*.pem", "*.key", "credentials.json", "secrets.json",
        ),
        dirs_exist_ok=True,
    )
    for path, source in overrides.items():
        path_object = Path(path)
        if path_object.is_absolute() or ".." in path_object.parts:
            raise ValueError(f"mutation override path is outside the private tree: {path}")
        target = destination / path_object
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")


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
) -> MutationRun:
    """Plan every mutant and execute only an exact approved plan."""
    if not specs:
        return MutationRun("not_applicable", ())
    argv = _command_argv(command) if command else None
    results: list[MutationResult] = []
    reason: str | None = None
    review_budget = AnalysisBudget(timeout_seconds, max_files=len(specs))
    with tempfile.TemporaryDirectory(prefix="dissect-mutations-") as directory:
        for index, spec in enumerate(specs):
            try:
                review_budget.claim_file()
            except AnalysisBudgetExceeded as error:
                reason = reason or error.reason_code
                for remaining in specs[index:]:
                    results.append(MutationResult(
                        remaining.mutation_id, remaining.subject, remaining.mutation_kind,
                        remaining.patch_sha256, None, None, (), error.reason_code,
                    ))
                break
            if argv is None:
                results.append(MutationResult(spec.mutation_id, spec.subject, spec.mutation_kind, spec.patch_sha256, None, None, (), "command_not_configured"))
                reason = reason or "command_not_configured"
                continue
            tree = Path(directory) / spec.mutation_id
            _copy_private_tree(root, tree, {spec.logical_path: spec.mutated_source})
            build_argv = _command_argv(build_command) if build_command else None
            if build_command and build_argv is None:
                results.append(MutationResult(spec.mutation_id, spec.subject, spec.mutation_kind, spec.patch_sha256, None, None, (), "invalid_build_command"))
                reason = reason or "invalid_build_command"
                continue
            plan_timeout = max(0.001, review_budget.remaining_seconds())
            build_plan = None
            build_error: str | None = None
            if build_argv is not None:
                build_plan, build_error = build_execution_plan(
                    kind="test-evidence",
                    name=f"mutation-build:{spec.mutation_id}",
                    argv=build_argv,
                    working_directory=tree,
                    environment=_isolated_environment(tree),
                    timeout_seconds=plan_timeout,
                    output_limit=output_limit,
                    bindings={
                        "mutation_id": spec.mutation_id,
                        "patch_sha256": spec.patch_sha256,
                        "repository_id": _repository_identity(root),
                        "source_path": spec.logical_path,
                        "source_layer": spec.subject.source_kind,
                        "original_sha256": spec.original_sha256,
                        "mutated_sha256": spec.mutated_sha256,
                        "phase": "build",
                    },
                )
                if build_plan is None:
                    results.append(MutationResult(spec.mutation_id, spec.subject, spec.mutation_kind, spec.patch_sha256, None, None, (), build_error or "plan_unavailable"))
                    reason = reason or build_error or "plan_unavailable"
                    continue
            plan, error = build_execution_plan(
                kind="test-evidence",
                name=f"mutation:{spec.mutation_id}",
                argv=argv,
                working_directory=tree,
                timeout_seconds=max(0.001, review_budget.remaining_seconds()),
                output_limit=output_limit,
                environment=_isolated_environment(tree),
                bindings={
                    "mutation_id": spec.mutation_id,
                    "patch_sha256": spec.patch_sha256,
                    "subject_id": spec.subject.subject_id,
                    "repository_id": _repository_identity(root),
                    "source_path": spec.logical_path,
                    "source_layer": spec.subject.source_kind,
                    "original_sha256": spec.original_sha256,
                    "mutated_sha256": spec.mutated_sha256,
                    "test_selection": "\0".join(test_selection),
                },
            )
            if plan is None:
                results.append(MutationResult(spec.mutation_id, spec.subject, spec.mutation_kind, spec.patch_sha256, None, None, (), error or "plan_unavailable"))
                reason = reason or error or "plan_unavailable"
                continue
            approval = (approved_digests or {}).get(spec.mutation_id)
            build_approval = (approved_digests or {}).get(f"{spec.mutation_id}:build")
            if approval is None or (build_plan is not None and build_approval is None):
                results.append(MutationResult(
                    spec.mutation_id, spec.subject, spec.mutation_kind, spec.patch_sha256,
                    None, None, (), "not_approved", plan.approval_digest,
                ))
                reason = reason or "not_approved"
                continue
            if build_plan is not None:
                build_completed, build_execution_error = execute_approved_plan(build_plan, build_approval)
                if build_completed is None or build_completed.returncode != 0:
                    results.append(MutationResult(spec.mutation_id, spec.subject, spec.mutation_kind, spec.patch_sha256, False, None, (), "invalid_mutant" if build_completed is not None else build_execution_error or "build_failed"))
                    reason = reason or ("invalid_mutant" if build_completed is not None else build_execution_error or "build_failed")
                    continue
            completed, execution_error = execute_approved_plan(plan, approval)
            if completed is None:
                results.append(MutationResult(spec.mutation_id, spec.subject, spec.mutation_kind, spec.patch_sha256, None, None, (), execution_error or "execution_failed", plan.approval_digest))
                reason = reason or execution_error or "execution_failed"
                continue
            output = redact_sensitive_text(((completed.stdout or "") + (completed.stderr or ""))[:output_limit])
            # Source validity is established before planning. A non-zero
            # test command means that the valid mutant was killed, not that
            # the mutant failed to build. Build failures are excluded during
            # generation rather than being counted as killed mutants.
            build_valid = True
            killed = completed.returncode != 0
            results.append(MutationResult(
                spec.mutation_id, spec.subject, spec.mutation_kind, spec.patch_sha256,
                build_valid, killed, _killing_tests(output, test_selection) if killed else (),
                None if completed.returncode == 0 else "mutant_killed", plan.approval_digest,
            ))
            _ = bounded_fingerprint(output)
    status = "complete" if all(item.reason_code != "not_approved" for item in results) and not reason else "planned" if reason == "not_approved" else "partial"
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
