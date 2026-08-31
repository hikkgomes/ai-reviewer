"""Inert, approval-bound proof-test workflow for one review candidate."""
from __future__ import annotations

from dataclasses import dataclass
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
from typing import Any, Mapping, Sequence

from dissect_checks.execution_plan import ExecutionPlan, build_execution_plan, execute_approved_plan
from dissect_checks.redaction import redact_sensitive_text
from .model import bounded_fingerprint


ORACLE_KINDS = frozenset({"user_intent", "public_contract", "existing_invariant", "external_spec", "independent_reference"})
OUTCOMES = frozenset({"disproved", "supported", "inconclusive"})
_DIFF_PATH_RE = re.compile(r"^(?:\+\+\+|---) [ab]/(.+)$", re.M)


@dataclass(frozen=True)
class ProofCandidate:
    candidate_id: str
    claimed_contract: str
    oracle_kind: str
    oracle_reference: str
    focal_subjects: tuple[str, ...]
    expected_current_result: str
    control: str

    def __post_init__(self) -> None:
        if not self.candidate_id or not self.claimed_contract or self.oracle_kind not in ORACLE_KINDS or not self.oracle_reference:
            raise ValueError("proof candidate requires an independent oracle and contract")
        if self.expected_current_result not in {"pass", "fail"}:
            raise ValueError("expected_current_result must be pass or fail")
        if self.control not in {"base", "known_good", "targeted_mutant"}:
            raise ValueError("proof candidate control is invalid")


@dataclass(frozen=True)
class ProofTestPlan:
    candidate: ProofCandidate
    test_patch_sha256: str
    changed_paths: tuple[str, ...]
    plan: ExecutionPlan | None
    status: str
    reason_code: str | None = None
    temporary_directory: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate.candidate_id,
            "claimed_contract": self.candidate.claimed_contract,
            "oracle_source": {
                "kind": self.candidate.oracle_kind,
                "reference": self.candidate.oracle_reference,
            },
            "focal_subjects": list(self.candidate.focal_subjects),
            "expected_current_result": self.candidate.expected_current_result,
            "control": self.candidate.control,
            "test_patch_sha256": self.test_patch_sha256,
            "changed_paths": list(self.changed_paths),
            "plan": self.plan.redacted_payload() if self.plan is not None else None,
            "status": self.status,
            "reason_code": self.reason_code,
        }

    def close(self) -> None:
        if self.temporary_directory:
            shutil.rmtree(self.temporary_directory, ignore_errors=True)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


@dataclass(frozen=True)
class ProofTestResult:
    outcome: str
    current_result: str | None
    control_result: str | None
    reachability: str
    test_patch_sha256: str
    command_plan_digest: str
    output_fingerprint: str
    reason_code: str | None = None
    candidate_id: str = ""
    oracle_kind: str = ""
    focal_subjects: tuple[str, ...] = ()
    oracle_reference: str = ""
    expected_current_result: str = ""
    control: str = ""

    def __post_init__(self) -> None:
        if self.outcome not in OUTCOMES:
            raise ValueError("invalid proof-test outcome")
        if self.reachability not in {"confirmed", "unverified", "not_reached"}:
            raise ValueError("invalid proof-test reachability state")
        for name, value in (
            ("test_patch_sha256", self.test_patch_sha256),
            ("command_plan_digest", self.command_plan_digest),
            ("output_fingerprint", self.output_fingerprint),
        ):
            if value and (len(value) != 64 or any(char not in "0123456789abcdef" for char in value)):
                raise ValueError(f"{name} must be a lowercase SHA-256")

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "proof_test",
            "candidate_id": self.candidate_id,
            "oracle_kind": self.oracle_kind,
            "oracle_reference": self.oracle_reference,
            "focal_subjects": list(self.focal_subjects),
            "expected_current_result": self.expected_current_result,
            "control": self.control,
            "outcome": self.outcome,
            "current_result": self.current_result,
            "control_result": self.control_result,
            "reachability": self.reachability,
            "test_patch_sha256": self.test_patch_sha256,
            "command_plan_digest": self.command_plan_digest,
            "output_fingerprint": self.output_fingerprint,
            "reason_code": self.reason_code,
        }


def patch_sha256(patch: str | bytes) -> str:
    data = patch if isinstance(patch, bytes) else patch.encode("utf-8", errors="surrogatepass")
    return hashlib.sha256(data).hexdigest()


def changed_patch_paths(patch: str) -> tuple[str, ...]:
    paths: set[str] = set()
    for raw in _DIFF_PATH_RE.findall(patch):
        path = Path(raw).as_posix()
        if path not in {"/dev/null", "dev/null"}:
            paths.add(path)
    return tuple(sorted(paths))


def _is_test_path(path: str) -> bool:
    lower = path.lower().replace("\\", "/")
    name = Path(lower).name
    return bool(
        re.search(r"(?:^|/)(?:test|tests|spec|specs|fixtures?|testdata|__tests__)(?:/|$)", lower)
        or re.search(r"(?:^|[._-])(?:test|spec)(?:[._-]|$)", name)
        or name.endswith("_test.go")
    )


def _is_ci_path(path: str) -> bool:
    return path.startswith(".github/") or path.startswith(".gitlab/") or path.endswith((".yml", ".yaml")) and "ci" in path.lower()


def _apply_patch(root: Path, patch: str) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ["git", "apply", "--whitespace=nowarn", "-"],
            cwd=root, input=patch, text=True, capture_output=True, check=False,
        )
    except OSError as error:
        return False, str(error)
    return result.returncode == 0, redact_sensitive_text((result.stderr or result.stdout or "")[:500])


def _source_files(root: Path, paths: Sequence[str]) -> dict[str, str]:
    output: dict[str, str] = {}
    for path in paths:
        try:
            output[path] = (root / path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return output


def _source_state_bindings(root: Path, candidate: Mapping[str, Any] | ProofCandidate, paths: Sequence[str]) -> dict[str, str]:
    """Collect bounded source hashes which make a proof plan checkout-specific."""
    values = set(paths)
    if isinstance(candidate, Mapping):
        for evidence in candidate.get("supporting_evidence", ()):
            if isinstance(evidence, Mapping):
                for key in ("file", "path", "logical_path"):
                    value = evidence.get(key)
                    if isinstance(value, str) and value and not Path(value).is_absolute() and ".." not in Path(value).parts:
                        values.add(Path(value).as_posix())
    hashes: dict[str, str] = {}
    for path in sorted(values):
        try:
            data = (root / path).read_bytes()
        except OSError:
            continue
        hashes[path] = hashlib.sha256(data[:5 * 1024 * 1024]).hexdigest()
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=False,
        ).stdout.strip()
    except OSError:
        revision = ""
    return {
        "repository_head": revision,
        "source_hashes": json.dumps(hashes, sort_keys=True, separators=(",", ":")),
    }


def _proof_environment(tree: Path) -> dict[str, str]:
    home = tree / ".dissect-home"
    temp = tree / ".dissect-tmp"
    home.mkdir(parents=True, exist_ok=True)
    temp.mkdir(parents=True, exist_ok=True)
    return {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(home), "TMPDIR": str(temp)}


def _compile_changed(root: Path, paths: Sequence[str]) -> tuple[bool, str | None]:
    for path in paths:
        suffix = Path(path).suffix.lower()
        if suffix in {".py", ".pyi"}:
            try:
                ast.parse((root / path).read_text(encoding="utf-8", errors="replace"), filename=path)
            except (OSError, SyntaxError, ValueError, TypeError) as error:
                return False, "parse_error"
        elif suffix in {".go", ".rs", ".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".java", ".cs", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
            try:
                source = (root / path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                return False, "read_failure"
            if _delimiter_error(source):
                return False, "parse_error"
    return True, None


def _delimiter_error(source: str) -> str | None:
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    index = 0
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char == "/" and next_char == "/":
            line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            block_comment = True
            index += 2
            continue
        if char in {'"', "'", "`"}:
            quote = char
        elif char in pairs:
            stack.append(pairs[char])
        elif char in pairs.values():
            if not stack or stack.pop() != char:
                return "unbalanced_delimiters"
        index += 1
    return "unbalanced_delimiters" if quote or block_comment or stack else None


def validate_test_patch(
    root: Path,
    patch: str,
    candidate: Mapping[str, Any] | ProofCandidate,
    *,
    focal_subjects: Sequence[str] = (),
) -> tuple[bool, tuple[str, ...]]:
    """Validate a proposed patch without writing it to the reviewed checkout."""
    if isinstance(candidate, ProofCandidate):
        proof = candidate
    else:
        oracle = candidate.get("oracle_source") if isinstance(candidate.get("oracle_source"), Mapping) else {}
        try:
            proof = ProofCandidate(
                str(candidate.get("candidate_id", candidate.get("id", ""))),
                str(candidate.get("claimed_contract", candidate.get("contract", ""))),
                str(oracle.get("kind", "")),
                str(oracle.get("reference", "")),
                tuple(str(item) for item in candidate.get("focal_subjects", focal_subjects) if isinstance(item, str)),
                str(candidate.get("expected_current_result", "")),
                str(candidate.get("control", "")),
            )
        except ValueError as error:
            return False, (str(error),)
    paths = changed_patch_paths(patch)
    errors: list[str] = []
    if not paths:
        errors.append("test patch has no changed paths")
    for path in paths:
        if not _is_test_path(path) and not any(token in path.lower() for token in ("fixture", "test-support", "test_helper")):
            errors.append(f"test patch changes a non-test path: {path}")
        if _is_ci_path(path):
            errors.append(f"test patch changes CI configuration: {path}")
    deleted_lines = [line[1:] for line in patch.splitlines() if line.startswith("-") and not line.startswith("---")]
    if any(re.search(r"\b(?:assert|expect|raises|snapshot|Fact|TestMethod|TEST_CASE)\b", line, re.I) for line in deleted_lines):
        errors.append("test patch removes an existing observable check")
    focal = tuple(focal_subjects) or proof.focal_subjects
    lower_patch = patch.lower()
    for subject in focal:
        name = subject.rsplit(".", 1)[-1].lower()
        if name and re.search(rf"\b(?:mock|patch|spy|stub|monkeypatch)\b[^\n]*\b{re.escape(name)}\b", lower_patch):
            errors.append(f"test patch mocks or bypasses focal subject: {subject}")
    if not re.search(r"\b(?:assert|expect|raises|snapshot|asserts|Fact|TestMethod|TEST_CASE|EXPECT_|ASSERT_)\b", patch, re.I):
        errors.append("test patch has no observable assertion or expected failure")
    if "current implementation output" in proof.oracle_reference.lower():
        errors.append("proof-test oracle must be independent of the current implementation")
    return not errors, tuple(dict.fromkeys(errors))


def build_proof_test_plan(
    root: Path,
    patch: str,
    candidate: Mapping[str, Any] | ProofCandidate,
    *,
    command: str | None = None,
    timeout_seconds: float = 120,
    output_limit: int = 64 * 1024,
) -> ProofTestPlan:
    valid, errors = validate_test_patch(root, patch, candidate)
    if isinstance(candidate, ProofCandidate):
        proof = candidate
    else:
        oracle = candidate.get("oracle_source") if isinstance(candidate.get("oracle_source"), Mapping) else {}
        proof = ProofCandidate(
            str(candidate.get("candidate_id", candidate.get("id", ""))),
            str(candidate.get("claimed_contract", candidate.get("contract", ""))),
            str(oracle.get("kind", "")), str(oracle.get("reference", "")),
            tuple(str(item) for item in candidate.get("focal_subjects", ()) if isinstance(item, str)),
            str(candidate.get("expected_current_result", "")), str(candidate.get("control", "")),
        )
    digest = patch_sha256(patch)
    paths = changed_patch_paths(patch)
    if not valid:
        return ProofTestPlan(proof, digest, paths, None, "failed", "invalid_test_patch: " + "; ".join(errors))
    if not command:
        return ProofTestPlan(proof, digest, paths, None, "planned", "command_not_configured")
    try:
        argv = shlex.split(command)
    except ValueError:
        return ProofTestPlan(proof, digest, paths, None, "failed", "invalid_test_command")
    directory = tempfile.mkdtemp(prefix="dissect-proof-plan-")
    tree = Path(directory)
    try:
        shutil.copytree(root, tree, ignore=shutil.ignore_patterns(".git", "node_modules", "__pycache__", "*.pyc", "target"), dirs_exist_ok=True)
        valid_apply, _detail = _apply_patch(tree, patch)
        if not valid_apply:
            shutil.rmtree(directory, ignore_errors=True)
            return ProofTestPlan(proof, digest, paths, None, "failed", "patch_application_failed")
        valid_source, reason = _compile_changed(tree, paths)
        if not valid_source:
            shutil.rmtree(directory, ignore_errors=True)
            return ProofTestPlan(proof, digest, paths, None, "failed", reason or "parse_error")
        plan, error = build_execution_plan(
            kind="test-evidence",
            name=f"proof-test:{proof.candidate_id}",
            argv=argv,
            working_directory=tree,
            timeout_seconds=timeout_seconds,
            output_limit=output_limit,
            environment=_proof_environment(tree),
            bindings={
                "candidate_id": proof.candidate_id,
                "test_patch_sha256": digest,
                "focal_subjects": "\0".join(proof.focal_subjects),
                **_source_state_bindings(root, candidate, paths),
            },
        )
    except OSError:
        shutil.rmtree(directory, ignore_errors=True)
        return ProofTestPlan(proof, digest, paths, None, "failed", "private_worktree_failure")
    if plan is None:
        shutil.rmtree(directory, ignore_errors=True)
        return ProofTestPlan(proof, digest, paths, None, "planned", error or "plan_unavailable")
    return ProofTestPlan(proof, digest, paths, plan, "planned", "not_approved", directory)


def execute_proof_test(
    plan: ProofTestPlan,
    approval_digest: str | None,
    *,
    control_plan: ProofTestPlan | None = None,
    control_approval_digest: str | None = None,
    reachability: str = "unverified",
) -> ProofTestResult:
    """Execute current and independent-control plans, then remove private trees."""
    current_result: subprocess.CompletedProcess[str] | None = None
    control_result: subprocess.CompletedProcess[str] | None = None
    reason: str | None = None
    try:
        if plan.plan is None or not approval_digest:
            reason = plan.reason_code or "not_approved"
        else:
            current_result, reason = execute_approved_plan(plan.plan, approval_digest)
        if reason is None and control_plan is not None:
            if control_plan.plan is None or not control_approval_digest:
                reason = control_plan.reason_code or "control_not_approved"
            else:
                control_result, reason = execute_approved_plan(control_plan.plan, control_approval_digest)
        current_passed = current_result is not None and current_result.returncode == 0
        control_passed = control_result is not None and control_result.returncode == 0
        output = ""
        for completed in (current_result, control_result):
            if completed is not None:
                output += (completed.stdout or "") + (completed.stderr or "")
        outcome = proof_outcome(
            plan.candidate,
            current_passed=current_passed if current_result is not None else None,
            control_passed=control_passed if control_result is not None else None,
            reachability=reachability,
        )
        if reason is not None:
            outcome = "inconclusive"
        return ProofTestResult(
            outcome,
            "pass" if current_result is not None and current_passed else "fail" if current_result is not None else None,
            "pass" if control_result is not None and control_passed else "fail" if control_result is not None else None,
            reachability,
            plan.test_patch_sha256,
            plan.plan.approval_digest if plan.plan is not None else "",
            bounded_fingerprint(redact_sensitive_text(output)),
            reason,
            plan.candidate.candidate_id,
            plan.candidate.oracle_kind,
            plan.candidate.focal_subjects,
            plan.candidate.oracle_reference,
            plan.candidate.expected_current_result,
            plan.candidate.control,
        )
    finally:
        plan.close()
        if control_plan is not None:
            control_plan.close()


def proof_outcome(
    candidate: ProofCandidate,
    *,
    current_passed: bool | None,
    control_passed: bool | None,
    reachability: str,
) -> str:
    if reachability != "confirmed" or current_passed is None or control_passed is None:
        return "inconclusive"
    if candidate.expected_current_result == "fail" and current_passed:
        return "disproved"
    if candidate.expected_current_result == "pass" and not current_passed:
        return "supported" if control_passed else "inconclusive"
    if current_passed != control_passed:
        return "supported" if not current_passed and control_passed else "disproved"
    return "inconclusive"
