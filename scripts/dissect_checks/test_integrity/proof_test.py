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
from .model import bounded_fingerprint, digest_payload
from ..source_validation import balanced_delimiter_error


ORACLE_KINDS = frozenset({"user_intent", "public_contract", "existing_invariant", "external_spec", "independent_reference"})
OUTCOMES = frozenset({"disproved", "supported", "inconclusive"})
_DIFF_PATH_RE = re.compile(r"^(?:\+\+\+|---) [ab]/(.+)$", re.M)
MAX_PROOF_PATCH_BYTES = 1024 * 1024


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
        if len(self.candidate_id) > 512 or len(self.claimed_contract) > 8_000 or len(self.oracle_reference) > 8_000:
            raise ValueError("proof candidate contract and oracle reference must be bounded")
        if not self.focal_subjects:
            raise ValueError("proof candidate requires at least one focal subject")
        if len(self.focal_subjects) > 32 or any(len(item) > 512 for item in self.focal_subjects):
            raise ValueError("proof candidate focal subjects must be bounded")
        if self.expected_current_result not in {"pass", "fail"}:
            raise ValueError("expected_current_result must be pass or fail")
        if self.control not in {"base", "known_good", "targeted_mutant"}:
            raise ValueError("proof candidate control is invalid")


@dataclass(frozen=True)
class _InvalidProofCandidate:
    """Retain rejected metadata so the inert plan can report why it failed."""

    candidate_id: str
    claimed_contract: str
    oracle_kind: str
    oracle_reference: str
    focal_subjects: tuple[str, ...]
    expected_current_result: str
    control: str


@dataclass(frozen=True)
class ProofTestPlan:
    candidate: ProofCandidate | _InvalidProofCandidate
    test_patch_sha256: str
    changed_paths: tuple[str, ...]
    plan: ExecutionPlan | None
    status: str
    reason_code: str | None = None
    temporary_directory: str = ""
    source_hashes: tuple[tuple[str, str], ...] = ()
    reviewed_root: str = ""
    reviewed_source_hashes: tuple[tuple[str, str], ...] = ()

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
            "source_hashes": {key: value for key, value in self.source_hashes},
            "reviewed_source_hashes": {key: value for key, value in self.reviewed_source_hashes},
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
        if self.outcome in {"disproved", "supported"}:
            if self.reachability != "confirmed" or self.current_result not in {"pass", "fail"} or self.control_result not in {"pass", "fail"}:
                raise ValueError("completed proof-test results require confirmed reachability and both outcomes")
            if not self.candidate_id or self.oracle_kind not in ORACLE_KINDS or not self.oracle_reference:
                raise ValueError("completed proof-test results require an independent oracle and candidate")

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
        path = Path(raw.replace("\\", "/")).as_posix()
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


def _is_test_support_path(path: str) -> bool:
    """Recognise test configuration and support files allowed in a proof patch."""
    lower = path.lower().replace("\\", "/")
    name = Path(lower).name
    return (
        _is_test_path(lower)
        or name in {
            "pytest.ini", "tox.ini", "conftest.py", "jest.config.js", "jest.config.cjs",
            "jest.config.ts", "vitest.config.js", "vitest.config.ts", "vitest.config.mjs",
        }
        or any(token in lower for token in ("test_helper", "test-support", "/helpers/", "/support/"))
    )


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
            physical = (root / path).resolve()
            physical.relative_to(root.resolve())
            size = physical.stat().st_size
            if size > 5 * 1024 * 1024:
                continue
            with physical.open("rb") as handle:
                data = handle.read(size)
            if len(data) == size and physical.stat().st_size == size:
                output[path] = data.decode("utf-8", errors="replace")
        except (OSError, ValueError):
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
        for trigger in candidate.get("trigger_path", ()):
            if not isinstance(trigger, str):
                continue
            path_value = trigger.rsplit(":", 1)[0]
            if path_value and not Path(path_value).is_absolute() and ".." not in Path(path_value).parts:
                values.add(Path(path_value).as_posix())
    hashes: dict[str, str] = {}
    for path in sorted(values):
        try:
            physical = (root / path).resolve()
            physical.relative_to(root.resolve())
            size = physical.stat().st_size
            if size > 5 * 1024 * 1024:
                continue
            with physical.open("rb") as handle:
                data = handle.read(size)
            if len(data) != size or physical.stat().st_size != size:
                continue
        except FileNotFoundError:
            # Bind absence as well as content.  A proof must not become valid
            # merely because a reviewed subject is created after approval.
            hashes[path] = ""
            continue
        except (OSError, ValueError):
            continue
        hashes[path] = hashlib.sha256(data).hexdigest()
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], cwd=root, capture_output=True, text=True, check=False,
        )
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=False,
        ).stdout.strip()
        repository_id = hashlib.sha256(
            top.stdout.strip().encode("utf-8", errors="surrogatepass")
        ).hexdigest() if top.returncode == 0 else ""
    except OSError:
        revision = ""
        repository_id = ""
    return {
        "repository_id": repository_id,
        "repository_head": revision,
        "source_hashes": json.dumps(hashes, sort_keys=True, separators=(",", ":")),
    }


def _source_hash_snapshot(root: Path, paths: Sequence[str]) -> tuple[tuple[str, str], ...] | None:
    """Capture exact live source presence and hashes for approval binding."""
    values: list[tuple[str, str]] = []
    for path in sorted(set(paths)):
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
        except FileNotFoundError:
            values.append((path_object.as_posix(), ""))
            continue
        except (OSError, ValueError):
            return None
        values.append((path_object.as_posix(), hashlib.sha256(data).hexdigest()))
    return tuple(values)


def _reviewed_sources_unchanged(plan: ProofTestPlan) -> bool:
    if not plan.reviewed_root:
        return False
    root = Path(plan.reviewed_root).resolve()
    try:
        if not root.is_dir():
            return False
    except OSError:
        return False
    expected = dict(plan.reviewed_source_hashes)
    observed = _source_hash_snapshot(root, tuple(expected))
    if observed is None or dict(observed) != expected:
        return False
    bindings = dict(plan.plan.bindings) if plan.plan is not None else {}
    expected_head = bindings.get("repository_head")
    if expected_head:
        try:
            current = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        if current.returncode != 0 or current.stdout.strip() != expected_head:
            return False
    return True


def _plan_matches_candidate(plan: ProofTestPlan) -> bool:
    if plan.plan is None:
        return False
    bindings = dict(plan.plan.bindings)
    candidate = plan.candidate
    return (
        bindings.get("candidate_id") == candidate.candidate_id
        and bindings.get("test_patch_sha256") == plan.test_patch_sha256
        and bindings.get("oracle_kind") == candidate.oracle_kind
        and bindings.get("oracle_reference") == candidate.oracle_reference
        and bindings.get("expected_current_result") == candidate.expected_current_result
        and bindings.get("control") == candidate.control
        and bindings.get("focal_subjects") == "\0".join(candidate.focal_subjects)
    )


def _candidate_source_paths(candidate: Mapping[str, Any] | ProofCandidate, patch_paths: Sequence[str]) -> tuple[str, ...]:
    values = set(patch_paths)
    if isinstance(candidate, Mapping):
        for evidence in candidate.get("supporting_evidence", ()):
            if not isinstance(evidence, Mapping):
                continue
            for key in ("file", "path", "logical_path"):
                value = evidence.get(key)
                if isinstance(value, str) and value and not Path(value).is_absolute() and ".." not in Path(value).parts:
                    values.add(Path(value).as_posix())
        for trigger in candidate.get("trigger_path", ()):
            if not isinstance(trigger, str):
                continue
            path_value = trigger.rsplit(":", 1)[0]
            if path_value and not Path(path_value).is_absolute() and ".." not in Path(path_value).parts:
                values.add(Path(path_value).as_posix())
    return tuple(sorted(values))


def _proof_environment(tree: Path) -> dict[str, str]:
    home = tree / ".dissect-home"
    temp = tree / ".dissect-tmp"
    home.mkdir(parents=True, exist_ok=True)
    temp.mkdir(parents=True, exist_ok=True)
    return {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(home), "TMPDIR": str(temp)}


def _private_source_hashes(tree: Path, paths: Sequence[str]) -> tuple[tuple[str, str], ...] | None:
    values: list[tuple[str, str]] = []
    for path in sorted(set(paths)):
        path_object = Path(path)
        if path_object.is_absolute() or not path_object.parts or ".." in path_object.parts:
            return None
        physical = (tree / path_object).resolve()
        try:
            physical.relative_to(tree.resolve())
            size = physical.stat().st_size
            if size > 5 * 1024 * 1024:
                return None
            with physical.open("rb") as handle:
                data = handle.read(size)
            if len(data) != size or physical.stat().st_size != size:
                return None
        except (OSError, ValueError):
            return None
        values.append((path_object.as_posix(), hashlib.sha256(data).hexdigest()))
    return tuple(values)


def _private_sources_unchanged(plan: ProofTestPlan) -> bool:
    if not plan.temporary_directory:
        return False
    tree = Path(plan.temporary_directory).resolve()
    observed = _private_source_hashes(tree, tuple(key for key, _value in plan.source_hashes))
    return observed is not None and dict(observed) == dict(plan.source_hashes)


def _compile_changed(root: Path, paths: Sequence[str]) -> tuple[bool, str | None]:
    for path in paths:
        suffix = Path(path).suffix.lower()
        if suffix in {".py", ".pyi"}:
            try:
                source = _source_files(root, [path]).get(path)
                if source is None:
                    return False, "read_failure"
                ast.parse(source, filename=path)
            except (OSError, SyntaxError, ValueError, TypeError) as error:
                return False, "parse_error"
        elif suffix in {".go", ".rs", ".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".java", ".cs", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
            try:
                source = _source_files(root, [path]).get(path)
                if source is None:
                    return False, "read_failure"
            except OSError:
                return False, "read_failure"
            if _delimiter_error(source, path):
                return False, "parse_error"
    return True, None


def _delimiter_error(source: str, path: str = "proof-test.py") -> str | None:
    return balanced_delimiter_error(path, source)


def validate_test_patch(
    root: Path,
    patch: str,
    candidate: Mapping[str, Any] | ProofCandidate,
    *,
    focal_subjects: Sequence[str] = (),
) -> tuple[bool, tuple[str, ...]]:
    """Validate a proposed patch without writing it to the reviewed checkout."""
    if not isinstance(patch, str):
        return False, ("test patch must be text",)
    if len(patch.encode("utf-8", errors="surrogatepass")) > MAX_PROOF_PATCH_BYTES:
        return False, ("test patch exceeds the configured size limit",)
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
    if "GIT binary patch" in patch or "\\x00" in patch:
        errors.append("test patch must be a text patch")
    if not paths:
        errors.append("test patch has no changed paths")
    for path in paths:
        path_object = Path(path)
        if path_object.is_absolute() or not path_object.parts or ".." in path_object.parts:
            errors.append(f"test patch path is outside the private checkout: {path}")
            continue
        if not _is_test_support_path(path):
            errors.append(f"test patch changes a non-test path: {path}")
        if _is_ci_path(path):
            errors.append(f"test patch changes CI configuration: {path}")
    deleted_lines = [line[1:] for line in patch.splitlines() if line.startswith("-") and not line.startswith("---")]
    if any(
        re.search(
            r"^\s*(?:(?:async\s+)?def\s+(?:test|spec)[A-Za-z0-9_$-]*|"
            r"(?:test|it|spec)\s*\(|\[(?:Fact|Theory|Test|TestCase|TestMethod)\]|"
            r"(?:TEST|TEST_F|TEST_P|TEST_CASE)\s*\()",
            line,
            re.I,
        )
        for line in deleted_lines
    ):
        errors.append("test patch removes an existing test declaration")
    if any(re.search(r"\b(?:assert|expect|raises|snapshot|Fact|TestMethod|TEST_CASE|fail|verify|check)\b", line, re.I) for line in deleted_lines):
        errors.append("test patch removes an existing observable check")
    added_lines = [line[1:] for line in patch.splitlines() if line.startswith("+") and not line.startswith("+++")]
    if any(re.search(r"\b(?:skip|skipif|xfail|todo|ignore|disabled|continue-on-error|passWithNoTests)\b", line, re.I) for line in added_lines):
        errors.append("test patch weakens discovery or failure behaviour")
    added_text = "\n".join(added_lines)
    if re.search(
        r"\bassert\s+(?:True|False)\b|\bassert\s+([A-Za-z_$][\w$]*)\s*==\s*\1\b|"
        r"\bexpect\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\.to(?:Be|Equal)\s*\(\s*\2\s*\)",
        added_text,
        re.I,
    ):
        errors.append("test patch adds a tautological assertion")
    focal = tuple(focal_subjects) or proof.focal_subjects
    lower_patch = patch.lower()
    compact_patch = re.sub(r"\s+", " ", lower_patch)
    for subject in focal:
        name = subject.rsplit(".", 1)[-1].lower()
        if name and not re.search(rf"\b{re.escape(name)}\b", lower_patch):
            errors.append(f"test patch does not select focal subject: {subject}")
        if name and re.search(
            rf"\b(?:mock|patch|spy|stub|monkeypatch)\b.{{0,160}}\b{re.escape(name)}\b",
            compact_patch,
        ):
            errors.append(f"test patch mocks or bypasses focal subject: {subject}")
        if name and re.search(
            rf"\b{re.escape(name)}\b\s*=\s*(?:mock|magicmock|asyncmock|jest\.fn|vi\.fn|sinon\.)",
            compact_patch,
        ):
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
    digest = patch_sha256(patch)
    paths = changed_patch_paths(patch)
    if isinstance(candidate, ProofCandidate):
        proof = candidate
    else:
        oracle = candidate.get("oracle_source") if isinstance(candidate.get("oracle_source"), Mapping) else {}
        values = (
            str(candidate.get("candidate_id", candidate.get("id", ""))),
            str(candidate.get("claimed_contract", candidate.get("contract", ""))),
            str(oracle.get("kind", "")),
            str(oracle.get("reference", "")),
            tuple(str(item) for item in candidate.get("focal_subjects", ()) if isinstance(item, str)),
            str(candidate.get("expected_current_result", "")),
            str(candidate.get("control", "")),
        )
        try:
            proof = ProofCandidate(*values)
        except ValueError as error:
            invalid = _InvalidProofCandidate(*values)
            reason = "invalid_proof_candidate: " + str(error)
            return ProofTestPlan(invalid, digest, paths, None, "failed", reason)
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
        base_ignore = shutil.ignore_patterns(
            ".git", "node_modules", "__pycache__", "*.pyc", "target",
            ".env", ".env.*", "*.pem", "*.key", "credentials.json", "secrets.json",
        )
        def ignore(directory_name: str, names: list[str]) -> set[str]:
            ignored = set(base_ignore(directory_name, names))
            ignored.update(name for name in names if (Path(directory_name) / name).is_symlink())
            return ignored
        shutil.copytree(
            root,
            tree,
            ignore=ignore,
            dirs_exist_ok=True,
        )
        valid_apply, _detail = _apply_patch(tree, patch)
        if not valid_apply:
            shutil.rmtree(directory, ignore_errors=True)
            return ProofTestPlan(proof, digest, paths, None, "failed", "patch_application_failed")
        valid_source, reason = _compile_changed(tree, paths)
        if not valid_source:
            shutil.rmtree(directory, ignore_errors=True)
            return ProofTestPlan(proof, digest, paths, None, "failed", reason or "parse_error")
        source_paths = _candidate_source_paths(candidate, paths)
        source_hashes = _private_source_hashes(tree, source_paths)
        if source_hashes is None:
            shutil.rmtree(directory, ignore_errors=True)
            return ProofTestPlan(proof, digest, paths, None, "failed", "private_source_unavailable")
        reviewed_source_hashes = _source_state_bindings(root, candidate, paths)
        reviewed_source_values = json.loads(reviewed_source_hashes["source_hashes"])
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
                "claimed_contract": proof.claimed_contract,
                "oracle_kind": proof.oracle_kind,
                "oracle_reference": proof.oracle_reference,
                "expected_current_result": proof.expected_current_result,
                "control": proof.control,
                "test_patch_sha256": digest,
                "focal_subjects": "\0".join(proof.focal_subjects),
                "patched_source_sha256": digest_payload(dict(source_hashes)),
                **reviewed_source_hashes,
            },
        )
    except OSError:
        shutil.rmtree(directory, ignore_errors=True)
        return ProofTestPlan(proof, digest, paths, None, "failed", "private_worktree_failure")
    if plan is None:
        shutil.rmtree(directory, ignore_errors=True)
        return ProofTestPlan(proof, digest, paths, None, "planned", error or "plan_unavailable")
    return ProofTestPlan(
        proof,
        digest,
        paths,
        plan,
        "planned",
        "not_approved",
        directory,
        source_hashes,
        str(root.resolve()),
        tuple(sorted((str(path), str(value)) for path, value in reviewed_source_values.items())),
    )


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
        elif not _plan_matches_candidate(plan):
            reason = "proof_plan_mismatch"
        elif not _reviewed_sources_unchanged(plan):
            reason = "reviewed_source_changed"
        elif not _private_sources_unchanged(plan):
            reason = "source_snapshot_changed"
        else:
            current_result, reason = execute_approved_plan(plan.plan, approval_digest)
        if reason is None and control_plan is not None:
            if control_plan.plan is None or not control_approval_digest:
                reason = control_plan.reason_code or "control_not_approved"
            elif not _plan_matches_candidate(control_plan):
                reason = "control_plan_mismatch"
            elif not _reviewed_sources_unchanged(control_plan):
                reason = "control_reviewed_source_changed"
            elif not _private_sources_unchanged(control_plan):
                reason = "control_source_snapshot_changed"
            else:
                control_result, reason = execute_approved_plan(control_plan.plan, control_approval_digest)
        if reason is None and control_plan is None:
            reason = "control_not_configured"
        current_timed_out = current_result is not None and current_result.returncode == 124
        control_timed_out = control_result is not None and control_result.returncode == 124
        if current_timed_out or control_timed_out:
            reason = reason or "test_timeout"
        current_passed = None if current_timed_out else current_result is not None and current_result.returncode == 0
        control_passed = None if control_timed_out else control_result is not None and control_result.returncode == 0
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
            "pass" if current_passed is True else "fail" if current_passed is False else None,
            "pass" if control_passed is True else "fail" if control_passed is False else None,
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
