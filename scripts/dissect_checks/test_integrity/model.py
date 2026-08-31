"""Frozen, bounded records used by the test-integrity workflows."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from typing import Any, Mapping


PUBLIC_STATES = frozenset({"Finding", "Checked", "Not applicable", "Not verified"})
INTERNAL_STATES = frozenset({"complete", "partial", "not_applicable", "planned", "unavailable", "failed"})
SCENARIO_IDS = (
    "base-code-base-tests",
    "base-code-head-tests",
    "head-code-base-tests",
    "head-code-head-tests",
)
SHA256_LENGTH = 64


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def digest_payload(value: Any, *, prefix: str = "") -> str:
    digest = hashlib.sha256(canonical_json(value).encode("utf-8", errors="surrogatepass")).hexdigest()
    return f"{prefix}{digest[:24]}" if prefix else digest


def _valid_hash(value: str, *, allow_empty: bool = False) -> bool:
    return allow_empty and value == "" or len(value) == SHA256_LENGTH and all(char in "0123456789abcdef" for char in value)


def _check_location(path: str, start: int, end: int) -> None:
    if not path or start < 1 or end < start:
        raise ValueError("test evidence locations must have a path and positive line range")


@dataclass(frozen=True)
class TestArtifact:
    logical_path: str
    framework_id: str
    role: str
    source_kind: str
    content_sha256: str
    uncertainty: str = ""

    def __post_init__(self) -> None:
        if not self.logical_path or not self.framework_id or not self.role or not self.source_kind:
            raise ValueError("test artefacts require path, framework, role, and source layer")
        if not _valid_hash(self.content_sha256):
            raise ValueError("test artefact content_sha256 must be a lowercase SHA-256")

    @property
    def artifact_id(self) -> str:
        return digest_payload(asdict(self), prefix="test-artifact-")

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["id"] = self.artifact_id
        return value


@dataclass(frozen=True)
class TestSubject:
    logical_path: str
    qualified_name: str
    start_line: int
    end_line: int
    source_kind: str
    content_sha256: str

    def __post_init__(self) -> None:
        _check_location(self.logical_path, self.start_line, self.end_line)
        if not self.qualified_name or not self.source_kind or not _valid_hash(self.content_sha256):
            raise ValueError("test subjects require a qualified name, source layer, and SHA-256")

    @property
    def subject_id(self) -> str:
        return digest_payload(asdict(self), prefix="test-subject-")

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["id"] = self.subject_id
        return value


@dataclass(frozen=True)
class TestChange:
    test: TestArtifact
    change_kinds: tuple[str, ...]
    affected_subjects: tuple[TestSubject, ...]
    evidence: tuple[Mapping[str, Any], ...] = ()
    oracle_source: Mapping[str, str] = field(default_factory=lambda: {
        "kind": "not_recorded",
        "reference": "No independent contract or oracle was attached to this test change.",
    })

    def __post_init__(self) -> None:
        if not self.change_kinds:
            raise ValueError("test changes require at least one change kind")

    @property
    def change_id(self) -> str:
        return digest_payload({
            "test": self.test.artifact_id,
            "change_kinds": self.change_kinds,
            "subjects": [subject.subject_id for subject in self.affected_subjects],
        }, prefix="test-change-")

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.change_id,
            "test": self.test.as_dict(),
            "change_kinds": list(self.change_kinds),
            "affected_subjects": [subject.as_dict() for subject in self.affected_subjects],
            "evidence": [dict(item) for item in self.evidence],
            "oracle_source": dict(self.oracle_source),
        }


@dataclass(frozen=True)
class TestRunResult:
    scenario_id: str
    command_plan_digest: str
    exit_code: int | None
    completed: bool
    passed: bool | None
    collected_tests: int | None
    selected_tests: tuple[str, ...]
    output_fingerprint: str
    reason_code: str | None = None
    production_patch_sha256: str = ""
    test_patch_sha256: str = ""
    shared_config_patch_sha256: str = ""

    def __post_init__(self) -> None:
        if self.scenario_id not in SCENARIO_IDS:
            raise ValueError(f"unknown test evidence scenario: {self.scenario_id}")
        if self.command_plan_digest and not _valid_hash(self.command_plan_digest):
            raise ValueError("command_plan_digest must be a lowercase SHA-256")
        if self.collected_tests is not None and self.collected_tests < 0:
            raise ValueError("collected_tests must not be negative")
        if not isinstance(self.completed, bool):
            raise ValueError("completed must be a boolean")
        if self.passed is not None and not isinstance(self.passed, bool):
            raise ValueError("passed must be a boolean or null")
        if self.completed and self.exit_code is None:
            raise ValueError("completed test runs require an exit code")
        if self.output_fingerprint and not _valid_hash(self.output_fingerprint):
            raise ValueError("output_fingerprint must be a lowercase SHA-256")
        for name, value in (
            ("production_patch_sha256", self.production_patch_sha256),
            ("test_patch_sha256", self.test_patch_sha256),
            ("shared_config_patch_sha256", self.shared_config_patch_sha256),
        ):
            if not _valid_hash(value, allow_empty=True):
                raise ValueError(f"{name} must be a lowercase SHA-256 or empty")

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["selected_tests"] = list(self.selected_tests)
        return value


@dataclass(frozen=True)
class MutationResult:
    mutation_id: str
    subject: TestSubject
    mutation_kind: str
    patch_sha256: str
    build_valid: bool | None
    killed: bool | None
    killing_tests: tuple[str, ...]
    reason_code: str | None = None
    command_plan_digest: str = ""

    def __post_init__(self) -> None:
        if not self.mutation_id or not self.mutation_kind or not _valid_hash(self.patch_sha256):
            raise ValueError("mutation results require an ID, kind, and SHA-256 patch")
        if self.command_plan_digest and not _valid_hash(self.command_plan_digest):
            raise ValueError("command_plan_digest must be a lowercase SHA-256")

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["subject"] = self.subject.as_dict()
        value["killing_tests"] = list(self.killing_tests)
        return value


def public_state(internal_state: str, *, applicable: bool = True) -> str:
    if internal_state == "not_applicable" or not applicable:
        return "Not applicable"
    if internal_state == "complete":
        return "Checked"
    return "Not verified"


def bounded_fingerprint(output: str | bytes, *, limit: int = 64 * 1024) -> str:
    data = output if isinstance(output, bytes) else output.encode("utf-8", errors="replace")
    return hashlib.sha256(data[:limit]).hexdigest()


def as_json_value(value: Any) -> Any:
    if hasattr(value, "as_dict"):
        return value.as_dict()
    if isinstance(value, Mapping):
        return {str(key): as_json_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [as_json_value(item) for item in value]
    if isinstance(value, list):
        return [as_json_value(item) for item in value]
    return value
