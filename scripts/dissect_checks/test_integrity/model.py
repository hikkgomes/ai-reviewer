"""Frozen, bounded records used by the test-integrity workflows."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


PUBLIC_STATES = frozenset({"Finding", "Checked", "Not applicable", "Not verified"})
INTERNAL_STATES = frozenset({"complete", "partial", "not_applicable", "planned", "unavailable", "failed"})
SCENARIO_IDS = (
    "base-code-base-tests",
    "base-code-head-tests",
    "head-code-base-tests",
    "head-code-head-tests",
)
REACHABILITY_STATES = frozenset({"confirmed", "not_reached", "unverified"})
ARTIFACT_ROLES = frozenset({
    "test", "test helper", "fixture", "snapshot or golden file",
    "test configuration", "CI test command", "production source",
    "test tooling", "shared build or manifest file", "documentation",
})
USEFULNESS_DIMENSIONS = (
    "collects_or_compiles",
    "passes_on_head",
    "reaches_focal_subject",
    "distinguishes_base_and_head",
    "kills_targeted_valid_mutant",
    "uses_independent_oracle",
    "has_explicit_contract_source",
    "stable_across_repeated_runs",
    "covers_unique_boundary",
    "has_unique_mutation_kill_set",
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
    if allow_empty and value == "":
        return True
    return isinstance(value, str) and len(value) == SHA256_LENGTH and all(
        char in "0123456789abcdef" for char in value
    )


def _check_location(path: str, start: int, end: int) -> None:
    path_object = Path(path.replace("\\", "/"))
    if (
        not path
        or path_object.is_absolute()
        or not path_object.parts
        or ".." in path_object.parts
        or isinstance(start, bool)
        or isinstance(end, bool)
        or not isinstance(start, int)
        or not isinstance(end, int)
        or start < 1
        or end < start
    ):
        raise ValueError("test evidence locations must have a path and positive line range")


@dataclass(frozen=True)
class TestArtifact:
    logical_path: str
    framework_id: str
    role: str
    source_kind: str
    content_sha256: str
    uncertainty: str = ""
    classification_evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.logical_path or not self.framework_id or not self.role or not self.source_kind:
            raise ValueError("test artefacts require path, framework, role, and source layer")
        if self.role not in ARTIFACT_ROLES:
            raise ValueError("test artefact role is not recognised")
        if not isinstance(self.uncertainty, str) or len(self.uncertainty) > 512:
            raise ValueError("test artefact uncertainty must be a bounded string")
        path = Path(self.logical_path.replace("\\", "/"))
        if path.is_absolute() or not path.parts or ".." in path.parts:
            raise ValueError("test artefact path must be repository-relative")
        if not _valid_hash(self.content_sha256):
            raise ValueError("test artefact content_sha256 must be a lowercase SHA-256")
        if any(not isinstance(item, str) or not item for item in self.classification_evidence):
            raise ValueError("test artefact classification evidence must contain non-empty strings")

    @property
    def artifact_id(self) -> str:
        return digest_payload(asdict(self), prefix="test-artifact-")

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["id"] = self.artifact_id
        value["classification_evidence"] = list(self.classification_evidence)
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
    usefulness: Mapping[str, Any] = field(default_factory=lambda: {
        key: None for key in USEFULNESS_DIMENSIONS
    })

    def __post_init__(self) -> None:
        if not self.change_kinds:
            raise ValueError("test changes require at least one change kind")
        if not isinstance(self.test, TestArtifact):
            raise ValueError("test changes require a test artefact")
        if any(not isinstance(item, TestSubject) for item in self.affected_subjects):
            raise ValueError("test changes require test subject records")
        if any(not isinstance(item, Mapping) for item in self.evidence):
            raise ValueError("test change evidence must contain mappings")
        if (
            not isinstance(self.oracle_source, Mapping)
            or not isinstance(self.oracle_source.get("kind"), str)
            or not self.oracle_source.get("kind")
            or not isinstance(self.oracle_source.get("reference"), str)
            or not self.oracle_source.get("reference")
        ):
            raise ValueError("test changes require an oracle source record")

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
            "usefulness": {key: self.usefulness.get(key) for key in USEFULNESS_DIMENSIONS},
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
    reachability: str = "unverified"
    reached_subjects: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.scenario_id not in SCENARIO_IDS:
            raise ValueError(f"unknown test evidence scenario: {self.scenario_id}")
        if self.reachability not in REACHABILITY_STATES:
            raise ValueError("test run reachability state is invalid")
        if any(not isinstance(item, str) or not item for item in self.reached_subjects):
            raise ValueError("reached subject IDs must be non-empty strings")
        if not self.completed and self.reachability != "unverified":
            raise ValueError("incomplete test runs cannot claim reachability")
        if self.reachability == "confirmed" and not self.reached_subjects:
            raise ValueError("confirmed reachability requires reached subject IDs")
        if self.reachability == "not_reached" and self.reached_subjects:
            raise ValueError("not_reached results cannot contain reached subject IDs")
        if any(not isinstance(item, str) or not item for item in self.selected_tests):
            raise ValueError("selected test identifiers must be non-empty strings")
        if self.command_plan_digest and not _valid_hash(self.command_plan_digest):
            raise ValueError("command_plan_digest must be a lowercase SHA-256")
        if self.collected_tests is not None and (
            isinstance(self.collected_tests, bool)
            or not isinstance(self.collected_tests, int)
            or self.collected_tests < 0
        ):
            raise ValueError("collected_tests must be a non-negative integer")
        if not isinstance(self.completed, bool):
            raise ValueError("completed must be a boolean")
        if self.passed is not None and not isinstance(self.passed, bool):
            raise ValueError("passed must be a boolean or null")
        if self.completed and self.exit_code is None:
            raise ValueError("completed test runs require an exit code")
        if self.completed and not isinstance(self.passed, bool):
            raise ValueError("completed test runs require a boolean passed result")
        if self.completed and not _valid_hash(self.command_plan_digest):
            raise ValueError("completed test runs require an approval plan digest")
        if self.completed and not _valid_hash(self.output_fingerprint):
            raise ValueError("completed test runs require an output fingerprint")
        if not self.completed and self.passed is not None:
            raise ValueError("incomplete test runs must not have a passed result")
        if self.exit_code is not None and (isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)):
            raise ValueError("test run exit_code must be an integer or null")
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
        value["reached_subjects"] = list(self.reached_subjects)
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
    build_command_plan_digest: str = ""

    def __post_init__(self) -> None:
        if not self.mutation_id or not self.mutation_kind or not _valid_hash(self.patch_sha256):
            raise ValueError("mutation results require an ID, kind, and SHA-256 patch")
        if not isinstance(self.subject, TestSubject):
            raise ValueError("mutation results require a test subject record")
        if any(not isinstance(item, str) or not item for item in self.killing_tests):
            raise ValueError("mutation killing tests must contain non-empty strings")
        if self.command_plan_digest and not _valid_hash(self.command_plan_digest):
            raise ValueError("command_plan_digest must be a lowercase SHA-256")
        if self.build_command_plan_digest and not _valid_hash(self.build_command_plan_digest):
            raise ValueError("build_command_plan_digest must be a lowercase SHA-256")
        if self.build_valid is not None and not isinstance(self.build_valid, bool):
            raise ValueError("mutation build_valid must be boolean or null")
        if self.killed is not None and not isinstance(self.killed, bool):
            raise ValueError("mutation killed must be boolean or null")
        if self.build_valid is not True and self.killed is not None:
            raise ValueError("an unbuilt or invalid mutant cannot have a killed result")
        if self.killed is not True and self.killing_tests:
            raise ValueError("killing tests require a killed mutant")
        if self.killed is not None and not _valid_hash(self.command_plan_digest):
            raise ValueError("executed mutation results require a command plan digest")

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
