from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import hashlib
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from analysis_budget import AnalysisBudget, AnalysisBudgetExceeded


@dataclass(frozen=True)
class AnalysisTarget:
    logical_path: str
    physical_path: Path
    language_id: str
    source_kind: str = "working-tree"
    revision: str = "WORKTREE"
    content_sha256: str = ""
    changed_ranges: tuple[tuple[int, int], ...] | None = None
    data: bytes | None = field(default=None, repr=False, compare=False)
    config_variant: str = ""
    manifest_path: str = ""
    manifest_source_layer: str = ""
    manifest_sha256: str = ""

    @property
    def target_id(self) -> str:
        return "|".join((self.logical_path, self.source_kind, self.content_sha256))


@dataclass(frozen=True)
class LoadedAnalysisTarget:
    """One bounded source read shared by all selected anti-slop backends."""

    target: AnalysisTarget
    data: bytes
    content_sha256: str

    @property
    def logical_path(self) -> str:
        return self.target.logical_path

    @property
    def physical_path(self) -> Path:
        return self.target.physical_path

    @property
    def language_id(self) -> str:
        return self.target.language_id

    @property
    def source_kind(self) -> str:
        return self.target.source_kind

    @property
    def revision(self) -> str:
        return self.target.revision

    @property
    def changed_ranges(self) -> tuple[tuple[int, int], ...] | None:
        return self.target.changed_ranges

    @property
    def config_variant(self) -> str:
        return self.target.config_variant

    @property
    def manifest_path(self) -> str:
        return self.target.manifest_path

    @property
    def manifest_source_layer(self) -> str:
        return self.target.manifest_source_layer

    @property
    def manifest_sha256(self) -> str:
        return self.target.manifest_sha256

    def as_target(self) -> AnalysisTarget:
        return replace_target_hash(self.target, self.content_sha256)


def replace_target_hash(target: AnalysisTarget, content_sha256: str) -> AnalysisTarget:
    """Return the immutable target with the hash from its loaded bytes."""
    return AnalysisTarget(
        target.logical_path, target.physical_path, target.language_id,
        target.source_kind, target.revision, content_sha256,
        target.changed_ranges, target.data, target.config_variant,
        target.manifest_path, target.manifest_source_layer, target.manifest_sha256,
    )


def load_target(
    root: Path,
    target: AnalysisTarget,
    budget: AnalysisBudget,
    *,
    max_file_bytes: int,
) -> LoadedAnalysisTarget:
    """Read one target after claiming its file and byte budget.

    Snapshot callers may provide immutable bytes directly. Physical files use
    their stat size to claim the aggregate byte quota before opening the file,
    so a large or exhausted target is rejected without an unaccounted read.
    """
    if max_file_bytes <= 0:
        raise ValueError("max_file_bytes must be greater than zero")
    budget.claim_file()
    root_resolved = root.resolve()
    if target.data is not None:
        data = bytes(target.data)
        if len(data) > max_file_bytes:
            if max_file_bytes:
                budget.claim_bytes(max_file_bytes)
            raise AnalysisBudgetExceeded("max_file_bytes", "source file exceeds the structural analysis limit")
        budget.claim_bytes(len(data))
    else:
        physical = target.physical_path.resolve()
        try:
            physical.relative_to(root_resolved)
        except ValueError:
            source_layers = set(target.source_kind.split("+"))
            if not source_layers <= {"commit", "index"}:
                raise ValueError("loaded source path escapes the review root")
        try:
            size = physical.stat().st_size
        except OSError as error:
            raise OSError(f"could not stat source file: {error}") from error
        if size > max_file_bytes:
            raise AnalysisBudgetExceeded("max_file_bytes", "source file exceeds the structural analysis limit")
        budget.claim_bytes(size)
        try:
            with physical.open("rb") as source_file:
                data = source_file.read(size)
        except OSError:
            raise
        if len(data) != size or physical.stat().st_size != size:
            raise OSError("source file changed during bounded read")
    if b"\0" in data[:4096]:
        raise AnalysisBudgetExceeded("binary_source", "NUL byte in source prefix")
    digest = hashlib.sha256(data).hexdigest()
    if target.content_sha256 and target.content_sha256 != digest:
        raise AnalysisBudgetExceeded("content_hash_mismatch", "loaded source differs from its declared snapshot hash")
    normalised = replace_target_hash(target, digest)
    return LoadedAnalysisTarget(normalised, data, digest)


def canonical_diagnostic_identity(diagnostic: "BackendDiagnostic") -> str:
    """Return the exact evidence identity used for candidate deduplication."""
    metadata = dict(diagnostic.metadata)
    nested = metadata.get("metadata")
    nested_map = nested if isinstance(nested, Mapping) else {}
    discriminator = (
        metadata.get("rule_discriminator")
        or metadata.get("discriminator")
        or nested_map.get("rule_discriminator")
        or nested_map.get("discriminator")
        or diagnostic.message
    )
    if isinstance(discriminator, (Mapping, list, tuple)):
        discriminator_value = canonical_json(discriminator)
    else:
        discriminator_value = str(discriminator)
    payload = {
        "backend_id": diagnostic.backend_id,
        "rule_id": diagnostic.rule_id,
        "logical_path": diagnostic.path,
        "source_layer": metadata.get("source_layer", nested_map.get("source_layer", "working-tree")),
        "content_sha256": metadata.get("content_sha256", nested_map.get("content_sha256", "")),
        "line": diagnostic.line,
        "column": diagnostic.column,
        "rule_discriminator": discriminator_value,
    }
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def diagnostic_identity_digest(diagnostic: "BackendDiagnostic") -> str:
    return hashlib.sha256(canonical_diagnostic_identity(diagnostic).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class BackendDiagnostic:
    backend_id: str
    language_id: str
    rule_id: str
    path: str
    line: int
    column: int
    message: str
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class BackendResult:
    backend_id: str
    level: str
    languages: tuple[str, ...]
    status: str
    applicable_files: int
    checked_files: int
    skipped_files: int
    diagnostics: list[BackendDiagnostic] = field(default_factory=list)
    reason_code: str | None = None
    reason: str = ""
    parse_states: dict[str, str] = field(default_factory=dict)
    parse_errors: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.status not in {"complete", "not_applicable", "partial", "unavailable", "failed"}:
            raise ValueError(f"invalid backend status: {self.status}")
        if any(value < 0 for value in (self.applicable_files, self.checked_files, self.skipped_files)):
            raise ValueError("backend file counts must not be negative")
        if self.checked_files + self.skipped_files > self.applicable_files:
            raise ValueError("backend checked and skipped files exceed applicable files")

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["diagnostics"] = [asdict(item) for item in self.diagnostics]
        return value


class AntiSlopBackend(Protocol):
    backend_id: str
    languages: tuple[str, ...]

    def analyse(
        self,
        root: Path,
        targets: Sequence[AnalysisTarget],
        budget: AnalysisBudget,
    ) -> BackendResult:
        ...
