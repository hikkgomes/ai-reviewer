from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import hashlib
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from analysis_budget import AnalysisBudget, AnalysisBudgetExceeded


def _valid_sha256(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


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
    physical_snapshot: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.physical_snapshot, bool):
            raise ValueError("physical_snapshot must be a boolean")
        path = Path(self.logical_path.replace("\\", "/"))
        if path.is_absolute() or not path.parts or ".." in path.parts:
            raise ValueError("analysis target logical_path must be repository-relative")
        if not isinstance(self.language_id, str) or not self.language_id:
            raise ValueError("analysis target language_id is required")
        if not isinstance(self.source_kind, str) or not self.source_kind:
            raise ValueError("analysis target source_kind is required")
        if not isinstance(self.revision, str) or not self.revision:
            raise ValueError("analysis target revision is required")
        if self.content_sha256 and not _valid_sha256(self.content_sha256):
            raise ValueError("analysis target content_sha256 must be a lowercase SHA-256")
        if self.manifest_sha256 and not _valid_sha256(self.manifest_sha256):
            raise ValueError("analysis target manifest_sha256 must be a lowercase SHA-256")
        if self.data is not None and not isinstance(self.data, bytes):
            raise ValueError("analysis target data must be bytes")
        if self.changed_ranges is not None:
            for start, end in self.changed_ranges:
                if (
                    isinstance(start, bool) or isinstance(end, bool)
                    or not isinstance(start, int) or not isinstance(end, int)
                    or start < 1 or end < start
                ):
                    raise ValueError("analysis target changed_ranges are invalid")

    @property
    def target_id(self) -> str:
        digest = self.content_sha256
        if not digest and self.data is not None:
            digest = hashlib.sha256(self.data).hexdigest()
        return "|".join((Path(self.logical_path).as_posix(), self.source_kind, digest))


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

    @property
    def physical_snapshot(self) -> bool:
        return self.target.physical_snapshot

    def as_target(self) -> AnalysisTarget:
        return replace_target_hash(self.target, self.content_sha256)


def replace_target_hash(target: AnalysisTarget, content_sha256: str) -> AnalysisTarget:
    """Return the immutable target with the hash from its loaded bytes."""
    return AnalysisTarget(
        target.logical_path, target.physical_path, target.language_id,
        target.source_kind, target.revision, content_sha256,
        target.changed_ranges, target.data, target.config_variant,
        target.manifest_path, target.manifest_source_layer, target.manifest_sha256,
        target.physical_snapshot,
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
    logical = Path(target.logical_path.replace("\\", "/"))
    if logical.is_absolute() or not logical.parts or ".." in logical.parts:
        raise ValueError("loaded source logical path must be repository-relative")
    root_resolved = root.resolve()
    physical = (
        target.physical_path
        if target.physical_path.is_absolute()
        else root_resolved / target.physical_path
    ).resolve()
    try:
        physical.relative_to(root_resolved)
    except ValueError:
        # A source layer may point outside the live checkout only when the
        # caller supplied immutable bytes or explicitly materialised the
        # snapshot.  Merely naming a target ``commit`` or ``index`` must not
        # grant permission to read an arbitrary external path.
        if target.data is None and not target.physical_snapshot:
            raise ValueError("loaded source path escapes the review root")
    if target.data is not None:
        data = bytes(target.data)
        if len(data) > max_file_bytes:
            raise AnalysisBudgetExceeded("max_file_bytes", "source file exceeds the structural analysis limit")
        budget.claim_source(len(data))
    else:
        try:
            size = physical.stat().st_size
        except OSError as error:
            raise OSError(f"could not stat source file: {error}") from error
        if size > max_file_bytes:
            raise AnalysisBudgetExceeded("max_file_bytes", "source file exceeds the structural analysis limit")
        budget.claim_source(size)
        try:
            with physical.open("rb") as source_file:
                # Read one sentinel byte when possible so a file which grows
                # between stat and open cannot be accepted as the old
                # snapshot while its unaccounted tail is ignored.
                data = source_file.read(min(size + 1, max_file_bytes + 1))
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
        discriminator_value = json.dumps(discriminator, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    else:
        discriminator_value = str(discriminator)
    logical_path = Path(diagnostic.path.replace("\\", "/")).as_posix()
    while logical_path.startswith("./"):
        logical_path = logical_path[2:]
    payload = {
        "backend_id": diagnostic.backend_id,
        "rule_id": diagnostic.rule_id,
        "logical_path": logical_path,
        "source_layer": metadata.get("source_layer") or metadata.get("source_kind") or nested_map.get("source_layer") or nested_map.get("source_kind") or "working-tree",
        "content_sha256": metadata.get("content_sha256") or metadata.get("source_sha256") or nested_map.get("content_sha256") or nested_map.get("source_sha256") or "",
        "line": diagnostic.line,
        "column": diagnostic.column,
        "rule_discriminator": discriminator_value,
        "config_variant": metadata.get("config_variant") or nested_map.get("config_variant") or "",
        "manifest_path": metadata.get("manifest_path") or nested_map.get("manifest_path") or "",
        "manifest_sha256": metadata.get("manifest_sha256") or nested_map.get("manifest_sha256") or "",
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
        if any(not isinstance(key, str) or not isinstance(value, str) for key, value in self.parse_states.items()):
            raise ValueError("backend parse states must map string target IDs to string states")
        if any(value not in {"complete", "failed", "not_verified", "not_run"} for value in self.parse_states.values()):
            raise ValueError("backend parse state is invalid")
        if self.status == "complete" and (
            self.checked_files != self.applicable_files or self.skipped_files != 0
        ):
            raise ValueError("complete backend results require every applicable file to be checked")
        if self.status == "complete" and (
            len(self.parse_states) != self.applicable_files
            or any(value != "complete" for value in self.parse_states.values())
        ):
            raise ValueError("complete backend results require complete parse states for every target")
        if self.status == "complete" and self.parse_errors:
            raise ValueError("complete backend results cannot contain parse errors")
        if self.status == "not_applicable" and any(
            (self.applicable_files, self.checked_files, self.skipped_files)
        ):
            raise ValueError("not_applicable backend results cannot contain files")
        if self.status == "not_applicable" and self.parse_states:
            raise ValueError("not_applicable backend results cannot contain parse states")

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
