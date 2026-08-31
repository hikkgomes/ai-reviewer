from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from analysis_budget import AnalysisBudget


@dataclass(frozen=True)
class AnalysisTarget:
    logical_path: str
    physical_path: Path
    language_id: str
    source_kind: str = "working-tree"
    revision: str = "WORKTREE"
    content_sha256: str = ""
    changed_ranges: tuple[tuple[int, int], ...] | None = None


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
