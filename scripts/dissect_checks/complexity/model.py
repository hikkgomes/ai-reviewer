"""Immutable complexity metrics and candidate records."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
from pathlib import Path
from typing import Any, Mapping


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()


@dataclass(frozen=True)
class ComplexityFunction:
    qualified_name: str
    logical_path: str
    source_layer: str
    content_sha256: str
    start_line: int
    end_line: int
    cyclomatic: int
    nloc: int
    token_count: int
    parameter_count: int
    is_test: bool = False
    signature: str = ""
    mapping_status: str = "complete"
    threshold: int | None = None
    threshold_source: str = ""

    def __post_init__(self) -> None:
        if not self.qualified_name or not self.logical_path or not self.source_layer:
            raise ValueError("complexity functions require identity fields")
        path = Path(self.logical_path)
        if path.is_absolute() or not path.parts or ".." in path.parts:
            raise ValueError("complexity function path must be repository-relative")
        if not isinstance(self.content_sha256, str) or len(self.content_sha256) != 64 or any(char not in "0123456789abcdef" for char in self.content_sha256):
            raise ValueError("complexity function hash must be a lowercase SHA-256")
        if (
            isinstance(self.start_line, bool)
            or isinstance(self.end_line, bool)
            or not isinstance(self.start_line, int)
            or not isinstance(self.end_line, int)
            or self.start_line < 1
            or self.end_line < self.start_line
        ):
            raise ValueError("complexity function line range is invalid")
        if self.mapping_status not in {"complete", "ambiguous", "unverified"}:
            raise ValueError("complexity function mapping status is invalid")
        if self.threshold is not None and not self.threshold_source:
            raise ValueError("complexity threshold source is required")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (self.nloc, self.token_count, self.parameter_count)
        ) or isinstance(self.cyclomatic, bool) or not isinstance(self.cyclomatic, int) or self.cyclomatic < 1:
            raise ValueError("complexity metrics are invalid")
        if self.threshold is not None and (
            isinstance(self.threshold, bool)
            or not isinstance(self.threshold, int)
            or self.threshold < 1
        ):
            raise ValueError("complexity threshold must be positive")

    @property
    def function_id(self) -> str:
        return _hash("\0".join((self.logical_path, self.source_layer, self.content_sha256, self.qualified_name, str(self.start_line))))[:24]

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["function_id"] = self.function_id
        return value


@dataclass(frozen=True)
class ComplexityCandidate:
    candidate_id: str
    function: ComplexityFunction
    reason_code: str
    threshold: int
    threshold_source: str
    base_complexity: int | None
    head_complexity: int
    delta: int | None
    changed_lines: tuple[int, ...] = ()
    mapping_status: str = "complete"

    def __post_init__(self) -> None:
        if not self.candidate_id or not self.reason_code or not self.threshold_source:
            raise ValueError("complexity candidates require an identity and policy source")
        if self.threshold < 1 or self.head_complexity < 1:
            raise ValueError("complexity candidate thresholds and metrics must be positive")
        if self.base_complexity is not None and self.base_complexity < 1:
            raise ValueError("base complexity must be positive when present")
        if self.delta is not None and not isinstance(self.delta, int):
            raise ValueError("complexity delta must be an integer or null")
        if any(isinstance(line, bool) or not isinstance(line, int) or line < 1 for line in self.changed_lines):
            raise ValueError("complexity changed lines must be positive integers")
        if self.mapping_status not in {"complete", "ambiguous", "unverified"}:
            raise ValueError("complexity candidate mapping status is invalid")

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["function"] = self.function.as_dict()
        value["changed_lines"] = list(self.changed_lines)
        return value


@dataclass(frozen=True)
class ComplexityResult:
    status: str
    functions: tuple[ComplexityFunction, ...]
    candidates: tuple[ComplexityCandidate, ...]
    policy: Mapping[str, Any]
    applicable_files: int
    checked_files: int
    skipped_files: int
    reason_code: str | None = None
    backend_id: str = "lizard-fallback"
    parse_states: Mapping[str, str] = field(default_factory=dict)
    parse_errors: tuple[Mapping[str, Any], ...] = ()
    candidate_summary: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.status not in {"complete", "partial", "not_applicable", "unavailable", "failed"}:
            raise ValueError("invalid complexity result status")
        if min(self.applicable_files, self.checked_files, self.skipped_files) < 0:
            raise ValueError("complexity counts must not be negative")
        if self.checked_files > self.applicable_files:
            raise ValueError("complexity checked files exceed applicable files")
        if self.checked_files + self.skipped_files > self.applicable_files:
            raise ValueError("complexity checked and skipped files exceed applicable files")
        if self.status == "complete" and (
            self.checked_files != self.applicable_files or self.skipped_files != 0
        ):
            raise ValueError("complete complexity results require every file to be checked")
        if self.status == "not_applicable" and any(
            (self.applicable_files, self.checked_files, self.skipped_files)
        ):
            raise ValueError("not_applicable complexity results cannot contain files")
        if any(
            not isinstance(path, str) or not path
            or state not in {"complete", "failed", "not_verified", "not_run"}
            for path, state in self.parse_states.items()
        ):
            raise ValueError("complexity parse states are invalid")
        if self.candidate_summary is None:
            object.__setattr__(self, "candidate_summary", {
                "total_candidates": len(self.candidates),
                "emitted_candidates": len(self.candidates),
                "truncated": False,
                "reason_code": None,
            })
        summary = self.candidate_summary
        if not isinstance(summary, Mapping):
            raise ValueError("complexity candidate summary must be an object")
        total = summary.get("total_candidates")
        emitted = summary.get("emitted_candidates")
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in (total, emitted)):
            raise ValueError("complexity candidate summary counts are invalid")
        if not isinstance(total, int) or not isinstance(emitted, int) or emitted > total or emitted != len(self.candidates):
            raise ValueError("complexity candidate summary does not match candidates")
        if summary.get("truncated") is not (total > emitted):
            raise ValueError("complexity candidate summary truncation flag is invalid")
        if summary.get("truncated") and summary.get("reason_code") != "max_candidates":
            raise ValueError("truncated complexity candidates require max_candidates reason")

    def as_dict(self) -> dict[str, Any]:
        state = (
            "Checked" if self.status == "complete"
            else "Not applicable" if self.status == "not_applicable"
            else "Not verified"
        )
        return {
            "status": self.status,
            "state": state,
            "reason_code": self.reason_code,
            "backend_id": self.backend_id,
            "applicable_files": self.applicable_files,
            "checked_files": self.checked_files,
            "skipped_files": self.skipped_files,
            "functions": [item.as_dict() for item in self.functions],
            "candidates": [item.as_dict() for item in self.candidates],
            "policy": dict(self.policy),
            "parse_states": dict(sorted(self.parse_states.items())),
            "parse_errors": [dict(item) for item in self.parse_errors],
            "candidate_summary": dict(self.candidate_summary or {}),
            "total_candidates": (self.candidate_summary or {}).get("total_candidates", 0),
            "emitted_candidates": (self.candidate_summary or {}).get("emitted_candidates", 0),
            "truncated": (self.candidate_summary or {}).get("truncated", False),
        }
