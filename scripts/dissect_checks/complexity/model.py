"""Immutable complexity metrics and candidate records."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
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
        if len(self.content_sha256) != 64 or any(char not in "0123456789abcdef" for char in self.content_sha256):
            raise ValueError("complexity function hash must be a lowercase SHA-256")
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("complexity function line range is invalid")
        if any(value < 0 for value in (self.nloc, self.token_count, self.parameter_count)) or self.cyclomatic < 1:
            raise ValueError("complexity metrics are invalid")
        if self.threshold is not None and self.threshold < 1:
            raise ValueError("complexity threshold must be positive")
        if self.threshold is not None and not self.threshold_source:
            raise ValueError("complexity threshold source is required")

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

    def __post_init__(self) -> None:
        if self.status not in {"complete", "partial", "not_applicable", "unavailable", "failed"}:
            raise ValueError("invalid complexity result status")
        if min(self.applicable_files, self.checked_files, self.skipped_files) < 0:
            raise ValueError("complexity counts must not be negative")
        if self.checked_files > self.applicable_files:
            raise ValueError("complexity checked files exceed applicable files")
        if self.checked_files + self.skipped_files > self.applicable_files:
            raise ValueError("complexity checked and skipped files exceed applicable files")

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason_code": self.reason_code,
            "backend_id": self.backend_id,
            "applicable_files": self.applicable_files,
            "checked_files": self.checked_files,
            "skipped_files": self.skipped_files,
            "functions": [item.as_dict() for item in self.functions],
            "candidates": [item.as_dict() for item in self.candidates],
            "policy": dict(self.policy),
        }
