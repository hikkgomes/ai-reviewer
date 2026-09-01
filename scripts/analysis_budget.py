"""Monotonic resource budgets shared by context analysers."""
from __future__ import annotations

from dataclasses import dataclass, field
import math
from pathlib import Path
import time
from typing import Any, Mapping


class AnalysisBudgetExceeded(RuntimeError):
    """An analyser reached a configured resource limit."""

    def __init__(self, reason_code: str, detail: str = "") -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(detail or reason_code)


DEFAULT_ANALYSIS_LIMITS: dict[str, int | float] = {
    "context_timeout_seconds": 300,
    "comment_slop_timeout_seconds": 60,
    "comment_slop_per_file_timeout_seconds": 5,
    "comment_slop_max_file_bytes": 5 * 1024 * 1024,
    "comment_slop_max_total_bytes": 64 * 1024 * 1024,
    "comment_slop_max_files": 10000,
    "comment_slop_max_candidates": 2000,
    "anti_slop_timeout_seconds": 120,
    "anti_slop_max_file_bytes": 10 * 1024 * 1024,
    "anti_slop_max_total_bytes": 256 * 1024 * 1024,
    "anti_slop_max_files": 20000,
    "anti_slop_max_candidates": 5000,
    "test_integrity_timeout_seconds": 300,
    "test_matrix_timeout_seconds": 600,
    "mutation_timeout_seconds": 300,
    "mutation_max_mutants": 25,
    "mutation_max_per_function": 3,
    "proof_test_timeout_seconds": 120,
    "flaky_test_repetitions": 3,
    "complexity_timeout_seconds": 60,
    "complexity_max_files": 20000,
    "complexity_max_total_bytes": 256 * 1024 * 1024,
    "complexity_max_candidates": 100,
    "complexity_fallback_threshold": 15,
    "complexity_delta_threshold": 5,
    "complexity_delta_minimum_head": 10,
    "external_command_max_argument_bytes": 24000,
    "external_command_max_files": 250,
    "worker_threads": 0,
}

_POSITIVE_FIELDS = frozenset(key for key in DEFAULT_ANALYSIS_LIMITS if key != "worker_threads")
_TIME_FIELDS = frozenset({
    "context_timeout_seconds",
    "comment_slop_timeout_seconds",
    "comment_slop_per_file_timeout_seconds",
    "anti_slop_timeout_seconds",
    "test_integrity_timeout_seconds",
    "test_matrix_timeout_seconds",
    "mutation_timeout_seconds",
    "proof_test_timeout_seconds",
    "complexity_timeout_seconds",
})
_FEATURE_TOGGLES = frozenset({
    "anti_slop", "comment_slop", "test_integrity", "complexity",
    "dynamic_test_evidence", "targeted_mutation", "proof_tests",
    "anti_slop_python_getattr",
})


def analysis_limits(config: Mapping[str, Any] | None) -> dict[str, int | float]:
    """Merge and validate the optional ``review_options.analysis_limits`` map."""
    values = dict(DEFAULT_ANALYSIS_LIMITS)
    if not isinstance(config, Mapping):
        return values
    options = config.get("review_options")
    if "review_options" in config and not isinstance(options, Mapping):
        raise ValueError("review_options must be an object")
    if isinstance(options, Mapping) and "complexity_threshold" in options:
        configured = options["complexity_threshold"]
        candidates = configured.values() if isinstance(configured, Mapping) else (configured,)
        if not isinstance(configured, (Mapping, int)) or isinstance(configured, bool):
            raise ValueError("review option complexity_threshold must be a positive integer or a language map")
        for item in candidates:
            if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
                raise ValueError("review option complexity_threshold values must be positive integers")
    if isinstance(options, Mapping) and "test_integrity_approved_new_paths" in options:
        approved_paths = options["test_integrity_approved_new_paths"]
        if not isinstance(approved_paths, list) or not all(
            isinstance(item, str) and item.strip() for item in approved_paths
        ):
            raise ValueError("review option test_integrity_approved_new_paths must be a non-empty-string array")
        for item in approved_paths:
            normalised = item.replace("\\", "/").strip()
            path = Path(normalised)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("review option test_integrity_approved_new_paths must contain repository-relative patterns")
    if not isinstance(options, Mapping) or "analysis_limits" not in options:
        if isinstance(options, Mapping):
            for key in _FEATURE_TOGGLES & set(options):
                if not isinstance(options[key], bool):
                    raise ValueError(f"review option {key} must be a boolean")
        return values
    for key in _FEATURE_TOGGLES & set(options):
        if not isinstance(options[key], bool):
            raise ValueError(f"review option {key} must be a boolean")
    supplied = options.get("analysis_limits")
    if not isinstance(supplied, Mapping):
        raise ValueError("review_options.analysis_limits must be an object")
    unknown = sorted(set(supplied) - set(DEFAULT_ANALYSIS_LIMITS))
    if unknown:
        raise ValueError(f"unknown analysis limit(s): {', '.join(unknown)}")
    for key, value in supplied.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"analysis limit {key} must be a finite number")
        if key in _TIME_FIELDS:
            try:
                finite = math.isfinite(float(value))
            except OverflowError:
                finite = False
            if not finite:
                raise ValueError(f"analysis limit {key} must be a finite number")
        if key in _POSITIVE_FIELDS and value <= 0:
            raise ValueError(f"analysis limit {key} must be greater than zero")
        if key == "worker_threads" and value < 0:
            raise ValueError("analysis limit worker_threads must be zero or greater")
        if key not in _TIME_FIELDS and not isinstance(value, int):
            raise ValueError(f"analysis limit {key} must be an integer")
        values[key] = value
    return values


@dataclass
class AnalysisBudget:
    """A deadline plus file, byte, and candidate quotas.

    The budget is mutable so each backend can claim work without a shared
    counter implementation.  Its deadline is absolute and monotonic.
    """

    timeout_seconds: float
    max_files: int | None = None
    max_total_bytes: int | None = None
    max_candidates: int | None = None
    started_at: float = field(default_factory=time.monotonic)
    deadline: float | None = None
    files_claimed: int = 0
    bytes_claimed: int = 0
    candidates_claimed: int = 0

    def __post_init__(self) -> None:
        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float)):
            raise ValueError("budget timeout must be a finite number")
        try:
            finite = math.isfinite(float(self.timeout_seconds))
        except OverflowError:
            finite = False
        if not finite:
            raise ValueError("budget timeout must be a finite number")
        if self.timeout_seconds <= 0:
            raise ValueError("budget timeout must be greater than zero")
        if isinstance(self.started_at, bool) or not isinstance(self.started_at, (int, float)) or not math.isfinite(float(self.started_at)):
            raise ValueError("budget started_at must be finite")
        if self.deadline is not None and (
            isinstance(self.deadline, bool)
            or not isinstance(self.deadline, (int, float))
            or not math.isfinite(float(self.deadline))
        ):
            raise ValueError("budget deadline must be finite")
        for name, value in (("max_files", self.max_files), ("max_total_bytes", self.max_total_bytes), ("max_candidates", self.max_candidates)):
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                raise ValueError(f"budget {name} must be a non-negative integer")
        for name, value in (("files_claimed", self.files_claimed), ("bytes_claimed", self.bytes_claimed), ("candidates_claimed", self.candidates_claimed)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"budget {name} must be a non-negative integer")
        if self.deadline is None:
            self.deadline = self.started_at + self.timeout_seconds

    def remaining_seconds(self) -> float:
        return max(0.0, float(self.deadline or 0.0) - time.monotonic())

    def check_deadline(self) -> None:
        if self.remaining_seconds() <= 0:
            raise AnalysisBudgetExceeded("total_timeout", "analysis deadline exceeded")

    def claim_file(self) -> None:
        self.check_deadline()
        if self.max_files is not None and self.files_claimed >= self.max_files:
            raise AnalysisBudgetExceeded("max_files", "maximum file count reached")
        self.files_claimed += 1

    def claim_source(self, byte_count: int) -> None:
        """Claim one source file and its known byte size atomically."""
        if isinstance(byte_count, bool) or not isinstance(byte_count, int) or byte_count < 0:
            raise ValueError("source byte claim must be a non-negative integer")
        self.check_deadline()
        if self.max_files is not None and self.files_claimed >= self.max_files:
            raise AnalysisBudgetExceeded("max_files", "maximum file count reached")
        if self.max_total_bytes is not None and self.bytes_claimed + byte_count > self.max_total_bytes:
            raise AnalysisBudgetExceeded("max_total_bytes", "maximum aggregate byte count reached")
        self.files_claimed += 1
        self.bytes_claimed += byte_count

    def claim_bytes(self, count: int) -> None:
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("byte claim must be a non-negative integer")
        self.check_deadline()
        if self.max_total_bytes is not None and self.bytes_claimed + count > self.max_total_bytes:
            raise AnalysisBudgetExceeded("max_total_bytes", "maximum aggregate byte count reached")
        self.bytes_claimed += count

    def claim_candidate(self) -> None:
        self.check_deadline()
        if self.max_candidates is not None and self.candidates_claimed >= self.max_candidates:
            raise AnalysisBudgetExceeded("max_candidates", "maximum candidate count reached")
        self.candidates_claimed += 1

    def child_deadline(self, max_seconds: float) -> float:
        if isinstance(max_seconds, bool) or not isinstance(max_seconds, (int, float)) or not math.isfinite(float(max_seconds)) or max_seconds <= 0:
            raise ValueError("child deadline must be greater than zero")
        self.check_deadline()
        return min(float(self.deadline), time.monotonic() + max_seconds)

    def child_budget(self, max_seconds: float) -> "AnalysisBudget":
        deadline = self.child_deadline(max_seconds)
        return AnalysisBudget(
            timeout_seconds=max(0.000001, deadline - time.monotonic()),
            max_files=self.max_files,
            max_total_bytes=self.max_total_bytes,
            max_candidates=self.max_candidates,
            started_at=time.monotonic(),
            deadline=deadline,
        )
