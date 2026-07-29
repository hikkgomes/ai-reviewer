from __future__ import annotations

from dataclasses import asdict, dataclass
import re

from .redaction import (
    contains_credential_shape,
    redact_sensitive_text,
    redacted_evidence_summary,
)

_REDACTED_EVIDENCE = re.compile(
    r"^redacted credential evidence \(type=[a-z0-9-]+, sha256=[0-9a-f]{12}\)$"
)


@dataclass(frozen=True)
class HistoricalSource:
    source: str
    path: str
    line: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", redact_sensitive_text(self.source))
        object.__setattr__(self, "path", redact_sensitive_text(self.path))


@dataclass(frozen=True)
class Finding:
    check_id: str
    category: str
    severity: str
    confidence: str
    path: str
    line: int
    evidence: str
    explanation: str
    remediation: str
    disposition: str = "finding"
    source: str = "working-tree"
    historical_sources: tuple[HistoricalSource, ...] = ()

    def __post_init__(self) -> None:
        raw_evidence = self.evidence
        for field in ("path", "source", "explanation", "remediation"):
            value = getattr(self, field)
            object.__setattr__(self, field, redact_sensitive_text(value))
        if _REDACTED_EVIDENCE.fullmatch(raw_evidence):
            object.__setattr__(self, "evidence", raw_evidence)
        elif self.category == "secrets" or contains_credential_shape(raw_evidence):
            object.__setattr__(self, "evidence", redacted_evidence_summary(raw_evidence))
        else:
            object.__setattr__(self, "evidence", redact_sensitive_text(raw_evidence))
        object.__setattr__(
            self,
            "historical_sources",
            tuple(
                item if isinstance(item, HistoricalSource) else HistoricalSource(**item)
                for item in self.historical_sources
            ),
        )

    def as_dict(self) -> dict:
        return asdict(self)
