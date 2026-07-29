from __future__ import annotations

from dataclasses import asdict, dataclass

from .redaction import (
    contains_credential_shape,
    redact_sensitive_text,
    redacted_evidence_summary,
)


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

    def __post_init__(self) -> None:
        raw_evidence = self.evidence
        for field in ("path", "source", "explanation", "remediation"):
            value = getattr(self, field)
            object.__setattr__(self, field, redact_sensitive_text(value))
        if self.category == "secrets" or contains_credential_shape(raw_evidence):
            object.__setattr__(self, "evidence", redacted_evidence_summary(raw_evidence))
        else:
            object.__setattr__(self, "evidence", redact_sensitive_text(raw_evidence))

    def as_dict(self) -> dict:
        return asdict(self)
