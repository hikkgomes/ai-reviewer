from __future__ import annotations

from dataclasses import asdict, dataclass

from .redaction import contains_credential_shape, redacted_evidence_summary


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
        if self.category != "secrets" and not contains_credential_shape(self.evidence):
            return
        object.__setattr__(self, "evidence", redacted_evidence_summary(self.evidence))

    def as_dict(self) -> dict:
        return asdict(self)
