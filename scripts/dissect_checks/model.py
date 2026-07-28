from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import re


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
        credential_shape = re.search(
            r"\b(?:sk_live_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,})\b",
            self.evidence,
        )
        if self.category != "secrets" and credential_shape is None:
            return
        raw = self.evidence
        fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
        token = credential_shape or re.search(r"[A-Za-z0-9_./+=-]{4,}", raw)
        prefix = (token.group(0)[:4] + "…") if token else "redacted"
        object.__setattr__(
            self,
            "evidence",
            f"redacted credential-like evidence (prefix={prefix}, sha256={fingerprint})",
        )

    def as_dict(self) -> dict:
        return asdict(self)
