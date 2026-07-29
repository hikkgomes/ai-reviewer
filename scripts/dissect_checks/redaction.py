from __future__ import annotations

import hashlib
import re


_CREDENTIAL = re.compile(
    r"\b(?:"
    r"sk_live_[A-Za-z0-9]{16,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|ghp_[A-Za-z0-9]{30,}"
    r"|(?:eyJ[A-Za-z0-9_-]{8,}\.){2}[A-Za-z0-9_-]{8,}"
    r")\b"
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:password|client_secret|api[_-]?key|access[_-]?key|access[_-]?token|"
    r"auth[_-]?token|secret)\b\s*[:=]\s*['\"]?)([^\s'\",;]{4,})(['\"]?)"
)
_BEARER = re.compile(r"(?i)(\bBearer\s+)([A-Za-z0-9._~+/=-]{8,})")


def _replacement(raw: str) -> str:
    fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    prefix = raw[:4] + "…" if raw else "redacted"
    return f"[REDACTED prefix={prefix} sha256={fingerprint}]"


def redact_sensitive_text(text: str) -> str:
    """Redact credential-shaped values while retaining useful diagnostics."""
    redacted = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{_replacement(match.group(2))}{match.group(3)}",
        text,
    )
    redacted = _BEARER.sub(
        lambda match: f"{match.group(1)}{_replacement(match.group(2))}",
        redacted,
    )
    return _CREDENTIAL.sub(lambda match: _replacement(match.group(0)), redacted)


def redacted_evidence_summary(text: str) -> str:
    fingerprint = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    token = _CREDENTIAL.search(text) or re.search(r"[A-Za-z0-9_./+=-]{4,}", text)
    prefix = token.group(0)[:4] + "…" if token else "redacted"
    return f"redacted credential-like evidence (prefix={prefix}, sha256={fingerprint})"


def contains_credential_shape(text: str) -> bool:
    return _CREDENTIAL.search(text) is not None
