from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit, urlunsplit


SENSITIVE_OPTIONS = {
    "--token", "--password", "--secret", "--api-key", "--apikey",
    "--access-key", "--client-secret", "--auth-token",
}
SENSITIVE_SHORT_OPTIONS = {"-p", "-t", "-k"}
_SENSITIVE_LABEL = (
    r"(?:password|passwd|client[_-]?secret|api[_-]?key|apikey|access[_-]?key|"
    r"access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?key|secret|token)"
)
_PROVIDER_PATTERNS = (
    ("stripe-live", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b")),
    ("github-fine-grained-token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_PEM = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?"
    r"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    re.S,
)
_AUTH = re.compile(r"(?i)\b(Bearer|Basic)\s+([A-Za-z0-9._~+/=-]{8,})")
_CLI_OPTION = re.compile(
    r"(?i)(--(?:token|password|secret|api-key|apikey|access-key|"
    r"client-secret|auth-token)(?:=|\s+))([^\s,;]+)"
)
_SECRET_FIELD = re.compile(
    rf"(?i)([\"']?{_SENSITIVE_LABEL}[\"']?\s*(?:[:=]|=>)\s*)"
    r"(?!\[REDACTED)(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;}\]]+)"
)
_ENV_ASSIGNMENT = re.compile(
    rf"(?i)\b([A-Z0-9_]*{_SENSITIVE_LABEL.upper()}[A-Z0-9_]*\s*=\s*)"
    r"(?!\[REDACTED)([^\s;]+)"
)
_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s<>'\"]+", re.I)


def _fingerprint(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:12]


def _replacement(raw: str, kind: str) -> str:
    return f"[REDACTED type={kind} sha256={_fingerprint(raw)}]"


def _redact_url(match: re.Match) -> str:
    raw = match.group(0)
    try:
        parsed = urlsplit(raw)
        if parsed.username is None and parsed.password is None:
            return raw
        hostname = parsed.hostname or ""
        if parsed.port:
            hostname += f":{parsed.port}"
    except ValueError:
        return _replacement(raw, "credential-url")
    safe_netloc = f"{_replacement(parsed.netloc, 'url-userinfo')}@{hostname}"
    return urlunsplit((parsed.scheme, safe_netloc, parsed.path, parsed.query, parsed.fragment))


def redact_sensitive_text(text: str) -> str:
    """Redact known and context-labelled credentials before retention."""
    redacted = _PEM.sub(lambda match: _replacement(match.group(0), "private-key"), text)
    redacted = _URL.sub(_redact_url, redacted)
    redacted = _AUTH.sub(
        lambda match: f"{match.group(1)} {_replacement(match.group(2), match.group(1).lower())}",
        redacted,
    )
    redacted = _CLI_OPTION.sub(
        lambda match: f"{match.group(1)}{_replacement(match.group(2), 'sensitive-argument')}",
        redacted,
    )
    redacted = _SECRET_FIELD.sub(
        lambda match: f"{match.group(1)}{_replacement(match.group(2), 'labelled-secret')}",
        redacted,
    )
    redacted = _ENV_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{_replacement(match.group(2), 'environment-secret')}",
        redacted,
    )
    redacted = _JWT.sub(lambda match: _replacement(match.group(0), "jwt"), redacted)
    for kind, pattern in _PROVIDER_PATTERNS:
        redacted = pattern.sub(lambda match, kind=kind: _replacement(match.group(0), kind), redacted)
    return redacted


def redact_environment(entries: tuple[tuple[str, str], ...]) -> list[dict[str, str]]:
    """Render environment values without ever changing the canonical plan values."""
    result = []
    for name, value in entries:
        sensitive = re.fullmatch(rf"(?i)[A-Z0-9_]*{_SENSITIVE_LABEL}[A-Z0-9_]*", name)
        result.append({
            "name": name,
            "value": _replacement(value, "environment-secret") if sensitive else redact_sensitive_text(value),
        })
    return result


def _shell_word_redaction(value: str) -> str:
    """Redact literal assignment data, leaving syntax capable of executing visible."""
    pieces: list[str] = []
    index = 0
    while index < len(value):
        if value.startswith("$(", index) or value.startswith("<(", index) or value.startswith(">(", index):
            opener = value[index:index + 2]
            depth = 1
            end = index + 2
            while end < len(value) and depth:
                if value[end] == "(":
                    depth += 1
                elif value[end] == ")":
                    depth -= 1
                end += 1
            pieces.append(value[index:end])
            index = end
        elif value[index] == "`":
            end = value.find("`", index + 1)
            end = len(value) if end < 0 else end + 1
            pieces.append(value[index:end])
            index = end
        else:
            end = index + 1
            while end < len(value) and not value.startswith(("$(", "<(", ">("), end) and value[end] != "`":
                end += 1
            literal = value[index:end]
            pieces.append(_replacement(literal, "environment-secret") if literal else literal)
            index = end
    return "".join(pieces)


def redact_shell_command(command: str) -> str:
    """Conservative shell rendering: assignment values are redacted, syntax remains shown.

    This intentionally does not try to evaluate shell.  It only identifies a sensitive
    assignment word and stops at shell separators, so substitutions, redirects, pipes,
    and subsequent commands always stay in the approval display.
    """
    assignment = re.compile(
        rf"(?i)(?<![A-Za-z0-9_])([A-Z_]*(?:{_SENSITIVE_LABEL.upper()})[A-Z0-9_]*=)"
    )
    output: list[str] = []
    position = 0
    for match in assignment.finditer(command):
        output.append(redact_sensitive_text(command[position:match.start()]))
        output.append(match.group(1))
        index = match.end()
        quote = ""
        depth = 0
        while index < len(command):
            char = command[index]
            if quote:
                if char == quote and (index == 0 or command[index - 1] != "\\"):
                    quote = ""
                index += 1
                continue
            if char in "'\"":
                quote = char
            elif command.startswith(("$(", "<(", ">("), index):
                depth += 1
                index += 2
                continue
            elif char == ")" and depth:
                depth -= 1
            elif depth == 0 and (char.isspace() or char in ";|&<>"):
                break
            index += 1
        output.append(_shell_word_redaction(command[match.end():index]))
        position = index
    output.append(redact_sensitive_text(command[position:]))
    return "".join(output)


def redact_argv(argv: list[str]) -> list[str]:
    """Redact argv with option/value relationships intact."""
    result = []
    redact_next = False
    for value in argv:
        if redact_next:
            result.append(_replacement(value, "sensitive-argument"))
            redact_next = False
            continue
        option, separator, assigned = value.partition("=")
        lowered = option.lower()
        if lowered in SENSITIVE_OPTIONS or lowered in SENSITIVE_SHORT_OPTIONS:
            if separator:
                result.append(f"{option}={_replacement(assigned, 'sensitive-argument')}")
            else:
                result.append(value)
                redact_next = True
            continue
        if re.fullmatch(rf"(?i)[A-Z0-9_]*{_SENSITIVE_LABEL}[A-Z0-9_]*", option) and separator:
            result.append(f"{option}={_replacement(assigned, 'environment-secret')}")
            continue
        result.append(redact_sensitive_text(value))
    return result


def evidence_kind(text: str) -> str:
    if _PEM.search(text):
        return "private-key"
    if _JWT.search(text):
        return "jwt"
    if _AUTH.search(text):
        return "authorization-credential"
    for kind, pattern in _PROVIDER_PATTERNS:
        if pattern.search(text):
            return kind
    if _SECRET_FIELD.search(text) or _ENV_ASSIGNMENT.search(text):
        return "labelled-secret"
    return "credential"


def redacted_evidence_summary(text: str) -> str:
    return (
        f"redacted credential evidence "
        f"(type={evidence_kind(text)}, sha256={_fingerprint(text)})"
    )


def contains_credential_shape(text: str) -> bool:
    return any(pattern.search(text) for _kind, pattern in _PROVIDER_PATTERNS) or bool(
        _JWT.search(text) or _PEM.search(text) or _AUTH.search(text)
    )
