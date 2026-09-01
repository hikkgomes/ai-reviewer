from __future__ import annotations

import hashlib
import re
from typing import Any
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
    ("generic-secret-token", re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b")),
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


def redact_payload(value: Any) -> Any:
    """Recursively redact strings before a payload is retained or emitted."""
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, list):
        return [redact_payload(item) for item in value]
    if isinstance(value, tuple):
        return [redact_payload(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_payload(item) for key, item in value.items()}
    return value


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


def _balanced_shell_construct(command: str, start: int, closers: list[str]) -> int:
    """Return the end of a shell substitution, or reject malformed syntax."""
    index = start
    quote = ""
    while index < len(command):
        char = command[index]
        if closers[-1] == "`" and char == "`":
            closers.pop()
            return index + 1
        if quote == "'":
            if char == "'":
                quote = ""
            index += 1
            continue
        if quote == '"':
            if char == "\\":
                if index + 1 >= len(command):
                    raise ValueError("shell command contains an unterminated escape")
                index += 2
                continue
            if char == '"':
                quote = ""
                index += 1
                continue
            if command.startswith(("$(", "${", "<(", ">("), index):
                opener = command[index:index + 2]
                nested = ["}"] if opener == "${" else [")"]
                index = _balanced_shell_construct(command, index + 2, nested)
                continue
            index += 1
            continue
        if char == "\\":
            if index + 1 >= len(command):
                raise ValueError("shell command contains an unterminated escape")
            index += 2
            continue
        if char == "'":
            quote = "'"
            index += 1
            continue
        if char == '"':
            quote = '"'
            index += 1
            continue
        if char == "`":
            end = index + 1
            while end < len(command):
                if command[end] == "\\":
                    end += 2
                elif command[end] == "`":
                    break
                else:
                    end += 1
            if end >= len(command):
                raise ValueError("shell command contains an unterminated backtick substitution")
            index = end + 1
            continue
        if command.startswith(("$(", "${", "<(", ">("), index):
            opener = command[index:index + 2]
            nested = ["}"] if opener == "${" else [")"]
            index = _balanced_shell_construct(command, index + 2, nested)
            continue
        if char == "(":
            closers.append(")")
        elif char == "{" and closers[-1] == "}":
            closers.append("}")
        elif char == closers[-1]:
            closers.pop()
            if not closers:
                return index + 1
        index += 1
    raise ValueError("shell command contains an unterminated substitution")


def _shell_word_spans(command: str) -> list[tuple[int, int]]:
    """Lex shell words while retaining source offsets and validating syntax."""
    spans: list[tuple[int, int]] = []
    index = 0
    operators = ";|&<>"
    while index < len(command):
        while index < len(command) and command[index].isspace():
            index += 1
        if index >= len(command):
            break
        if command[index] in operators:
            index += 1
            continue
        start = index
        quote = ""
        while index < len(command):
            char = command[index]
            if quote == "'":
                if char == "'":
                    quote = ""
                index += 1
                continue
            if quote == '"':
                if char == "\\":
                    if index + 1 >= len(command):
                        raise ValueError("shell command contains an unterminated escape")
                    index += 2
                elif char == '"':
                    quote = ""
                    index += 1
                elif command.startswith(("$(", "${", "<(", ">("), index):
                    opener = command[index:index + 2]
                    closers = ["}"] if opener == "${" else [")"]
                    index = _balanced_shell_construct(command, index + 2, closers)
                elif char == "`":
                    index = _balanced_shell_construct(command, index + 1, ["`"])
                else:
                    index += 1
                continue
            if char == "\\":
                if index + 1 >= len(command):
                    raise ValueError("shell command contains an unterminated escape")
                index += 2
                continue
            if char in "'\"":
                quote = char
                index += 1
                continue
            if command.startswith(("$(", "${", "<(", ">("), index):
                opener = command[index:index + 2]
                closers = ["}"] if opener == "${" else [")"]
                index = _balanced_shell_construct(command, index + 2, closers)
                continue
            if char == "`":
                index = _balanced_shell_construct(command, index + 1, ["`"])
                continue
            if char.isspace() or char in operators:
                break
            index += 1
        if quote:
            raise ValueError("shell command contains an unterminated quote")
        spans.append((start, index))
    return spans


def _shell_word_redaction(value: str) -> str:
    """Redact literal source slices while retaining shell syntax verbatim."""
    pieces: list[str] = []
    index = 0
    literal_start = 0
    quote = ""

    def flush_literal(end: int) -> None:
        nonlocal literal_start
        if literal_start < end:
            pieces.append(_replacement(value[literal_start:end], "sensitive-argument"))
        literal_start = end

    while index < len(value):
        if quote == "'":
            if value[index] == "'":
                flush_literal(index)
                pieces.append("'")
                index += 1
                literal_start = index
                quote = ""
            else:
                index += 1
            continue
        if quote == '"':
            if value[index] == "\\" and index + 1 < len(value):
                index += 2
                continue
            if value[index] == '"':
                flush_literal(index)
                pieces.append('"')
                index += 1
                literal_start = index
                quote = ""
                continue
        if value[index] in "'\"":
            flush_literal(index)
            quote = value[index]
            pieces.append(value[index])
            index += 1
            literal_start = index
            continue
        if value[index] == "\\" and index + 1 < len(value) and value[index + 1] == "\n":
            flush_literal(index)
            pieces.append("\\\n")
            index += 2
            literal_start = index
            continue
        if value[index] == "\\" and index + 1 < len(value):
            if value[index + 1] in "'\"":
                flush_literal(index)
                pieces.append(value[index:index + 2])
                index += 2
                literal_start = index
                continue
            index += 2
            continue
        if value.startswith(("$(", "${", "<(", ">("), index):
            flush_literal(index)
            opener = value[index:index + 2]
            closers = ["}"] if opener == "${" else [")"]
            end = _balanced_shell_construct(value, index + 2, closers)
            pieces.append(value[index:end])
            index = end
            literal_start = index
            continue
        if value[index] == "$" and index + 1 < len(value) and (
            value[index + 1].isalpha() or value[index + 1] == "_"
        ):
            flush_literal(index)
            end = index + 2
            while end < len(value) and (value[end].isalnum() or value[end] == "_"):
                end += 1
            pieces.append(value[index:end])
            index = end
            literal_start = index
            continue
        if value[index] == "`":
            flush_literal(index)
            end = _balanced_shell_construct(value, index + 1, ["`"])
            pieces.append(value[index:end])
            index = end
            literal_start = index
            continue
        index += 1
    flush_literal(len(value))
    return "".join(pieces)


def _sensitive_option_name(value: str) -> bool:
    return value.lower() in {item.lower() for item in SENSITIVE_OPTIONS | SENSITIVE_SHORT_OPTIONS}


def redact_shell_command(command: str) -> str:
    """Render shell syntax from original slices without user-collidable markers."""
    spans = _shell_word_spans(command)
    replacements: dict[tuple[int, int], str] = {}
    assignment = re.compile(rf"(?i)^[A-Z_]*(?:{_SENSITIVE_LABEL.upper()})[A-Z0-9_]*=")
    for ordinal, (start, end) in enumerate(spans):
        raw = command[start:end]
        if "=" in raw:
            option, value = raw.split("=", 1)
            if _sensitive_option_name(option):
                replacements[(start, end)] = f"{option}={_shell_word_redaction(value)}"
                continue
        if _sensitive_option_name(raw) and ordinal + 1 < len(spans):
            value_start, value_end = spans[ordinal + 1]
            replacements[(value_start, value_end)] = _shell_word_redaction(command[value_start:value_end])
        match = assignment.match(raw)
        if match:
            prefix = match.group(0)
            replacements[(start, end)] = prefix + _shell_word_redaction(raw[len(prefix):])

    output: list[str] = []
    position = 0
    for start, end in sorted(replacements):
        output.append(redact_sensitive_text(command[position:start]))
        output.append(replacements[(start, end)])
        position = end
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
