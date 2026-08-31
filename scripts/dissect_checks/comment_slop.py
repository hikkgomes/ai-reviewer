"""Conservative, language-aware detection of redundant AI narration comments."""
from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import io
import json
import re
import time
import tokenize
from difflib import SequenceMatcher
from pathlib import Path
from typing import Callable, Iterable

from analysis_budget import AnalysisBudget, AnalysisBudgetExceeded
from language_registry import LANGUAGE_SPECS, language_for_path
from review_ledger import blank_candidate, validate_candidate
from .anti_slop.model import AnalysisTarget
from .redaction import redact_payload


@dataclass(frozen=True)
class Comment:
    line: int
    end_line: int
    text: str
    docstring: bool = False
    column: int = 0


def _syntax_from_registry() -> dict[str, frozenset[str]]:
    syntax: dict[str, frozenset[str]] = {}
    for spec in LANGUAGE_SPECS:
        if not spec.comment_style:
            continue
        families = frozenset(spec.comment_style.replace(",", "+").split("+"))
        for suffix in spec.suffixes:
            syntax[suffix] = families
    return syntax


SYNTAX = _syntax_from_registry()
HASH_ATTRIBUTE_SUFFIXES = {".php"}

# Syntax audit: every suffix named by reference/lang is represented above;
# C/C++ headers use slash comments, PHP uses slash and hash, and Terraform
# uses slash, hash, and block comments. No other reference suffix mismatched.

IMPERATIVE_VERBS = {
    "add", "call", "check", "create", "do", "ensure", "execute", "fetch", "get",
    "handle", "initialise", "initialize", "iterate", "loop", "perform", "process",
    "remove", "return", "save", "send", "set", "update", "validate",
}
NEGATIVE_RE = re.compile(
    r"\b(?:doesn['’]?t|does not|don['’]?t|do not|won['’]?t|will not|cannot|can['’]?t|no longer|never|without|not)\b",
    re.I,
)
HISTORICAL_RE = re.compile(
    r"\b(?:used to|previous(?:ly| implementation)?|no longer|changed|instead|removed|before|old version|now|still)\b",
    re.I,
)
CONVERSATION_RE = re.compile(r"\b(?:as requested|per the instructions|fixed the bug where)\b", re.I)
EXPLANATORY_RE = re.compile(
    r"(?:\b(?:because|since|workaround|must|cannot|invariant|NOTE|SAFETY|compatibility|contract|deliberately|boundary|concurrent-safe)\b"
    r"|\brather\s+than\b)",
    re.I,
)
STRONG_EXPLANATORY_RE = re.compile(r"\b(?:rather\s+than|concurrent-safe|database\s+lint)\b", re.I)
BEHAVIOURAL_RE = re.compile(
    r"(?:\b(?:this|the)\s+(?:function|method|helper|class|module|hook|endpoint|handler)\b.*"
    r"|\A\s*[A-Za-z][A-Za-z0-9]*\b.*)",
    re.I | re.S,
)
URL_RE = re.compile(r"\b(?:https?|ftp)://\S+", re.I)
REFERENCE_RE = re.compile(r"\bsee\s+(?:https?://|\S*(?:ticket|issue)|#\d+)\b", re.I)


def _is_python_path(path: str | Path) -> bool:
    spec = language_for_path(path)
    return spec is not None and spec.language_id == "python"


def _comment_text(value: str | bytes) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return re.sub(r"\s+", " ", value.strip()).strip()


def _source_bytes(value: str | bytes) -> bytes:
    return value if isinstance(value, bytes) else value.encode("utf-8")


def _python_docstring_ranges(value: str | bytes, tree: ast.AST | None = None) -> set[tuple[int, int]]:
    try:
        tree = tree or ast.parse(value)
    except (SyntaxError, ValueError, TypeError, UnicodeDecodeError, LookupError):
        return set()
    ranges: set[tuple[int, int]] = set()
    nodes = [tree, *ast.walk(tree)]
    for node in nodes:
        body = getattr(node, "body", None)
        if not isinstance(body, list) or not body:
            continue
        first = body[0]
        if not isinstance(first, ast.Expr) or not isinstance(first.value, ast.Constant):
            continue
        if not isinstance(first.value.value, str) or not hasattr(first, "lineno"):
            continue
        end = getattr(first, "end_lineno", first.lineno)
        ranges.add((first.lineno, end))
    return ranges


def _python_comments_detailed(value: str | bytes, deadline: float | None = None) -> tuple[list[Comment], str | None]:
    data = _source_bytes(value)
    comments: list[Comment] = []
    parse_error: BaseException | None = None
    try:
        tree = ast.parse(data)
    except (SyntaxError, ValueError, TypeError, UnicodeDecodeError, LookupError) as error:
        tree = None
        parse_error = error
    doc_ranges = _python_docstring_ranges(data, tree)
    try:
        # The byte tokenizer honours an encoding declaration and decodes only
        # Python source, unlike a blanket UTF-8 replacement read.
        tokens = tokenize.tokenize(io.BytesIO(data).readline)
        for token_index, token in enumerate(tokens, 1):
            if deadline is not None and token_index % 256 == 0 and time.monotonic() >= deadline:
                raise AnalysisBudgetExceeded("file_timeout", "comment file deadline exceeded")
            if token.type == tokenize.COMMENT:
                comments.append(Comment(token.start[0], token.end[0], _comment_text(token.string[1:]), column=token.start[1]))
            elif token.type == tokenize.STRING:
                token_range = (token.start[0], token.end[0])
                if token_range not in doc_ranges:
                    continue
                value = token.string
                prefix = re.match(r"(?i)[rubf]*", value)
                body = value[len(prefix.group(0)):] if prefix else value
                if len(body) < 6 or body[:3] not in {"'''", '\"\"\"'}:
                    continue
                comments.append(Comment(token.start[0], token.end[0], _comment_text(body[3:-3]), True, token.start[1]))
    except (tokenize.TokenError, IndentationError, SyntaxError, UnicodeDecodeError, LookupError) as error:
        parse_error = parse_error or error
    if parse_error is None:
        return comments, None
    return comments, f"Python source could not be parsed: {parse_error}"


def _python_comments(value: str | bytes) -> list[Comment]:
    return _python_comments_detailed(value)[0]


class SourceParseError(ValueError):
    """A source file could not be parsed for bounded comment analysis."""


def _check_file_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise AnalysisBudgetExceeded("file_timeout", "comment file deadline exceeded")


def _consume_quoted(data: bytes, start: int, quote: bytes, deadline: float | None = None) -> tuple[int, int]:
    index = start + len(quote)
    work = len(quote)
    while index < len(data):
        if deadline is not None and work % 1024 == 0 and time.monotonic() >= deadline:
            raise AnalysisBudgetExceeded("file_timeout", "comment file deadline exceeded")
        if data.startswith(quote, index):
            return index + len(quote), work + len(quote)
        if data[index:index + 1] == b"\\":
            index += min(2, len(data) - index)
            work += 2
        else:
            index += 1
            work += 1
    return len(data), work


def _looks_like_regex(data: bytes, start: int) -> bool:
    # The bounded prefix keeps the decision linear even for a large file with
    # many division operators.
    prefix = data[max(0, start - 96):start].rstrip()
    if not prefix:
        return True
    match = re.search(rb"([A-Za-z_$][\w$]*)$", prefix)
    if match and match.group(1).decode("ascii", errors="ignore") in {"return", "throw", "case", "delete", "void", "typeof", "instanceof", "in", "of"}:
        return True
    return prefix[-1:] in b"=([{,:;!?&|+-*%^~<>"


def _consume_regex(data: bytes, start: int, deadline: float | None = None) -> tuple[int, int]:
    index = start + 1
    work = 1
    in_class = False
    while index < len(data):
        if deadline is not None and work % 1024 == 0 and time.monotonic() >= deadline:
            raise AnalysisBudgetExceeded("file_timeout", "comment file deadline exceeded")
        char = data[index:index + 1]
        if char == b"\\":
            index += min(2, len(data) - index)
            work += 2
            continue
        if char == b"[":
            in_class = True
        elif char == b"]":
            in_class = False
        elif char == b"/" and not in_class:
            index += 1
            while index < len(data) and (65 <= data[index] <= 90 or 97 <= data[index] <= 122):
                index += 1
                work += 1
            return index, work + 1
        elif char == b"\n":
            return index, work
        index += 1
        work += 1
    return len(data), work


def _heredoc_end(data: bytes, start: int, deadline: float | None = None) -> int | None:
    """Return the first offset after a shell/Terraform heredoc."""
    line_end = data.find(b"\n", start)
    if line_end < 0:
        line_end = len(data)
    match = re.search(rb"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1", data[start:line_end])
    if match is None:
        return None
    delimiter = match.group(2)
    cursor = line_end + 1
    lines = 0
    while cursor < len(data):
        if lines % 256 == 0:
            _check_file_deadline(deadline)
        end = data.find(b"\n", cursor)
        if end < 0:
            end = len(data)
        if data[cursor:end].strip(b"\r") == delimiter:
            return len(data) if end == len(data) else end + 1
        cursor = len(data) if end == len(data) else end + 1
        lines += 1
    return len(data)


def _rust_raw_string_end(data: bytes, start: int, deadline: float | None = None) -> int | None:
    if start >= len(data) or data[start:start + 1] != b"r":
        return None
    cursor = start + 1
    while cursor < len(data) and data[cursor:cursor + 1] == b"#":
        cursor += 1
    if cursor >= len(data) or data[cursor:cursor + 1] != b'"':
        return None
    hashes = cursor - start - 1
    close = b'"' + (b"#" * hashes)
    end = data.find(close, cursor + 1)
    if end < 0:
        return len(data)
    return end + len(close)


def _generic_comments_detailed(path: str, value: str | bytes, deadline: float | None = None) -> tuple[list[Comment], int]:
    suffix = Path(path).suffix.lower()
    syntax = SYNTAX.get(suffix, frozenset())
    line_marker = b"#" if "hash" in syntax else b"--" if "sql" in syntax else None
    slash_comments = "slash" in syntax
    html_comments = "html" in syntax
    data = _source_bytes(value)
    comments: list[Comment] = []
    index = 0
    length = len(data)
    line = 1
    column = 0
    work = 0

    def advance(end: int) -> None:
        nonlocal index, line, column, work
        end = max(index, min(length, end))
        last_newline = data.rfind(b"\n", index, end)
        if last_newline >= index:
            line += data[index:end].count(b"\n")
            column = end - last_newline - 1
        else:
            column += end - index
        work += end - index
        index = end

    while index < length:
        if deadline is not None and work % 1024 == 0 and time.monotonic() >= deadline:
            raise AnalysisBudgetExceeded("file_timeout", "comment file deadline exceeded")
        start_line = line
        if suffix in {".sh", ".bash", ".zsh", ".tf", ".tfvars"} and data.startswith(b"<<", index):
            heredoc_end = _heredoc_end(data, index, deadline)
            if heredoc_end is not None:
                advance(heredoc_end)
                continue
        if suffix == ".rs":
            raw_end = _rust_raw_string_end(data, index, deadline)
            if raw_end is not None:
                advance(raw_end)
                continue
        if html_comments and data.startswith(b"<!--", index):
            comment_start = index
            start_column = column
            end = data.find(b"-->", index + 4)
            end = length if end < 0 else end
            closing_end = length if end == length else end + 3
            advance(closing_end)
            comments.append(Comment(start_line, line, _comment_text(data[comment_start + 4:end]), column=start_column))
            continue
        if (slash_comments or "sql" in syntax) and data.startswith(b"/*", index):
            comment_start = index
            start_column = column
            is_docstring = data.startswith(b"/**", index)
            cursor = index + 2
            depth = 1
            nested = suffix == ".rs"
            while cursor < length:
                if deadline is not None and work % 1024 == 0 and time.monotonic() >= deadline:
                    raise AnalysisBudgetExceeded("file_timeout", "comment file deadline exceeded")
                if nested and data.startswith(b"/*", cursor):
                    depth += 1
                    cursor += 2
                    work += 2
                    continue
                if data.startswith(b"*/", cursor):
                    depth -= 1
                    cursor += 2
                    work += 2
                    if depth == 0:
                        break
                    continue
                cursor += 1
                work += 1
            body_end = cursor - 2 if depth == 0 else length
            advance(cursor)
            comments.append(Comment(start_line, line, _comment_text(data[comment_start + 2:body_end]), is_docstring, start_column))
            continue
        if slash_comments and data.startswith(b"//", index):
            comment_start = index
            start_column = column
            prefix = data[max(0, index - 12):index].lower()
            if prefix.endswith((b"http:", b"https:")):
                advance(index + 2)
                continue
            end = data.find(b"\n", index + 2)
            end = length if end < 0 else end
            advance(end)
            comments.append(Comment(start_line, start_line, _comment_text(data[comment_start + 2:end]), column=start_column))
            continue
        if (
            line_marker
            and data.startswith(line_marker, index)
            and not (suffix in HASH_ATTRIBUTE_SUFFIXES and data.startswith(b"#[", index))
        ):
            comment_start = index
            start_column = column
            end = data.find(b"\n", index + len(line_marker))
            end = length if end < 0 else end
            advance(end)
            comments.append(Comment(start_line, start_line, _comment_text(data[comment_start + len(line_marker):end]), column=start_column))
            continue
        if data[index:index + 1] in {b'"', b"'"}:
            quote = data[index:index + 1]
            if data.startswith(quote * 3, index):
                end, consumed = _consume_quoted(data, index, quote * 3, deadline)
            else:
                end, consumed = _consume_quoted(data, index, quote, deadline)
            consumed_bytes = end - index
            advance(end)
            work += consumed - consumed_bytes
            continue
        if data[index:index + 1] == b"`" and (slash_comments or suffix in {".rb", ".sh", ".bash", ".zsh"}):
            end, consumed = _consume_quoted(data, index, b"`", deadline)
            consumed_bytes = end - index
            advance(end)
            work += consumed - consumed_bytes
            continue
        if data[index:index + 1] == b"/" and slash_comments and not data.startswith((b"//", b"/*"), index) and _looks_like_regex(data, index):
            end, consumed = _consume_regex(data, index, deadline)
            consumed_bytes = end - index
            advance(end)
            work += consumed - consumed_bytes
            continue
        advance(index + 1)
    return comments, work


def _generic_comments(path: str, value: str | bytes) -> list[Comment]:
    return _generic_comments_detailed(path, value)[0]


def extract_comments_with_work(path: str, text: str | bytes) -> tuple[list[Comment], int]:
    """Extract comments and report the production cursor work performed."""
    if _is_python_path(path):
        return _python_comments(text), len(_source_bytes(text))
    return _generic_comments_detailed(path, text)


def extract_comments(path: str, text: str | bytes) -> list[Comment]:
    """Extract comments without treating strings, URLs, regexes, or heredocs as comments."""
    return extract_comments_with_work(path, text)[0]


def _group_comments(comments: list[Comment], lines: list[str | bytes], deadline: float | None = None) -> list[Comment]:
    if not comments:
        return []
    groups: list[Comment] = []
    current = comments[0]
    for index, comment in enumerate(comments[1:], 1):
        if index % 256 == 0:
            _check_file_deadline(deadline)
        between = lines[current.end_line:comment.line - 1]
        if comment.line <= current.end_line + 1 and all(not item.strip() for item in between):
            current = Comment(
                current.line,
                comment.end_line,
                _comment_text(f"{current.text} {comment.text}"),
                current.docstring or comment.docstring,
                current.column,
            )
        else:
            groups.append(current)
            current = comment
    groups.append(current)
    return groups


def _tokens(value: str) -> list[str]:
    pieces = re.findall(r"[A-Za-z][A-Za-z0-9]*", value)
    output: list[str] = []
    for piece in pieces:
        output.extend(re.findall(r"[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+", piece))
    return [item.lower() for item in output if item.lower() not in {"a", "an", "and", "for", "if", "in", "of", "the", "to", "this", "with"}]


def _strip_inline_comment(path: str, value: str) -> str:
    suffix = Path(path).suffix.lower()
    syntax = SYNTAX.get(suffix, frozenset())
    markers: list[str] = []
    if "slash" in syntax:
        markers.extend(("//", "/*"))
    if "hash" in syntax:
        markers.append("#")
    if "sql" in syntax:
        markers.append("--")
    if "html" in syntax:
        markers.append("<!--")
    quote = ""
    index = 0
    while index < len(value):
        char = value[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if value.startswith(quote, index):
                closing = quote
                quote = ""
                index += len(closing)
                continue
            index += 1
            continue
        if char in {'"', "'", "`"}:
            quote = char
            index += 1
            continue
        marker = next(
            (
                item for item in markers
                if value.startswith(item, index)
                and not (item == "#" and suffix in HASH_ATTRIBUTE_SUFFIXES and value.startswith("#[", index))
            ),
            None,
        )
        if marker is not None:
            return value[:index].rstrip()
        index += 1
    return value.strip()


def _following_code(path: str, lines: list[str | bytes], end_line: int, deadline: float | None = None) -> list[str]:
    code: list[str] = []
    for raw_value in lines[end_line:end_line + 3]:
        _check_file_deadline(deadline)
        value = (
            raw_value.decode("utf-8", errors="replace")
            if isinstance(raw_value, bytes) else raw_value
        )
        if not value.strip():
            continue
        if value.lstrip().startswith(("//", "#", "--", "/*", "*", "<!--")):
            continue
        value = _strip_inline_comment(path, value)
        if value:
            code.append(value)
    return code[:3]


def _is_heading(text: str) -> bool:
    value = text.strip().strip("-:*").lower()
    return (
        0 < len(_tokens(value)) <= 4
        and not re.search(r"[.!?]", value)
        and bool(re.fullmatch(r"[a-z][a-z0-9 _/-]*", value))
        and any(token in value for token in ("helper", "main", "logic", "utility", "initial", "setup", "validation", "handler", "process"))
    )


def _normalize_verb(token: str) -> str:
    """Apply small, deterministic inflection rules used by the comment scorer."""
    value = token.lower()
    if value.endswith("ies") and len(value) > 4:
        return value[:-3] + "y"
    if value.endswith("ing") and len(value) > 5:
        stem = value[:-3]
        if stem + "e" in IMPERATIVE_VERBS:
            return stem + "e"
        if len(stem) > 2 and stem[-1] == stem[-2]:
            stem = stem[:-1]
        return stem
    if value.endswith("ed") and len(value) > 4:
        stem = value[:-2]
        if stem + "e" in IMPERATIVE_VERBS:
            return stem + "e"
        if len(stem) > 2 and stem[-1] == stem[-2]:
            stem = stem[:-1]
        return stem
    if value.endswith("es") and len(value) > 4:
        stem = value[:-2]
        if stem in IMPERATIVE_VERBS or stem + "e" in IMPERATIVE_VERBS:
            return stem if stem in IMPERATIVE_VERBS else stem + "e"
    if value.endswith("s") and len(value) > 3:
        return value[:-1]
    return value


def _is_behavioural_claim(text: str) -> bool:
    if not BEHAVIOURAL_RE.search(text) or NEGATIVE_RE.search(text) or HISTORICAL_RE.search(text):
        return False
    subject = re.search(
        r"\b(?:this|the)\s+(?:function|method|helper|class|module|hook|endpoint|handler)\b(?P<body>.*)",
        text,
        re.I | re.S,
    )
    if subject and any(_normalize_verb(token) in IMPERATIVE_VERBS for token in _tokens(subject.group("body"))):
        return True
    leading = re.match(r"\s*([A-Za-z][A-Za-z0-9]*)\b", text)
    return bool(
        leading
        and leading.group(1).lower().endswith(("s", "es", "ies"))
        and _normalize_verb(leading.group(1)) in IMPERATIVE_VERBS
    )


def _score(text: str, code: list[str], diff_density: float) -> float:
    comment_tokens = set(_tokens(text))
    code_tokens = set(_tokens(" ".join(code)))
    overlap = comment_tokens & code_tokens
    overlap_ratio = len(overlap) / max(1, len(comment_tokens))
    has_imperative = any(_normalize_verb(token) in IMPERATIVE_VERBS for token in comment_tokens)
    score = 0.0
    if has_imperative and overlap_ratio >= 0.25:
        score += 1.5
    if has_imperative and overlap_ratio >= 0.5:
        score += 1.0
    if has_imperative:
        score += 2.0
    if code and SequenceMatcher(None, " ".join(_tokens(text)), " ".join(_tokens(" ".join(code)))).ratio() >= 0.55:
        score += 2.0
    if _is_heading(text):
        score += 2.0
    if diff_density >= 0.5:
        score += 1.0
    if NEGATIVE_RE.search(text):
        score += 0.5
    if HISTORICAL_RE.search(text):
        score += 1.0
    if CONVERSATION_RE.search(text):
        score += 3.0
    if EXPLANATORY_RE.search(text):
        score -= 1.0
    if STRONG_EXPLANATORY_RE.search(text):
        score -= 1.5
    if _is_behavioural_claim(text):
        score += 2.0
    if re.search(r"\bNOTE\b", text):
        score += 0.5
    if URL_RE.search(text):
        score -= 1.0
    if REFERENCE_RE.search(text):
        score -= 1.0
    if len(comment_tokens) >= 3:
        score += 0.5
    return score


def score_comment(text: str, following_code: Iterable[str], diff_density: float = 0.0) -> float:
    """Expose the additive score for calibration tests without adding it to evidence."""
    return _score(text, list(following_code), diff_density)


def _subtype(text: str, code: list[str]) -> str:
    if CONVERSATION_RE.search(text):
        return "conversation-leak"
    if _is_behavioural_claim(text):
        return "behavioural-claim"
    historical = bool(HISTORICAL_RE.search(text))
    negative = bool(NEGATIVE_RE.search(text))
    if historical and negative and re.search(r"\b(?:won['’]?t|will not|does not|doesn['’]?t)\b", text, re.I):
        return "mixed"
    if historical:
        return "historical"
    if negative:
        return "negative-claim"
    if _is_heading(text):
        return "section-header"
    return "narration"


def _overlaps(line: int, end_line: int, ranges: list[tuple[int, int]]) -> bool:
    return any(line <= end and end_line >= start for start, end in ranges)


@dataclass(frozen=True)
class FileSkip:
    path: str
    reason_code: str
    detail: str = ""


@dataclass
class CommentAnalysisResult:
    status: str
    applicable_files: int
    checked_files: int
    skipped_files: list[FileSkip]
    bytes_scanned: int
    candidates: list[dict]
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"complete", "not_applicable", "partial", "failed"}:
            raise ValueError(f"invalid comment analysis status: {self.status}")
        if self.applicable_files < 0 or self.checked_files < 0:
            raise ValueError("comment analysis file counts must not be negative")
        if self.checked_files + len(self.skipped_files) > self.applicable_files:
            raise ValueError("comment analysis counts exceed applicable files")


def scan_comments(
    path: str,
    text: str | bytes,
    changed_line_ranges: list[tuple[int, int]] | None,
    mode: str,
    diff_density: float = 0.0,
    *,
    budget: AnalysisBudget | None = None,
    deadline: float | None = None,
    source_layer: str = "working-tree",
    content_sha256: str = "",
    strict_python: bool = True,
) -> list[dict]:
    """Return ledger candidates for comments in the requested review scope."""
    if mode == "diff" and changed_line_ranges is None:
        return []
    lines: list[str | bytes] = text.splitlines()
    if _is_python_path(path):
        comments, parse_error = _python_comments_detailed(text, deadline)
        if parse_error is not None and strict_python:
            raise SourceParseError(parse_error)
        if deadline is not None and time.monotonic() >= deadline:
            raise AnalysisBudgetExceeded("file_timeout", "comment file deadline exceeded")
    else:
        comments = _generic_comments_detailed(path, text, deadline)[0]
    _check_file_deadline(deadline)
    groups = _group_comments(comments, lines, deadline)
    candidates: list[dict] = []
    ranges = changed_line_ranges or []
    try:
        for comment in groups:
            _check_file_deadline(deadline)
            if mode == "diff" and not _overlaps(comment.line, comment.end_line, ranges):
                continue
            code = _following_code(path, lines, comment.end_line, deadline)
            if not code:
                continue
            score = _score(comment.text, code, diff_density)
            _check_file_deadline(deadline)
            if mode == "full" and comment.docstring:
                score -= 4.0
            threshold = 3.5 if mode == "full" else 2.0
            if score < threshold:
                continue
            subtype = _subtype(comment.text, code)
            identity = json.dumps({
                "analyser": "comment-slop",
                "rule": f"comment-slop/{_subtype(comment.text, code)}",
                "path": Path(path).as_posix(),
                "source_layer": source_layer,
                "content_sha256": content_sha256,
                "line": comment.line,
                "column": comment.column,
                "discriminator": comment.column,
            }, sort_keys=True, separators=(",", ":"))
            digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
            contract = (
                "Verify the asserted behaviour exists in the current implementation "
                "(truthfulness), is in scope (relevance), and describes the current "
                "invariant (stability)."
                if subtype == "behavioural-claim"
                else "Verify truthfulness, relevance, and stability before recommending removal."
            )
            candidate = blank_candidate(
                f"candidate-comment-slop-{digest}",
                source=f"comment-slop/{subtype}",
                claim=f"Comment may be redundant or narrational at {Path(path).as_posix()}:{comment.line}",
                contract=contract,
            )
            candidate["trigger_path"] = [f"{Path(path).as_posix()}:{comment.line}"]
            candidate["supporting_evidence"] = [{
                "kind": "comment",
                "file": Path(path).as_posix(),
                "line": comment.line,
                "column": comment.column,
                "message": comment.text,
                "source_layer": source_layer,
                "content_sha256": content_sha256,
            }]
            candidate = redact_payload(candidate)
            errors = validate_candidate(candidate)
            if errors:
                raise ValueError("invalid comment-slop candidate: " + "; ".join(errors))
            if budget is not None:
                budget.claim_candidate()
            candidates.append(candidate)
    except AnalysisBudgetExceeded as error:
        error.partial_candidates = candidates
        raise
    return candidates


def scan_comment_targets(
    root: Path,
    paths: Iterable[str | Path],
    *,
    mode: str,
    changed_ranges: dict[str, list[tuple[int, int]] | None] | None = None,
    diff_density: float = 0.0,
    budget: AnalysisBudget | None = None,
    max_file_bytes: int = 5 * 1024 * 1024,
    per_file_timeout: float = 5,
    excluded_paths: Iterable[str | Path] = (),
    text_by_path: dict[str, str | bytes] | None = None,
    pre_skipped: Iterable[FileSkip] = (),
    targets: Iterable[AnalysisTarget] | None = None,
    target_contents: dict[str, str | bytes] | None = None,
    source_reader: Callable[[str, int], tuple[str | bytes | None, str | None]] | None = None,
) -> CommentAnalysisResult:
    """Read and analyse only supported comment-bearing source targets.

    Scope filtering happens before ``stat`` and before opening a file.  The
    bounded binary read also lets the generic scanner preserve byte positions
    without decoding unsupported content.
    """
    root = root.absolute()
    excluded = {Path(path).as_posix() for path in excluded_paths}
    selected: list[tuple[str, Path, str | bytes | None, AnalysisTarget | None]] = []
    selected_keys: set[tuple[str, str, str]] = set()
    if targets is not None:
        for target in targets:
            logical_path = Path(target.logical_path)
            if logical_path.is_absolute() or not logical_path.parts or ".." in logical_path.parts:
                continue
            relative = logical_path.as_posix()
            if relative in excluded:
                continue
            spec = language_for_path(relative)
            if spec is None or spec.comment_style is None:
                continue
            physical = target.physical_path if target.physical_path.is_absolute() else root / target.physical_path
            provided = None
            if target_contents is not None:
                provided = target_contents.get(target.physical_path.as_posix())
                if provided is None:
                    provided = target_contents.get(physical.as_posix())
            if provided is None:
                try:
                    physical.resolve().relative_to(root.resolve())
                except (OSError, ValueError):
                    continue
            key = (relative, target.source_kind, target.content_sha256)
            if key in selected_keys:
                continue
            selected_keys.add(key)
            selected.append((relative, physical, provided, target))
        selected.sort(key=lambda item: (item[0], item[3].source_kind if item[3] is not None else "", item[3].content_sha256 if item[3] is not None else ""))
    else:
        for value in paths:
            candidate = Path(value)
            try:
                relative = candidate.absolute().relative_to(root).as_posix() if candidate.is_absolute() else candidate.as_posix()
            except ValueError:
                continue
            spec = language_for_path(relative)
            if spec is None or spec.comment_style is None:
                continue
            try:
                resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
                resolved.relative_to(root.resolve())
            except (OSError, ValueError):
                continue
            if relative in excluded:
                continue
            provided = text_by_path.get(relative) if text_by_path is not None else None
            key = (relative, "working-tree", "")
            if key in selected_keys:
                continue
            selected_keys.add(key)
            selected.append((relative, resolved, provided, None))
        selected.sort(key=lambda item: item[0])
    result_budget = budget or AnalysisBudget(timeout_seconds=300)
    pre_skip_by_path = {item.path: item for item in pre_skipped}
    skipped: list[FileSkip] = []
    candidates: list[dict] = []
    checked = 0
    bytes_scanned = 0
    internal_failure = False
    for relative, path, provided, target in selected:
        if relative in pre_skip_by_path:
            skipped.append(pre_skip_by_path[relative])
            continue
        ranges = (
            list(target.changed_ranges)
            if target is not None and target.changed_ranges is not None
            else changed_ranges.get(relative) if changed_ranges is not None else None
        )
        if mode == "diff" and ranges is None:
            skipped.append(FileSkip(relative, "no_diff_line_evidence", "changed line ranges were unavailable"))
            continue
        try:
            result_budget.claim_file()
        except AnalysisBudgetExceeded as error:
            skipped.append(FileSkip(relative, error.reason_code, error.detail))
            continue
        try:
            remaining = result_budget.max_total_bytes - result_budget.bytes_claimed if result_budget.max_total_bytes is not None else max_file_bytes
            if remaining <= 0:
                skipped.append(FileSkip(relative, "max_total_bytes", "aggregate byte budget exhausted"))
                continue
            source_limit = min(max_file_bytes, remaining)
            if provided is None and source_reader is not None:
                provided, reader_error = source_reader(relative, source_limit)
                if reader_error is not None:
                    observed = len(_source_bytes(provided)) if provided is not None else 0
                    allowed = min(observed, max_file_bytes, remaining)
                    if allowed:
                        result_budget.claim_bytes(allowed)
                        bytes_scanned += allowed
                    reason_code = "read_failure" if reader_error.startswith("read_failure:") else "max_total_bytes" if remaining < max_file_bytes else "max_file_bytes"
                    skipped.append(FileSkip(relative, reason_code, reader_error))
                    continue
                size = len(_source_bytes(provided)) if provided is not None else 0
            else:
                size = len(_source_bytes(provided)) if provided is not None else path.stat().st_size
            if size > max_file_bytes:
                skipped.append(FileSkip(relative, "max_file_bytes", f"file is {size} bytes"))
                continue
            read_limit = min(max_file_bytes + 1, remaining + 1)
            if provided is not None:
                data = _source_bytes(provided)[:read_limit]
            else:
                with path.open("rb") as source_file:
                    data = source_file.read(read_limit)
            observed = len(data)
            allowed = min(observed, max_file_bytes, remaining)
            if allowed:
                result_budget.claim_bytes(allowed)
                bytes_scanned += allowed
            if observed > max_file_bytes:
                skipped.append(FileSkip(relative, "max_file_bytes", "bounded read exceeded file limit"))
                continue
            if observed > remaining:
                skipped.append(FileSkip(relative, "max_total_bytes", "bounded read exceeded aggregate limit"))
                continue
            if b"\0" in data[:4096]:
                skipped.append(FileSkip(relative, "binary_source", "NUL byte in bounded source prefix"))
                continue
            deadline = result_budget.child_deadline(per_file_timeout)
            values = scan_comments(
                relative,
                data,
                ranges,
                mode,
                diff_density,
                budget=result_budget,
                deadline=deadline,
                source_layer=target.source_kind if target is not None else "working-tree",
                content_sha256=target.content_sha256 if target is not None else "",
                strict_python=True,
            )
            candidates.extend(values)
            checked += 1
        except AnalysisBudgetExceeded as error:
            candidates.extend(getattr(error, "partial_candidates", ()))
            skipped.append(FileSkip(relative, error.reason_code, error.detail))
        except SourceParseError as error:
            skipped.append(FileSkip(relative, "parse_error", str(error)))
        except (OSError, UnicodeError) as error:
            skipped.append(FileSkip(relative, "read_failure", str(error)))
        except Exception as error:  # one malformed file must not abort the pass
            internal_failure = True
            skipped.append(FileSkip(relative, "internal_failure", str(error)))
    if not selected:
        status = "not_applicable"
        reason_code = "no_applicable_files"
    elif internal_failure:
        status = "failed"
        reason_code = "internal_failure"
    elif skipped:
        status = "partial"
        reason_code = skipped[0].reason_code
    else:
        status = "complete"
        reason_code = None
    return CommentAnalysisResult(
        status=status,
        applicable_files=len(selected),
        checked_files=checked,
        skipped_files=skipped,
        bytes_scanned=bytes_scanned,
        candidates=candidates,
        reason_code=reason_code,
    )
