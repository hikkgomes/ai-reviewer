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

MAX_NORMALISED_COMMENT_CHARS = 2_000
MAX_FOLLOWING_CODE_CHARS = 2_000
MAX_SCORE_TOKENS = 256

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
    _check_file_deadline(deadline)
    try:
        tree = ast.parse(data)
    except (SyntaxError, ValueError, TypeError, UnicodeDecodeError, LookupError) as error:
        tree = None
        parse_error = error
    _check_file_deadline(deadline)
    doc_ranges = _python_docstring_ranges(data, tree) if tree is not None else set()
    _check_file_deadline(deadline)
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
    _check_file_deadline(deadline)
    if parse_error is None:
        return comments, None
    return comments, f"Python source could not be parsed: {parse_error}"


def _python_comments(value: str | bytes) -> list[Comment]:
    return _python_comments_detailed(value)[0]


class SourceParseError(ValueError):
    """A source file could not be parsed for bounded comment analysis."""


class SourceReadError(OSError):
    """A source reader could not provide the bounded file snapshot."""


def _check_file_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise AnalysisBudgetExceeded("file_timeout", "comment file deadline exceeded")


def _consume_quoted(data: bytes, start: int, quote: bytes, deadline: float | None = None) -> tuple[int, int]:
    index = start + len(quote)
    work = len(quote)
    iterations = 0
    while index < len(data):
        iterations += 1
        if iterations % 1024 == 0:
            _check_file_deadline(deadline)
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
    iterations = 0
    while index < len(data):
        iterations += 1
        if iterations % 1024 == 0:
            _check_file_deadline(deadline)
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


def _find_bounded(data: bytes, marker: bytes, start: int, deadline: float | None = None) -> int:
    """Find a marker in bounded chunks so file deadlines remain observable."""
    cursor = max(0, start)
    overlap = max(0, len(marker) - 1)
    chunk_size = 64 * 1024
    while cursor < len(data):
        _check_file_deadline(deadline)
        end = min(len(data), cursor + chunk_size + overlap)
        found = data.find(marker, cursor, end)
        _check_file_deadline(deadline)
        if found >= 0:
            return found
        cursor += chunk_size
    return -1


def _heredoc_end(data: bytes, start: int, deadline: float | None = None) -> int | None:
    """Return the first offset after a shell/Terraform heredoc."""
    line_end = _find_bounded(data, b"\n", start, deadline)
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
        end = _find_bounded(data, b"\n", cursor, deadline)
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
    end = _find_bounded(data, close, cursor + 1, deadline)
    if end < 0:
        return len(data)
    return end + len(close)


def _generic_comments_detailed(
    path: str,
    value: str | bytes,
    deadline: float | None = None,
    observer: Callable[[int], None] | None = None,
) -> tuple[list[Comment], int]:
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
    iterations = 0

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
        if observer is not None and end > index:
            observer(end - index)
        index = end

    while index < length:
        iterations += 1
        if iterations % 1024 == 0:
            _check_file_deadline(deadline)
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
            end = _find_bounded(data, b"-->", index + 4, deadline)
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
            block_iterations = 0
            while cursor < length:
                block_iterations += 1
                if block_iterations % 1024 == 0:
                    _check_file_deadline(deadline)
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
            end = _find_bounded(data, b"\n", index + 2, deadline)
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
            end = _find_bounded(data, b"\n", index + len(line_marker), deadline)
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


def extract_comments_with_work(
    path: str,
    text: str | bytes,
    *,
    observer: Callable[[int], None] | None = None,
) -> tuple[list[Comment], int]:
    """Extract comments and report the production cursor work performed."""
    if _is_python_path(path):
        work = len(_source_bytes(text))
        if observer is not None and work:
            observer(work)
        return _python_comments(text), work
    return _generic_comments_detailed(path, text, observer=observer)


def extract_comments(
    path: str,
    text: str | bytes,
    *,
    observer: Callable[[int], None] | None = None,
) -> list[Comment]:
    """Extract comments without treating strings, URLs, regexes, or heredocs as comments."""
    return extract_comments_with_work(path, text, observer=observer)[0]


def _group_comments(comments: list[Comment], lines: list[str | bytes], deadline: float | None = None) -> list[Comment]:
    if not comments:
        return []
    groups: list[Comment] = []
    current = comments[0]
    for index, comment in enumerate(comments[1:], 1):
        if index % 256 == 0:
            _check_file_deadline(deadline)
        empty_between = True
        if comment.line <= current.end_line + 1:
            for line_index in range(current.end_line, max(current.end_line, comment.line - 1)):
                if line_index % 256 == 0:
                    _check_file_deadline(deadline)
                if lines[line_index].strip():
                    empty_between = False
                    break
            _check_file_deadline(deadline)
        if comment.line <= current.end_line + 1 and empty_between:
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
            raw_value[:MAX_FOLLOWING_CODE_CHARS].decode("utf-8", errors="replace")
            if isinstance(raw_value, bytes) else raw_value[:MAX_FOLLOWING_CODE_CHARS]
        )
        _check_file_deadline(deadline)
        # Bound the line before scanning for inline markers. A generated line
        # must not make the per-file deadline depend on its unbounded tail.
        value = value[:MAX_FOLLOWING_CODE_CHARS]
        if not value.strip():
            continue
        if value.lstrip().startswith(("//", "#", "--", "/*", "*", "<!--")):
            continue
        value = _strip_inline_comment(path, value)
        _check_file_deadline(deadline)
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


def _bounded_similarity(left: list[str], right: list[str], deadline: float | None = None) -> bool:
    """Return a bounded token similarity without arbitrary text matching."""
    _check_file_deadline(deadline)
    left = left[:MAX_SCORE_TOKENS]
    right = right[:MAX_SCORE_TOKENS]
    if not left or not right:
        return False
    left_set = set(left)
    right_set = set(right)
    overlap = len(left_set & right_set)
    if overlap / max(1, min(len(left_set), len(right_set))) >= 0.55:
        _check_file_deadline(deadline)
        return True
    # Ordered adjacent pairs preserve a little more signal than a set while
    # keeping the work bounded by the token cap above.
    left_pairs = set(zip(left, left[1:]))
    right_pairs = set(zip(right, right[1:]))
    similar = bool(left_pairs and right_pairs and len(left_pairs & right_pairs) / max(1, min(len(left_pairs), len(right_pairs))) >= 0.5)
    _check_file_deadline(deadline)
    return similar


def _score(text: str, code: list[str], diff_density: float, deadline: float | None = None) -> float:
    _check_file_deadline(deadline)
    bounded_text = text[:MAX_NORMALISED_COMMENT_CHARS]
    bounded_code = " ".join(code)[:MAX_FOLLOWING_CODE_CHARS]
    comment_tokens = _tokens(bounded_text)[:MAX_SCORE_TOKENS]
    code_tokens_list = _tokens(bounded_code)[:MAX_SCORE_TOKENS]
    comment_token_set = set(comment_tokens)
    code_tokens = set(code_tokens_list)
    overlap = comment_token_set & code_tokens
    overlap_ratio = len(overlap) / max(1, len(comment_tokens))
    has_imperative = any(_normalize_verb(token) in IMPERATIVE_VERBS for token in comment_tokens)
    score = 0.0
    if has_imperative and overlap_ratio >= 0.25:
        score += 1.5
    if has_imperative and overlap_ratio >= 0.5:
        score += 1.0
    if has_imperative:
        score += 2.0
    if _bounded_similarity(comment_tokens, code_tokens_list, deadline):
        score += 2.0
    _check_file_deadline(deadline)
    if _is_heading(bounded_text):
        score += 2.0
    _check_file_deadline(deadline)
    if diff_density >= 0.5:
        score += 1.0
    if NEGATIVE_RE.search(bounded_text):
        score += 0.5
    if HISTORICAL_RE.search(bounded_text):
        score += 1.0
    if CONVERSATION_RE.search(bounded_text):
        score += 3.0
    if EXPLANATORY_RE.search(bounded_text):
        score -= 1.0
    if STRONG_EXPLANATORY_RE.search(bounded_text):
        score -= 1.5
    if _is_behavioural_claim(bounded_text):
        score += 2.0
    _check_file_deadline(deadline)
    if re.search(r"\bNOTE\b", bounded_text):
        score += 0.5
    if URL_RE.search(bounded_text):
        score -= 1.0
    if REFERENCE_RE.search(bounded_text):
        score -= 1.0
    if len(comment_tokens) >= 3:
        score += 0.5
    _check_file_deadline(deadline)
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
    target_id: str = ""
    count: int = 1

    def __post_init__(self) -> None:
        path = Path(self.path.replace("\\", "/"))
        if path.is_absolute() or not path.parts or ".." in path.parts:
            raise ValueError("comment skip path must be repository-relative")
        if not isinstance(self.reason_code, str) or not self.reason_code:
            raise ValueError("comment skip reason_code is required")
        if isinstance(self.count, bool) or not isinstance(self.count, int) or self.count < 1:
            raise ValueError("comment skip count must be positive")

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "reason_code": self.reason_code,
            "detail": self.detail[:240],
            "target_id": self.target_id,
            "count": self.count,
        }


@dataclass
class CommentAnalysisResult:
    status: str
    applicable_files: int
    checked_files: int
    skipped_files: list[FileSkip]
    bytes_scanned: int
    candidates: list[dict]
    reason_code: str | None = None
    changed_line_count: int = 0
    changed_comment_count: int = 0
    comment_density: float = 0.0
    skipped_file_count: int | None = None

    def __post_init__(self) -> None:
        if self.status not in {"complete", "not_applicable", "partial", "failed"}:
            raise ValueError(f"invalid comment analysis status: {self.status}")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (self.applicable_files, self.checked_files)
        ):
            raise ValueError("comment analysis file counts must be non-negative integers")
        if any(not isinstance(item, FileSkip) for item in self.skipped_files):
            raise ValueError("comment skipped_files must contain FileSkip records")
        if self.skipped_file_count is None:
            self.skipped_file_count = sum(item.count for item in self.skipped_files)
        if (
            isinstance(self.skipped_file_count, bool)
            or not isinstance(self.skipped_file_count, int)
            or self.skipped_file_count < 0
            or self.skipped_file_count > self.applicable_files
        ):
            raise ValueError("comment skipped file count must be a valid non-negative integer")
        if self.checked_files + self.skipped_file_count > self.applicable_files:
            raise ValueError("comment analysis counts exceed applicable files")
        if self.status == "complete" and (
            self.checked_files != self.applicable_files or self.skipped_file_count != 0
        ):
            raise ValueError("complete comment analysis requires every file to be checked")
        if self.status == "not_applicable" and any((self.applicable_files, self.checked_files, self.skipped_file_count)):
            raise ValueError("not_applicable comment analysis cannot contain files")
        if isinstance(self.bytes_scanned, bool) or not isinstance(self.bytes_scanned, int) or self.bytes_scanned < 0:
            raise ValueError("comment analysis bytes must be a non-negative integer")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (self.changed_line_count, self.changed_comment_count)
        ):
            raise ValueError("comment density counts must be non-negative integers")
        if self.changed_comment_count > self.changed_line_count:
            raise ValueError("changed comment count cannot exceed changed line count")
        if not 0 <= self.comment_density <= 1:
            raise ValueError("comment density must be between zero and one")

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "applicable_files": self.applicable_files,
            "checked_files": self.checked_files,
            "skipped_files": [item.as_dict() for item in self.skipped_files],
            "skipped_file_count": self.skipped_file_count,
            "bytes_scanned": self.bytes_scanned,
            "changed_line_count": self.changed_line_count,
            "changed_comment_count": self.changed_comment_count,
            "comment_density": self.comment_density,
            "reason_code": self.reason_code,
            "candidates": list(self.candidates),
        }


@dataclass(frozen=True)
class _CommentDraft:
    path: str
    comment: Comment
    code: tuple[str, ...]
    score: float
    mode: str
    source_layer: str
    content_sha256: str
    target_id: str


@dataclass(frozen=True)
class _TargetScanOutcome:
    checked: bool = False
    bytes_scanned: int = 0
    changed_line_count: int = 0
    changed_comment_count: int = 0
    candidates: tuple[dict, ...] = ()
    skip: FileSkip | None = None
    terminal_reason: str | None = None
    terminal_detail: str = ""
    internal_failure: bool = False


def _normalise_ranges(ranges: Iterable[tuple[int, int]] | None) -> tuple[tuple[int, int], ...]:
    values = sorted(
        (max(1, int(start)), max(int(start), int(end)))
        for start, end in (ranges or ())
    )
    merged: list[tuple[int, int]] = []
    for start, end in values:
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return tuple(merged)


def _range_line_count(ranges: Iterable[tuple[int, int]]) -> int:
    return sum(end - start + 1 for start, end in ranges)


def _target_id(path: str, source_layer: str, content_sha256: str) -> str:
    return "|".join((Path(path).as_posix(), source_layer or "working-tree", content_sha256 or ""))


def _extract_comment_groups(
    path: str,
    text: str | bytes,
    deadline: float | None,
    *,
    strict_python: bool,
) -> tuple[list[str | bytes], list[Comment]]:
    _check_file_deadline(deadline)
    lines: list[str | bytes] = text.splitlines()
    _check_file_deadline(deadline)
    if _is_python_path(path):
        comments, parse_error = _python_comments_detailed(text, deadline)
        if parse_error is not None and strict_python:
            raise SourceParseError(parse_error)
    else:
        comments = _generic_comments_detailed(path, text, deadline)[0]
    _check_file_deadline(deadline)
    groups = _group_comments(comments, lines, deadline)
    _check_file_deadline(deadline)
    return lines, groups


def _candidate_from_comment(
    path: str,
    comment: Comment,
    code: Iterable[str],
    source_layer: str,
    content_sha256: str,
    target_id: str,
    score: float,
    deadline: float | None = None,
) -> dict:
    _check_file_deadline(deadline)
    bounded_comment = comment.text[:MAX_NORMALISED_COMMENT_CHARS]
    _check_file_deadline(deadline)
    subtype = _subtype(bounded_comment, list(code))
    _check_file_deadline(deadline)
    identity = json.dumps({
        "analyser": "comment-slop",
        "rule": f"comment-slop/{subtype}",
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
        "message": bounded_comment,
        "source_layer": source_layer,
        "content_sha256": content_sha256,
        "target_id": target_id,
        "score": score,
    }]
    candidate = redact_payload(candidate)
    _check_file_deadline(deadline)
    errors = validate_candidate(candidate)
    if errors:
        raise ValueError("invalid comment-slop candidate: " + "; ".join(errors))
    _check_file_deadline(deadline)
    return candidate


def _drafts_for_groups(
    path: str,
    lines: list[str | bytes],
    groups: Iterable[Comment],
    changed_ranges: tuple[tuple[int, int], ...],
    mode: str,
    source_layer: str,
    content_sha256: str,
    target_id: str,
    deadline: float | None,
    diff_density: float,
) -> list[_CommentDraft]:
    drafts: list[_CommentDraft] = []
    for comment in groups:
        _check_file_deadline(deadline)
        if mode == "diff" and not _overlaps(comment.line, comment.end_line, list(changed_ranges)):
            continue
        code = _following_code(path, lines, comment.end_line, deadline)
        if not code:
            continue
        score = _score(comment.text, code, diff_density, deadline)
        if mode == "full" and comment.docstring:
            score -= 4.0
        drafts.append(_CommentDraft(
            path, comment, tuple(code), score, mode, source_layer,
            content_sha256, target_id,
        ))
    return drafts


def _render_drafts(
    drafts: Iterable[_CommentDraft],
    density: float,
    budget: AnalysisBudget | None,
    deadline: float | None = None,
) -> list[dict]:
    candidates: list[dict] = []
    try:
        for draft in drafts:
            _check_file_deadline(deadline)
            score = draft.score + (1.0 if draft.mode == "diff" and density >= 0.5 else 0.0)
            threshold = 3.5 if draft.mode == "full" else 2.0
            if score < threshold:
                continue
            if budget is not None:
                try:
                    budget.claim_candidate()
                except AnalysisBudgetExceeded as error:
                    error.partial_candidates = candidates
                    raise
            candidates.append(_candidate_from_comment(
                draft.path, draft.comment, draft.code, draft.source_layer,
                draft.content_sha256, draft.target_id, score, deadline,
            ))
            _check_file_deadline(deadline)
    except AnalysisBudgetExceeded as error:
        if not hasattr(error, "partial_candidates"):
            error.partial_candidates = candidates
        raise
    return candidates


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
    """Return ledger candidates for one already-loaded source value."""
    if mode == "diff" and changed_line_ranges is None:
        return []
    if not content_sha256:
        content_sha256 = hashlib.sha256(_source_bytes(text)).hexdigest()
    lines, groups = _extract_comment_groups(path, text, deadline, strict_python=strict_python)
    ranges = _normalise_ranges(changed_line_ranges)
    target_id = _target_id(path, source_layer, content_sha256)
    drafts = _drafts_for_groups(
        path, lines, groups, ranges, mode, source_layer, content_sha256,
        target_id, deadline, diff_density,
    )
    try:
        return _render_drafts(drafts, 0.0 if mode == "diff" else diff_density, budget, deadline)
    except AnalysisBudgetExceeded as error:
        if not hasattr(error, "partial_candidates"):
            error.partial_candidates = []
        raise


def _select_comment_targets(
    root: Path,
    paths: Iterable[str | Path],
    *,
    excluded_paths: Iterable[str | Path],
    targets: Iterable[AnalysisTarget] | None,
    text_by_path: dict[str, str | bytes] | None,
    target_contents: dict[str, str | bytes] | None,
) -> list[tuple[str, Path, str | bytes | None, AnalysisTarget | None]]:
    excluded = {Path(path).as_posix() for path in excluded_paths}
    selected: list[tuple[str, Path, str | bytes | None, AnalysisTarget | None]] = []
    selected_keys: set[tuple[str, str, object]] = set()
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
            provided = target.data
            if target_contents is not None:
                snapshot_value = target_contents.get(relative)
                if snapshot_value is None:
                    snapshot_value = target_contents.get(target.physical_path.as_posix())
                if snapshot_value is None:
                    snapshot_value = target_contents.get(physical.as_posix())
                if snapshot_value is not None:
                    provided = snapshot_value
            try:
                physical.resolve().relative_to(root.resolve())
            except (OSError, ValueError):
                if target.data is None and not target.physical_snapshot:
                    continue
            # The bounded scan claims bytes before calculating the source
            # digest. Raw supplied bytes are only a pre-read deduplication key.
            identity = target.content_sha256 or target.data or ""
            key = (relative, target.source_kind, identity)
            if key in selected_keys:
                continue
            selected_keys.add(key)
            selected.append((relative, physical, provided, target))
        selected.sort(key=lambda item: (
            item[0],
            item[3].source_kind if item[3] is not None else "",
            item[3].content_sha256 if item[3] is not None else "",
        ))
        return selected
    for value in paths:
        candidate = Path(value)
        try:
            relative = candidate.absolute().relative_to(root).as_posix() if candidate.is_absolute() else candidate.as_posix()
        except ValueError:
            continue
        spec = language_for_path(relative)
        if spec is None or spec.comment_style is None or relative in excluded:
            continue
        try:
            resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
            resolved.relative_to(root.resolve())
        except (OSError, ValueError):
            continue
        provided = text_by_path.get(relative) if text_by_path is not None else None
        key = (relative, "working-tree", "")
        if key in selected_keys:
            continue
        selected_keys.add(key)
        selected.append((relative, resolved, provided, None))
    selected.sort(key=lambda item: item[0])
    return selected


def _scan_comment_target(
    root: Path,
    item: tuple[str, Path, str | bytes | None, AnalysisTarget | None],
    *,
    mode: str,
    changed_ranges: dict[str, list[tuple[int, int]] | None] | None,
    diff_density: float,
    result_budget: AnalysisBudget,
    max_file_bytes: int,
    per_file_timeout: float,
    pre_skip_by_id: dict[str, FileSkip],
    pre_skip_by_path: dict[str, FileSkip],
    source_reader: Callable[[str, int], tuple[str | bytes | None, str | None]] | None,
) -> _TargetScanOutcome:
    relative, path, provided, target = item
    source_layer = target.source_kind if target is not None else "working-tree"
    declared_hash = target.content_sha256 if target is not None else ""
    declared_id = _target_id(relative, source_layer, declared_hash)
    prior_skip = pre_skip_by_id.get(declared_id) or pre_skip_by_path.get(relative)
    if prior_skip is not None:
        return _TargetScanOutcome(skip=prior_skip)
    ranges_value = (
        list(target.changed_ranges)
        if target is not None and target.changed_ranges is not None
        else changed_ranges.get(relative) if changed_ranges is not None else None
    )
    ranges = _normalise_ranges(ranges_value)
    if mode == "diff" and ranges_value is None:
        return _TargetScanOutcome(
            skip=FileSkip(relative, "no_diff_line_evidence", "changed line ranges were unavailable", declared_id),
        )
    bytes_scanned = 0
    try:
        result_budget.claim_file()
        deadline = result_budget.child_deadline(per_file_timeout)
        remaining = (
            result_budget.max_total_bytes - result_budget.bytes_claimed
            if result_budget.max_total_bytes is not None else max_file_bytes
        )
        if remaining <= 0:
            raise AnalysisBudgetExceeded("max_total_bytes", "aggregate byte budget exhausted")
        size: int | None = None
        claimed_before_read = False
        if provided is None:
            try:
                size = path.stat().st_size
            except OSError as error:
                if source_reader is None:
                    raise SourceReadError(f"read_failure: {error}") from error
                size = None
            if size is not None:
                if size > max_file_bytes:
                    return _TargetScanOutcome(
                        skip=FileSkip(relative, "max_file_bytes", "source file exceeds file limit", declared_id),
                    )
                if size > remaining:
                    raise AnalysisBudgetExceeded("max_total_bytes", "source file exceeds aggregate byte limit")
                result_budget.claim_bytes(size)
                claimed_before_read = True
        read_limit = size if claimed_before_read and size is not None else min(max_file_bytes + 1, remaining)
        if provided is None and not claimed_before_read:
            # A custom reader may hide its stat operation. Reserve the full
            # bounded read before invoking it so a reader cannot bypass the
            # aggregate byte quota when the size is unavailable.
            result_budget.claim_bytes(read_limit)
            claimed_before_read = True
        reader_error: str | None = None
        if provided is None and source_reader is not None:
            provided, reader_error = source_reader(relative, read_limit)
            if reader_error is not None:
                if provided is not None and not claimed_before_read:
                    observed = min(len(_source_bytes(provided)), max_file_bytes, remaining)
                    if observed:
                        result_budget.claim_bytes(observed)
                        bytes_scanned += observed
                code = "max_file_bytes" if "max_file_bytes" in reader_error else "read_failure"
                raise SourceReadError(f"{code}: {reader_error}")
        if provided is not None:
            data = _source_bytes(provided)
            if not claimed_before_read:
                result_budget.claim_bytes(min(len(data), max_file_bytes))
        else:
            with path.open("rb") as source_file:
                data = source_file.read(read_limit)
        observed = len(data)
        if claimed_before_read:
            try:
                unchanged = len(data) == size and path.stat().st_size == size
            except OSError:
                unchanged = False
            if not unchanged:
                raise SourceReadError("read_failure: source changed during bounded read")
        bytes_scanned += min(observed, max_file_bytes)
        if observed > max_file_bytes:
            return _TargetScanOutcome(
                bytes_scanned=bytes_scanned,
                skip=FileSkip(relative, "max_file_bytes", "bounded read exceeded file limit", declared_id),
            )
        if not claimed_before_read and observed > remaining:
            raise AnalysisBudgetExceeded("max_total_bytes", "bounded read exceeded aggregate limit")
        if b"\0" in data[:4096]:
            return _TargetScanOutcome(
                bytes_scanned=bytes_scanned,
                skip=FileSkip(relative, "binary_source", "NUL byte in bounded source prefix", declared_id),
            )
        _check_file_deadline(deadline)
        digest = hashlib.sha256(data).hexdigest()
        _check_file_deadline(deadline)
        if declared_hash and declared_hash != digest:
            return _TargetScanOutcome(
                bytes_scanned=bytes_scanned,
                skip=FileSkip(relative, "content_hash_mismatch", "loaded source differs from its declared snapshot hash", declared_id),
            )
        target_id = _target_id(relative, source_layer, digest)
        lines, groups = _extract_comment_groups(relative, data, deadline, strict_python=True)
        drafts = _drafts_for_groups(
            relative, lines, groups, ranges, mode, source_layer, digest,
            target_id, deadline, 0.0 if mode == "diff" else diff_density,
        )
        _check_file_deadline(deadline)
        changed_comment_lines: set[int] = set()
        if mode == "diff":
            for comment in groups:
                for start, end in ranges:
                    overlap_start = max(comment.line, start)
                    overlap_end = min(comment.end_line, end)
                    if overlap_start <= overlap_end:
                        changed_comment_lines.update(range(overlap_start, overlap_end + 1))
        changed_comment_count = len(changed_comment_lines)
        changed_line_count = _range_line_count(ranges) if mode == "diff" else 0
        local_density = (
            changed_comment_count / changed_line_count
            if mode == "diff" and changed_line_count else diff_density
        )
        try:
            candidates = tuple(_render_drafts(tuple(drafts), local_density, result_budget, deadline))
        except AnalysisBudgetExceeded as error:
            partial = tuple(getattr(error, "partial_candidates", ()))
            terminal = error.reason_code if error.reason_code in {"max_candidates", "total_timeout", "max_total_bytes", "max_files"} else None
            return _TargetScanOutcome(
                checked=error.reason_code == "max_candidates",
                bytes_scanned=bytes_scanned,
                changed_line_count=changed_line_count,
                changed_comment_count=changed_comment_count,
                candidates=partial,
                skip=None if error.reason_code == "max_candidates" else FileSkip(relative, error.reason_code, error.detail, declared_id),
                terminal_reason=terminal,
                terminal_detail=error.detail,
            )
        return _TargetScanOutcome(
            checked=True,
            bytes_scanned=bytes_scanned,
            changed_line_count=changed_line_count,
            changed_comment_count=changed_comment_count,
            candidates=candidates,
        )
    except AnalysisBudgetExceeded as error:
        terminal = error.reason_code in {"total_timeout", "max_files", "max_total_bytes"}
        return _TargetScanOutcome(
            bytes_scanned=bytes_scanned,
            skip=FileSkip(relative, error.reason_code, error.detail, declared_id),
            terminal_reason=error.reason_code if terminal else None,
            terminal_detail=error.detail,
        )
    except SourceParseError as error:
        return _TargetScanOutcome(skip=FileSkip(relative, "parse_error", str(error), declared_id), bytes_scanned=bytes_scanned)
    except SourceReadError as error:
        detail = str(error)
        reason_code = "max_file_bytes" if detail.startswith("max_file_bytes:") else "read_failure"
        return _TargetScanOutcome(skip=FileSkip(relative, reason_code, detail, declared_id), bytes_scanned=bytes_scanned)
    except (OSError, UnicodeError) as error:
        return _TargetScanOutcome(skip=FileSkip(relative, "read_failure", str(error), declared_id), bytes_scanned=bytes_scanned)
    except Exception as error:
        return _TargetScanOutcome(
            skip=FileSkip(relative, "internal_failure", str(error), declared_id),
            bytes_scanned=bytes_scanned,
            internal_failure=True,
        )


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
    """Bounded one-pass implementation used by the public target scanner."""
    root = root.absolute()
    selected = _select_comment_targets(
        root,
        paths,
        excluded_paths=excluded_paths,
        targets=targets,
        text_by_path=text_by_path,
        target_contents=target_contents,
    )

    result_budget = budget or AnalysisBudget(timeout_seconds=300)
    pre_skips = tuple(pre_skipped)
    pre_skip_by_id = {item.target_id: item for item in pre_skips if item.target_id}
    selected_layer_counts: dict[str, int] = {}
    for item in selected:
        selected_layer_counts[item[0]] = selected_layer_counts.get(item[0], 0) + 1
    # A path-only skip is safe only when that path has one selected source
    # layer. With staged and worktree copies, applying it by logical path
    # would hide the other snapshot's evidence.
    pre_skip_by_path = {
        item.path: item
        for item in pre_skips
        if not item.target_id and selected_layer_counts.get(item.path, 0) <= 1
    }
    skipped: list[FileSkip] = []
    skipped_file_count = 0
    external_pre_skipped = 0
    candidates: list[dict] = []
    checked = 0
    bytes_scanned = 0
    changed_line_count = 0
    changed_comment_count = 0
    internal_failure = False
    terminal_reason: str | None = None
    terminal_detail = ""

    def record_skip(skip: FileSkip, count: int = 1) -> None:
        nonlocal skipped_file_count
        skipped_file_count += max(0, count)
        if len(skipped) < 3:
            skipped.append(skip)

    selected_ids = {
        _target_id(item[0], item[3].source_kind, item[3].content_sha256)
        if item[3] is not None else _target_id(item[0], "working-tree", "")
        for item in selected
    }
    selected_layer_keys = {
        (item[0], item[3].source_kind if item[3] is not None else "working-tree")
        for item in selected
    }
    selected_paths = {item[0] for item in selected}
    represented_pre_skipped = 0
    represented_pre_skip_units = 0
    for skip in pre_skips:
        skip_parts = skip.target_id.split("|", 2) if skip.target_id else []
        represented = (
            skip.target_id in selected_ids
            or len(skip_parts) > 1 and (skip.path, skip_parts[1]) in selected_layer_keys
            if skip_parts
            else skip.path in selected_paths
        )
        if not represented:
            record_skip(skip, skip.count)
            external_pre_skipped += skip.count
        else:
            represented_pre_skipped += skip.count
            represented_pre_skip_units += 1

    for index, item in enumerate(selected):
        outcome = _scan_comment_target(
            root,
            item,
            mode=mode,
            changed_ranges=changed_ranges,
            diff_density=diff_density,
            result_budget=result_budget,
            max_file_bytes=max_file_bytes,
            per_file_timeout=per_file_timeout,
            pre_skip_by_id=pre_skip_by_id,
            pre_skip_by_path=pre_skip_by_path,
            source_reader=source_reader,
        )
        checked += int(outcome.checked)
        bytes_scanned += outcome.bytes_scanned
        changed_line_count += outcome.changed_line_count
        changed_comment_count += outcome.changed_comment_count
        candidates.extend(outcome.candidates)
        if outcome.skip is not None:
            record_skip(outcome.skip, outcome.skip.count)
        if outcome.internal_failure:
            internal_failure = True
        if outcome.terminal_reason is not None:
            terminal_reason = outcome.terminal_reason
            terminal_detail = outcome.terminal_detail
            skipped_file_count += len(selected) - index - 1
            break
        if (
            result_budget.max_candidates is not None
            and result_budget.candidates_claimed >= result_budget.max_candidates
            and index + 1 < len(selected)
        ):
            terminal_reason = "max_candidates"
            terminal_detail = "maximum candidate count reached"
            skipped_file_count += len(selected) - index - 1
            break

    density = (
        changed_comment_count / changed_line_count
        if changed_line_count else diff_density if mode == "diff" else 0.0
    )
    candidate_limit = terminal_reason == "max_candidates"

    if not selected and external_pre_skipped == 0:
        status = "not_applicable"
        reason_code = "no_applicable_files"
    elif internal_failure:
        status = "failed"
        reason_code = "internal_failure"
    elif skipped_file_count or terminal_reason or candidate_limit:
        status = "partial"
        reason_code = terminal_reason or (skipped[0].reason_code if skipped else None)
    else:
        status = "complete"
        reason_code = None
    return CommentAnalysisResult(
        status=status,
        applicable_files=len(selected) + external_pre_skipped + max(
            0, represented_pre_skipped - represented_pre_skip_units,
        ),
        checked_files=checked,
        skipped_files=skipped,
        bytes_scanned=bytes_scanned,
        candidates=candidates,
        reason_code=reason_code,
        changed_line_count=changed_line_count,
        changed_comment_count=changed_comment_count,
        comment_density=density,
        skipped_file_count=skipped_file_count,
    )
