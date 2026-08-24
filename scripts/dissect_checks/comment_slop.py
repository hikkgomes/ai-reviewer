"""Conservative, language-aware detection of redundant AI narration comments."""
from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import io
import re
import tokenize
from difflib import SequenceMatcher
from pathlib import Path
from typing import Iterable

from review_ledger import blank_candidate, validate_candidate
from .redaction import redact_payload


@dataclass(frozen=True)
class Comment:
    line: int
    end_line: int
    text: str
    docstring: bool = False


SLASH_LANGUAGES = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".cs", ".go", ".java", ".js", ".jsx",
    ".mjs", ".cjs", ".kt", ".kts", ".php", ".rs", ".swift", ".ts", ".tsx",
    ".mts", ".cts",
}
HASH_LANGUAGES = {".bash", ".cfg", ".ini", ".php", ".py", ".rb", ".sh", ".tf", ".tfvars", ".toml", ".yaml", ".yml", ".zsh"}
HASH_ATTRIBUTE_SUFFIXES = {".php"}
SQL_LANGUAGES = {".sql"}
HTML_LANGUAGES = {".html", ".htm", ".md", ".xml", ".xhtml", ".svg"}

SYNTAX: dict[str, frozenset[str]] = {
    suffix: frozenset(
        family
        for family, suffixes in (
            ("slash", SLASH_LANGUAGES),
            ("hash", HASH_LANGUAGES),
            ("sql", SQL_LANGUAGES),
            ("html", HTML_LANGUAGES),
        )
        if suffix in suffixes
    )
    for suffix in SLASH_LANGUAGES | HASH_LANGUAGES | SQL_LANGUAGES | HTML_LANGUAGES
}
for _suffix, _families in {".php": {"slash", "hash"}, ".tf": {"slash", "hash"}, ".tfvars": {"slash", "hash"}}.items():
    SYNTAX[_suffix] = frozenset(set(SYNTAX.get(_suffix, frozenset())) | _families)

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
    r"(?:\b(?:because|since|workaround|must|cannot|invariant|NOTE|SAFETY|compatibility|contract|deliberately|boundary)\b"
    r"|\brather\s+than\b)",
    re.I,
)
BEHAVIOURAL_RE = re.compile(
    r"(?:\b(?:this|the)\s+(?:function|method|helper|class|module|hook|endpoint|handler)\b.*"
    r"|\A\s*[A-Za-z][A-Za-z0-9]*\b.*)",
    re.I | re.S,
)
URL_RE = re.compile(r"\b(?:https?|ftp)://\S+", re.I)
REFERENCE_RE = re.compile(r"\bsee\s+(?:https?://|\S*(?:ticket|issue)|#\d+)\b", re.I)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _comment_text(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).strip()


def _python_docstring_ranges(text: str) -> set[tuple[int, int]]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
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


def _python_comments(text: str) -> list[Comment]:
    doc_ranges = _python_docstring_ranges(text)
    comments: list[Comment] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for token in tokens:
            if token.type == tokenize.COMMENT:
                comments.append(Comment(token.start[0], token.end[0], _comment_text(token.string[1:])))
            elif token.type == tokenize.STRING:
                token_range = (token.start[0], token.end[0])
                if token_range not in doc_ranges:
                    continue
                value = token.string
                prefix = re.match(r"(?i)[rubf]*", value)
                body = value[len(prefix.group(0)):] if prefix else value
                if len(body) < 6 or body[:3] not in {"'''", '\"\"\"'}:
                    continue
                comments.append(Comment(token.start[0], token.end[0], _comment_text(body[3:-3]), True))
    except (tokenize.TokenError, IndentationError):
        return comments
    return comments


def _heredoc_lines(text: str) -> set[int]:
    lines = text.splitlines()
    skipped: set[int] = set()
    pattern = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
    for index, line in enumerate(lines):
        match = pattern.search(line)
        if match is None:
            continue
        delimiter = match.group(2)
        for end in range(index + 1, len(lines)):
            skipped.add(end + 1)
            if lines[end].strip() == delimiter:
                break
    return skipped


def _consume_quoted(text: str, start: int, quote: str) -> int:
    index = start + len(quote)
    while index < len(text):
        if text.startswith(quote, index):
            return index + len(quote)
        if text[index] == "\\":
            index += 2
        else:
            index += 1
    return len(text)


def _looks_like_regex(text: str, start: int) -> bool:
    prefix = text[:start].rstrip()
    if not prefix:
        return True
    match = re.search(r"([A-Za-z_$][\w$]*)$", prefix)
    if match and match.group(1) in {"return", "throw", "case", "delete", "void", "typeof", "instanceof", "in", "of"}:
        return True
    return prefix[-1] in "=([{,:;!?&|+-*%^~<>"


def _consume_regex(text: str, start: int) -> int:
    index = start + 1
    in_class = False
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            index += 1
            while index < len(text) and text[index].isalpha():
                index += 1
            return index
        elif char == "\n":
            return index
        index += 1
    return len(text)


def _generic_comments(path: str, text: str) -> list[Comment]:
    suffix = Path(path).suffix.lower()
    syntax = SYNTAX.get(suffix, frozenset())
    line_marker = "#" if "hash" in syntax else "--" if "sql" in syntax else None
    slash_comments = "slash" in syntax
    html_comments = "html" in syntax
    heredoc_lines = _heredoc_lines(text)
    comments: list[Comment] = []
    index = 0
    length = len(text)
    while index < length:
        line = _line_number(text, index)
        if line in heredoc_lines:
            newline = text.find("\n", index)
            index = length if newline < 0 else newline + 1
            continue
        if html_comments and text.startswith("<!--", index):
            end = text.find("-->", index + 4)
            end = length if end < 0 else end
            comments.append(Comment(line, _line_number(text, end), _comment_text(text[index + 4:end])))
            index = length if end == length else end + 3
            continue
        if (slash_comments or "sql" in syntax) and text.startswith("/*", index):
            is_docstring = text.startswith("/**", index)
            end = text.find("*/", index + 2)
            end = length if end < 0 else end
            comments.append(Comment(line, _line_number(text, end), _comment_text(text[index + 2:end]), is_docstring))
            index = length if end == length else end + 2
            continue
        if slash_comments and text.startswith("//", index):
            prefix = text[max(0, index - 12):index].lower()
            if prefix.endswith(("http:", "https:")):
                index += 2
                continue
            end = text.find("\n", index + 2)
            end = length if end < 0 else end
            comments.append(Comment(line, line, _comment_text(text[index + 2:end])))
            index = end
            continue
        if (
            line_marker
            and text.startswith(line_marker, index)
            and not (suffix in HASH_ATTRIBUTE_SUFFIXES and text.startswith("#[", index))
        ):
            end = text.find("\n", index + len(line_marker))
            end = length if end < 0 else end
            comments.append(Comment(line, line, _comment_text(text[index + len(line_marker):end])))
            index = end
            continue
        if text[index] in {'"', "'"}:
            if suffix == ".py" and text.startswith(text[index] * 3, index):
                index = _consume_quoted(text, index, text[index] * 3)
            else:
                index = _consume_quoted(text, index, text[index])
            continue
        if text[index] == "`" and (slash_comments or suffix in {".rb", ".sh", ".bash", ".zsh"}):
            index = _consume_quoted(text, index, "`")
            continue
        if text[index] == "/" and slash_comments and not text.startswith(("//", "/*"), index) and _looks_like_regex(text, index):
            index = _consume_regex(text, index)
            continue
        index += 1
    return comments


def extract_comments(path: str, text: str) -> list[Comment]:
    """Extract comments without treating strings, URLs, regexes, or heredocs as comments."""
    if Path(path).suffix.lower() == ".py":
        return _python_comments(text)
    return _generic_comments(path, text)


def _group_comments(comments: list[Comment], lines: list[str]) -> list[Comment]:
    if not comments:
        return []
    groups: list[Comment] = []
    current = comments[0]
    for comment in comments[1:]:
        between = lines[current.end_line:comment.line - 1]
        if comment.line <= current.end_line + 1 and all(not item.strip() for item in between):
            current = Comment(
                current.line,
                comment.end_line,
                _comment_text(f"{current.text} {comment.text}"),
                current.docstring or comment.docstring,
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


def _following_code(path: str, lines: list[str], end_line: int) -> list[str]:
    code: list[str] = []
    for value in lines[end_line:end_line + 3]:
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
    score = 0.0
    if overlap_ratio >= 0.25:
        score += 1.5
    if overlap_ratio >= 0.5:
        score += 1.0
    if any(_normalize_verb(token) in IMPERATIVE_VERBS for token in comment_tokens):
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
        score += 1.5
    if CONVERSATION_RE.search(text):
        score += 3.0
    if EXPLANATORY_RE.search(text):
        score -= 1.0
    if re.search(r"\brather\s+than\b", text, re.I):
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


def scan_comments(
    path: str,
    text: str,
    changed_line_ranges: list[tuple[int, int]] | None,
    mode: str,
    diff_density: float = 0.0,
) -> list[dict]:
    """Return ledger candidates for comments in the requested review scope."""
    if mode == "diff" and changed_line_ranges is None:
        return []
    lines = text.splitlines()
    groups = _group_comments(extract_comments(path, text), lines)
    candidates: list[dict] = []
    ranges = changed_line_ranges or []
    for comment in groups:
        if mode == "diff" and not _overlaps(comment.line, comment.end_line, ranges):
            continue
        code = _following_code(path, lines, comment.end_line)
        if not code:
            continue
        score = _score(comment.text, code, diff_density)
        if mode == "full" and comment.docstring:
            score -= 4.0
        threshold = 3.5 if mode == "full" else 2.0
        if score < threshold:
            continue
        subtype = _subtype(comment.text, code)
        digest = hashlib.sha1(f"{path}:{comment.line}:{comment.text}".encode("utf-8")).hexdigest()[:12]
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
            "message": comment.text,
        }]
        candidate = redact_payload(candidate)
        errors = validate_candidate(candidate)
        if errors:
            raise ValueError("invalid comment-slop candidate: " + "; ".join(errors))
        candidates.append(candidate)
    return candidates
