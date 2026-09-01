"""Small, conservative source guards used before structural analysers."""
from __future__ import annotations

import ast
from pathlib import Path
import re
import tokenize
import io


_PYTHON_SUFFIXES = {".py", ".pyi"}
_JS_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
_RUST_SUFFIXES = {".rs"}
_C_LIKE_SUFFIXES = {
    ".go", ".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp",
    ".hxx", ".ipp", ".tpp", ".java", ".cs", ".rs",
}


def _python_error(data: bytes, path: str) -> str | None:
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        ast.parse(data.decode(encoding), filename=path, type_comments=True)
    except (SyntaxError, ValueError, TypeError, UnicodeDecodeError, LookupError):
        return "parse_error"
    return None


def _looks_like_regex(text: str, index: int) -> bool:
    prefix = text[max(0, index - 96):index].rstrip()
    if not prefix:
        return True
    word = re.search(r"[A-Za-z_$][\w$]*$", prefix)
    if word and word.group(0) in {
        "return", "throw", "case", "delete", "void", "typeof",
        "instanceof", "in", "of",
    }:
        return True
    return prefix[-1:] in "=([{,:;!?&|+-*%^~<>"


def _raw_string_end(text: str, index: int, suffix: str) -> int | None:
    if suffix in _RUST_SUFFIXES and text[index] == "r":
        cursor = index + 1
        while cursor < len(text) and text[cursor] == "#":
            cursor += 1
        if cursor < len(text) and text[cursor] == '"':
            hashes = cursor - index - 1
            closing = '"' + ("#" * hashes)
            end = text.find(closing, cursor + 1)
            return -1 if end < 0 else end + len(closing)
    if suffix in {".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".ipp", ".tpp"} and text.startswith('R"', index):
        delimiter_end = text.find("(", index + 2, min(len(text), index + 18))
        if delimiter_end >= 0:
            delimiter = text[index + 2:delimiter_end]
            if len(delimiter) <= 16 and "\\" not in delimiter and " " not in delimiter:
                closing = ")" + delimiter + '"'
                end = text.find(closing, delimiter_end + 1)
                return -1 if end < 0 else end + len(closing)
    return None


def balanced_delimiter_error(path: str, source: bytes | str) -> str | None:
    """Return a conservative syntax error without claiming to be a parser.

    This guard only prevents recovered structural matches from being accepted
    when a source snapshot is visibly truncated.  Language parsers remain the
    authority for acceptance and may report additional errors.
    """
    data = source if isinstance(source, bytes) else source.encode("utf-8", errors="surrogatepass")
    if b"\0" in data[:4096]:
        return "binary_source"
    suffix = Path(path).suffix.lower()
    if suffix in _PYTHON_SUFFIXES:
        return _python_error(data, path)
    text = data.decode("utf-8", errors="replace")
    if suffix in _JS_SUFFIXES and re.search(
        r"(?m)\b(?:const|let|var)\s*=\s*[;,]|\binterface\s*\{|"
        r"\bfunction\s+[A-Za-z_$][\w$]*\s*\(\s*:",
        text,
    ):
        return "parse_error"
    if suffix == ".go" and re.search(r"\bfunc\s+[A-Za-z_]\w*\s*\(\s*:", text):
        return "parse_error"
    if suffix in {".java", ".cs"} and re.search(r"\b(?:void|public|private|static)\s+[A-Za-z_]\w*\s*\(\s*:", text):
        return "parse_error"
    if suffix not in _C_LIKE_SUFFIXES and suffix not in _JS_SUFFIXES:
        return None

    pairs = {"(": ")", "[": "]", "{": "}"}
    closing = set(pairs.values())
    stack: list[str] = []
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if char in "\r\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        raw_end = _raw_string_end(text, index, suffix)
        if raw_end is not None:
            if raw_end < 0:
                return "parse_error"
            index = raw_end
            continue
        if char == "/" and next_char == "/":
            line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            block_comment = True
            index += 2
            continue
        if suffix in _JS_SUFFIXES and char == "/" and next_char not in {"/", "*"} and _looks_like_regex(text, index):
            index += 1
            in_class = False
            regex_escaped = False
            while index < len(text):
                current = text[index]
                if regex_escaped:
                    regex_escaped = False
                elif current == "\\":
                    regex_escaped = True
                elif current == "[":
                    in_class = True
                elif current == "]":
                    in_class = False
                elif current == "/" and not in_class:
                    index += 1
                    while index < len(text) and text[index].isalpha():
                        index += 1
                    break
                elif current in "\r\n":
                    return "parse_error"
                index += 1
            else:
                return "parse_error"
            continue
        if char in {'"', "'", "`"}:
            quote = char
        elif char in pairs:
            stack.append(pairs[char])
        elif char in closing:
            if not stack or stack.pop() != char:
                return "unbalanced_delimiters"
        index += 1
    return "unbalanced_delimiters" if quote or block_comment or stack else None
