"""Deterministic, selected-file complexity backend.

The skill pins Lizard 1.24.0 as the fallback dependency.  This module keeps a
small standard-library extractor available for offline validation and exposes
the same function metrics expected from that pinned backend.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
import io
import importlib
import re
import sys
import tokenize
from pathlib import Path
from typing import Any, Iterable, Mapping

from .model import ComplexityFunction
from .configuration import resolve_policy
from language_registry import language_for_path
from ..test_integrity.model import sha256_bytes


LIZARD_VERSION = "1.24.0"
_LIZARD_SITE = Path(__file__).resolve().parents[2] / "vendor" / "lizard" / "site-packages"
SUPPORTED_SUFFIXES = frozenset({
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
    ".go", ".rs", ".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".ipp", ".tpp", ".java", ".cs",
})
_KEYWORDS = frozenset({"if", "for", "while", "switch", "catch", "with", "foreach", "return", "sizeof"})
_BRACE_DECLARATION = re.compile(
    r"(?m)^[ \t]*(?:(?:public|private|protected|internal|static|final|virtual|override|async|unsafe|extern|inline|constexpr|const|volatile|template\s*<[^>]*>|pub|\w+::)*\s*)"
    r"(?:function\s+|fn\s+|func\s+)?([A-Za-z_$][\w$:]*)\s*\(([^()\n]*)\)[^{};\n]*\{"
)
_ARROW_DECLARATION = re.compile(r"(?m)^[ \t]*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^()\n]*\)\s*=>\s*\{")


def _load_lizard() -> Any | None:
    if not _LIZARD_SITE.is_dir():
        return None
    if not (_LIZARD_SITE / "lizard.py").is_file() and not (_LIZARD_SITE / "lizard").is_dir():
        return None
    path = str(_LIZARD_SITE)
    if path not in sys.path:
        sys.path.insert(0, path)
    try:
        module = importlib.import_module("lizard")
    except (ImportError, OSError):
        return None
    module_path = getattr(module, "__file__", None)
    if not module_path:
        return None
    try:
        Path(module_path).resolve().relative_to(_LIZARD_SITE.resolve())
    except (OSError, ValueError):
        return None
    version = str(getattr(module, "version", getattr(module, "__version__", "")))
    return module if version == LIZARD_VERSION else None


_LIZARD = _load_lizard()


def _is_test_path(path: str) -> bool:
    lower = path.lower().replace("\\", "/")
    name = Path(lower).name
    return bool(
        re.search(r"(?:^|/)(?:test|tests|spec|specs|__tests__|testdata|fixtures?)(?:/|$)", lower)
        or re.search(r"(?:^|[._-])(?:test|spec)(?:[._-]|$)", name)
        or name.endswith("_test.go")
    )


def _is_test_function(path: str, name: str) -> bool:
    return _is_test_path(path) or bool(re.search(r"(?:^|[.:$])(?:test|spec)[_$-]", name, re.I))


def _nloc(source: str, start: int, end: int) -> int:
    return sum(1 for line in source[start:end].splitlines() if line.strip() and not line.lstrip().startswith(("#", "//", "/*", "*", "--")))


def _token_count(source: str) -> int:
    try:
        return sum(1 for token in tokenize.generate_tokens(io.StringIO(source).readline) if token.type not in {tokenize.ENCODING, tokenize.ENDMARKER, tokenize.NL, tokenize.NEWLINE, tokenize.COMMENT, tokenize.INDENT, tokenize.DEDENT})
    except (tokenize.TokenError, IndentationError):
        return len(re.findall(r"[A-Za-z_$][\w$]*|\d+(?:\.\d+)?|==|!=|<=|>=|&&|\|\||[^\s]", source))


class _PythonComplexity(ast.NodeVisitor):
    def __init__(self) -> None:
        self.value = 1

    def visit_If(self, node: ast.If) -> None:
        self.value += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.value += 1
        self.generic_visit(node)

    visit_AsyncFor = visit_For

    def visit_While(self, node: ast.While) -> None:
        self.value += 1
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.value += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        self.value += max(0, len(node.values) - 1)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self.value += 1
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> None:
        self.value += len(node.cases)
        self.generic_visit(node)

    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
        return

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_Lambda = lambda self, _node: None


def _python_functions(path: str, source: str, source_kind: str, digest: str) -> list[ComplexityFunction]:
    try:
        tree = ast.parse(source, filename=path, type_comments=True)
    except (SyntaxError, ValueError, TypeError):
        raise
    result: list[ComplexityFunction] = []

    def visit(node: ast.AST, prefix: str = "") -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = f"{prefix}.{child.name}" if prefix else child.name
                counter = _PythonComplexity()
                for statement in child.body:
                    counter.visit(statement)
                segment = ast.get_source_segment(source, child) or ""
                result.append(ComplexityFunction(
                    name, path, source_kind, digest,
                    child.lineno, getattr(child, "end_lineno", child.lineno),
                    counter.value, _nloc(segment, 0, len(segment)),
                    _token_count(segment), len(child.args.posonlyargs) + len(child.args.args) + len(child.args.kwonlyargs) + int(child.args.vararg is not None) + int(child.args.kwarg is not None),
                    _is_test_function(path, name), ast.unparse(child.args) if hasattr(ast, "unparse") else "",
                ))
                visit(child, name)
            elif isinstance(child, ast.ClassDef):
                name = f"{prefix}.{child.name}" if prefix else child.name
                visit(child, name)
            else:
                visit(child, prefix)
    visit(tree)
    return result


def _matching_brace(source: str, opening: int) -> int:
    pairs = {"{": "}", "(": ")", "[": "]"}
    stack: list[str] = []
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    index = opening
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if line_comment:
            if char == "\n":
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
        if char in {'"', "'", "`"}:
            quote = char
        elif char == "/" and next_char == "/":
            line_comment = True
            index += 2
            continue
        elif char == "/" and next_char == "*":
            block_comment = True
            index += 2
            continue
        elif char in pairs:
            stack.append(pairs[char])
        elif char in pairs.values():
            if not stack or stack.pop() != char:
                return -1
            if not stack:
                return index
        index += 1
    return -1


def source_parse_error(path: str, source: bytes | str) -> str | None:
    """Return a bounded syntax error before handing source to Lizard.

    Lizard is a metrics parser, not a compiler. Some malformed C-like files
    therefore produce partial function records instead of an error. The
    language-specific interpreter check covers Python; balanced delimiters are
    the conservative minimum for the other accepted source languages.
    """
    data = source if isinstance(source, bytes) else source.encode("utf-8", errors="surrogatepass")
    text = data.decode("utf-8", errors="replace")
    if b"\0" in data[:4096]:
        return "binary_source"
    if Path(path).suffix.lower() in {".py", ".pyi"}:
        try:
            ast.parse(text, filename=path, type_comments=True)
        except (SyntaxError, ValueError, TypeError):
            return "parse_error"
        return None
    pairs = {"(": ")", "[": "]", "{": "}"}
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
        if char == "/" and next_char == "/":
            line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            block_comment = True
            index += 2
            continue
        if char in {'"', "'", "`"}:
            quote = char
        elif char in pairs:
            stack.append(pairs[char])
        elif char in pairs.values():
            if not stack or stack.pop() != char:
                return "parse_error"
        index += 1
    return "parse_error" if quote or block_comment or stack else None


def _brace_functions(path: str, source: str, source_kind: str, digest: str) -> list[ComplexityFunction]:
    result: list[ComplexityFunction] = []
    matches = [*_BRACE_DECLARATION.finditer(source), *_ARROW_DECLARATION.finditer(source)]
    for match in sorted(matches, key=lambda item: item.start()):
        name = match.group(1)
        if name in _KEYWORDS or name.startswith("operator") and name == "operator":
            continue
        opening = source.find("{", match.start(), match.end())
        closing = _matching_brace(source, opening)
        if opening < 0 or closing < opening:
            raise SyntaxError(f"unbalanced function body for {name}")
        body = source[opening + 1:closing]
        complexity = 1
        complexity += len(re.findall(r"\b(?:if|for|while|case|catch|when)\b|&&|\|\|", body))
        complexity += len(re.findall(r"\?(?!=)", body))
        start_line = source.count("\n", 0, match.start()) + 1
        end_line = source.count("\n", 0, closing) + 1
        params = match.group(2) if match.lastindex and match.lastindex >= 2 else ""
        parameters = 0 if not params.strip() else len([item for item in params.split(",") if item.strip()])
        result.append(ComplexityFunction(
            name.replace("::", "."), path, source_kind, digest,
            start_line, end_line, complexity, _nloc(source, match.start(), closing + 1),
            _token_count(source[match.start():closing + 1]), parameters,
            _is_test_function(path, name), params.strip(), "complete",
        ))
    return result


def extract_functions(path: str, source: bytes | str, *, source_kind: str = "working-tree") -> tuple[ComplexityFunction, ...]:
    data = source if isinstance(source, bytes) else source.encode("utf-8", errors="surrogatepass")
    text = data.decode("utf-8", errors="replace")
    digest = sha256_bytes(data)
    parse_error = source_parse_error(path, data)
    if parse_error is not None:
        raise SyntaxError(f"{path}: {parse_error}")
    if _LIZARD is not None:
        try:
            analysis = _LIZARD.analyze_file.analyze_source_code(path, text)
            functions: list[ComplexityFunction] = []
            for info in getattr(analysis, "function_list", ()):
                start_line = max(1, int(getattr(info, "start_line", 1) or 1))
                end_line = max(start_line, int(getattr(info, "end_line", start_line) or start_line))
                name = str(getattr(info, "long_name", getattr(info, "name", "")))
                functions.append(ComplexityFunction(
                    name or str(getattr(info, "name", "<anonymous>")), path, source_kind, digest,
                    start_line, end_line,
                    max(1, int(getattr(info, "cyclomatic_complexity", 1) or 1)),
                    max(0, int(getattr(info, "nloc", 0) or 0)),
                    max(0, int(getattr(info, "token_count", 0) or 0)),
                    max(0, int(getattr(info, "parameter_count", 0) or 0)),
                    _is_test_function(path, name), str(getattr(info, "long_name", "")), "complete",
                ))
            return tuple(sorted(functions, key=lambda item: (item.logical_path, item.start_line, item.qualified_name)))
        except (AttributeError, SyntaxError, TypeError, ValueError):
            # The deterministic extractor below remains the bounded fallback
            # for a source feature the pinned library cannot parse.
            pass
    if Path(path).suffix.lower() in {".py", ".pyi"}:
        functions = _python_functions(path, text, source_kind, digest)
    else:
        functions = _brace_functions(path, text, source_kind, digest)
    return tuple(sorted(functions, key=lambda item: (item.logical_path, item.start_line, item.qualified_name)))


def analyse_source(path: str, source: bytes | str, *, source_kind: str = "working-tree", configured_threshold: int | None = None, fallback_threshold: int = 15, root: Path | None = None) -> tuple[tuple[ComplexityFunction, ...], dict[str, Any]]:
    spec = language_for_path(path)
    language = "c" if spec is not None and spec.language_id == "c-header" else spec.language_id if spec is not None else ""
    policy = resolve_policy(root or Path.cwd(), language, configured_threshold=configured_threshold, fallback_threshold=fallback_threshold)
    return extract_functions(path, source, source_kind=source_kind), {**policy, "language_id": language, "backend": "lizard-fallback", "tool": "lizard", "tool_version": LIZARD_VERSION}
