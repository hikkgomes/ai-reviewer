"""Deterministic, selected-file complexity backend.

The skill pins Lizard 1.24.0 as the fallback dependency. This module loads only
that skill-local implementation and exposes its function metrics to the
bounded orchestrator.
"""
from __future__ import annotations

import ast
import io
import importlib
import re
import sys
import tokenize
from pathlib import Path
from typing import Any

from .model import ComplexityFunction
from .configuration import resolve_policy
from language_registry import language_for_path
from ..test_integrity.model import sha256_bytes
from ..source_validation import balanced_delimiter_error


LIZARD_VERSION = "1.24.0"
_LIZARD_SITE = Path(__file__).resolve().parents[2] / "vendor" / "lizard" / "site-packages"
SUPPORTED_SUFFIXES = frozenset({
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
    ".go", ".rs", ".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".ipp", ".tpp", ".java", ".cs",
})


def _load_lizard() -> Any | None:
    if not _LIZARD_SITE.is_dir():
        return None
    if not (_LIZARD_SITE / "lizard.py").is_file() and not (_LIZARD_SITE / "lizard").is_dir():
        return None
    path = str(_LIZARD_SITE)
    if path not in sys.path:
        sys.path.insert(0, path)
    try:
        for module_name in ("lizard", "lizard_ext", "lizard_languages"):
            existing = sys.modules.get(module_name)
            existing_path = getattr(existing, "__file__", None) if existing is not None else None
            if existing is None:
                continue
            try:
                if not existing_path:
                    raise ValueError("existing Lizard module has no file identity")
                Path(existing_path).resolve().relative_to(_LIZARD_SITE.resolve())
            except (OSError, ValueError):
                # A caller may have imported a global Lizard before Dissect.
                # Do not silently use it, because the fallback must remain
                # the exact skill-local 1.24.0 implementation.
                for loaded_name in tuple(sys.modules):
                    if loaded_name == module_name or loaded_name.startswith(module_name + "."):
                        sys.modules.pop(loaded_name, None)
        module = importlib.import_module("lizard")
    except (ImportError, OSError, ValueError):
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


def lizard_available() -> bool:
    """Return whether the exact skill-local fallback is loaded."""
    return _LIZARD is not None


def _is_test_path(path: str) -> bool:
    lower = path.lower().replace("\\", "/")
    name = Path(lower).name
    return bool(
        re.search(r"(?:^|/)(?:test|tests|spec|specs|__tests__|testdata|fixtures?)(?:/|$)", lower)
        or re.search(r"^(?:test|spec)[._-]", name)
        or re.search(r"[._-](?:test|spec)[._-]", name)
        or name.endswith("_test.go")
    )


def _python_has_test_declaration(text: str) -> bool:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, TypeError):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            bases = {
                base.id if isinstance(base, ast.Name)
                else base.attr if isinstance(base, ast.Attribute)
                else ""
                for base in node.bases
            }
            if "TestCase" in bases:
                return True
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if re.match(r"^test(?:_|$)", node.name, re.I):
            return True
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if isinstance(target, ast.Attribute) and target.attr in {"fixture", "parametrize"}:
                return True
    return False


def _is_test_function(path: str, name: str, text: str) -> bool:
    suffix = Path(path).suffix.lower()
    return _is_test_path(path) if suffix not in {".py", ".pyi"} else _python_has_test_declaration(text)


def _decode_source(path: str, data: bytes) -> str:
    """Decode Python using its declared source encoding before parsing."""
    if Path(path).suffix.lower() in {".py", ".pyi"}:
        try:
            encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
            return data.decode(encoding)
        except (SyntaxError, UnicodeDecodeError, LookupError) as error:
            raise SyntaxError(f"{path}: invalid source encoding") from error
    return data.decode("utf-8", errors="replace")


def source_parse_error(path: str, source: bytes | str) -> str | None:
    """Return a bounded syntax error before handing source to Lizard.

    Lizard is a metrics parser, not a compiler. Some malformed C-like files
    therefore produce partial function records instead of an error. The
    language-specific interpreter check covers Python; balanced delimiters are
    the conservative minimum for the other accepted source languages.
    """
    data = source if isinstance(source, bytes) else source.encode("utf-8", errors="surrogatepass")
    text = _decode_source(path, data)
    if b"\0" in data[:4096]:
        return "binary_source"
    if Path(path).suffix.lower() in {".py", ".pyi"}:
        try:
            ast.parse(text, filename=path, type_comments=True)
        except (SyntaxError, ValueError, TypeError):
            return "parse_error"
        return None
    return balanced_delimiter_error(path, data)


def extract_functions(path: str, source: bytes | str, *, source_kind: str = "working-tree") -> tuple[ComplexityFunction, ...]:
    data = source if isinstance(source, bytes) else source.encode("utf-8", errors="surrogatepass")
    text = _decode_source(path, data)
    digest = sha256_bytes(data)
    parse_error = source_parse_error(path, data)
    if parse_error is not None:
        raise SyntaxError(f"{path}: {parse_error}")
    if _LIZARD is None:
        raise RuntimeError("the exact skill-local Lizard fallback is unavailable")
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
                _is_test_function(path, name, text), str(getattr(info, "long_name", "")), "complete",
            ))
        return tuple(sorted(functions, key=lambda item: (item.logical_path, item.start_line, item.qualified_name)))
    except (AttributeError, SyntaxError, TypeError, ValueError) as error:
        # Lizard is the approved fallback analyser. Do not hide a parser
        # failure behind a second, uncalibrated complexity implementation.
        raise SyntaxError(f"{path}: Lizard could not analyse the source") from error


def analyse_source(path: str, source: bytes | str, *, source_kind: str = "working-tree", configured_threshold: int | None = None, fallback_threshold: int = 15, root: Path | None = None) -> tuple[tuple[ComplexityFunction, ...], dict[str, Any]]:
    spec = language_for_path(path)
    language = "c" if spec is not None and spec.language_id == "c-header" else spec.language_id if spec is not None else ""
    policy = resolve_policy(root or Path.cwd(), language, configured_threshold=configured_threshold, fallback_threshold=fallback_threshold)
    return extract_functions(path, source, source_kind=source_kind), {**policy, "language_id": language, "backend": "lizard-fallback", "tool": "lizard", "tool_version": LIZARD_VERSION}
