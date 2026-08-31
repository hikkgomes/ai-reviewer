"""Canonical source-language and analyser capability registry.

The registry is intentionally extension based.  It decides applicability only;
parsers and analysers remain responsible for validating source content.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Iterable


@dataclass(frozen=True)
class LanguageSpec:
    language_id: str
    display_name: str
    suffixes: frozenset[str]
    reference_pack: str | None = None
    comment_style: str | None = None
    anti_slop_backend: str | None = None
    ast_grep_language: str | None = None
    public_language_id: str | None = None


_SPECS = (
    LanguageSpec("javascript", "JavaScript", frozenset({".js", ".jsx", ".mjs", ".cjs"}), "javascript", "slash", "oxlint-js-ts"),
    LanguageSpec("typescript", "TypeScript", frozenset({".ts", ".tsx", ".mts", ".cts"}), "typescript", "slash", "oxlint-js-ts"),
    LanguageSpec("python", "Python", frozenset({".py", ".pyi"}), "python", "hash", "python-ast"),
    LanguageSpec("go", "Go", frozenset({".go"}), "go", "slash", "ast-grep-go", "go"),
    LanguageSpec("rust", "Rust", frozenset({".rs"}), "rust", "slash", "ast-grep-rust", "rust"),
    # The detector historically reported both C and C++ as ``cpp``.  Keep
    # that public label while retaining a distinct internal backend language.
    LanguageSpec("c", "C", frozenset({".c"}), "cpp", "slash", "ast-grep-c", "c", "cpp"),
    LanguageSpec("cpp", "C++", frozenset({".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".ipp", ".tpp"}), "cpp", "slash", "ast-grep-cpp", "cpp"),
    LanguageSpec("java", "Java", frozenset({".java"}), "java-csharp", "slash", "ast-grep-java", "java", "java-csharp"),
    LanguageSpec("csharp", "C#", frozenset({".cs"}), "java-csharp", "slash", "ast-grep-csharp", "csharp", "java-csharp"),
    LanguageSpec("sql", "SQL", frozenset({".sql"}), "sql", "sql"),
    LanguageSpec("php", "PHP", frozenset({".php"}), "php", "slash+hash"),
    LanguageSpec("ruby", "Ruby", frozenset({".rb"}), None, "hash"),
    LanguageSpec("terraform", "Terraform", frozenset({".tf", ".tfvars"}), None, "slash+hash"),
    LanguageSpec("yaml", "YAML", frozenset({".yml", ".yaml"}), None, "hash"),
    LanguageSpec("kotlin", "Kotlin", frozenset({".kt", ".kts"}), None, "slash"),
    LanguageSpec("swift", "Swift", frozenset({".swift"}), None, "slash"),
    LanguageSpec("shell", "Shell", frozenset({".sh", ".bash", ".zsh"}), None, "hash"),
    LanguageSpec("config", "Configuration", frozenset({".cfg", ".ini", ".toml"}), None, "hash"),
    LanguageSpec("html", "HTML", frozenset({".html", ".htm", ".xhtml"}), None, "html"),
    LanguageSpec("markdown", "Markdown", frozenset({".md"}), None, "html"),
    LanguageSpec("xml", "XML", frozenset({".xml", ".svg"}), None, "html"),
    LanguageSpec("powershell", "PowerShell", frozenset({".ps1"}), None, "hash"),
    LanguageSpec("c-header", "C/C++ header", frozenset({".h"}), "cpp", "slash", public_language_id="cpp"),
)

LANGUAGE_SPECS: tuple[LanguageSpec, ...] = _SPECS
_BY_SUFFIX = MappingProxyType({suffix: spec for spec in _SPECS for suffix in spec.suffixes})
_BY_ID = MappingProxyType({spec.language_id: spec for spec in _SPECS})


def _suffix(path: str | Path) -> str:
    return Path(path).suffix.lower()


def language_for_path(path: str | Path, *, header_language: str | None = None) -> LanguageSpec | None:
    """Return the extension specification for ``path``.

    ``.h`` is returned as ``c-header`` unless a caller has enough surrounding
    scope to resolve it explicitly to C or C++.
    """
    spec = _BY_SUFFIX.get(_suffix(path))
    if spec is None or spec.language_id != "c-header" or not header_language:
        return spec
    resolved = _BY_ID.get(header_language.lower())
    return resolved if resolved and resolved.language_id in {"c", "cpp"} else spec


def _header_language(paths: list[Path]) -> str | None:
    has_c = any(_suffix(path) == ".c" for path in paths)
    has_cpp = any(_suffix(path) in _BY_ID["cpp"].suffixes for path in paths)
    if has_c and not has_cpp:
        return "c"
    if has_cpp and not has_c:
        return "cpp"
    return None


def detect_languages(paths: Iterable[str | Path]) -> tuple[str, ...]:
    """Detect languages in stable display order for a path scope."""
    values = [Path(path) for path in paths]
    header_language = _header_language(values)
    language_ids = set()
    for path in values:
        spec = language_for_path(path, header_language=header_language)
        if spec is not None:
            language_ids.add(spec.public_language_id or spec.language_id)
    return tuple(sorted(language_ids))


def paths_for_comment_analysis(paths: Iterable[str | Path]) -> tuple[str, ...]:
    """Return only paths with a known comment syntax."""
    selected = {
        Path(path).as_posix()
        for path in paths
        if (spec := language_for_path(path)) is not None and spec.comment_style is not None
    }
    return tuple(sorted(selected))


def paths_for_anti_slop(paths: Iterable[str | Path]) -> dict[str, tuple[str, ...]]:
    """Group supported paths by structural anti-slop backend.

    Ambiguous ``.h`` files are intentionally excluded.  Callers can report
    the excluded paths with the stable ``ambiguous_header_language`` reason.
    """
    values = [Path(path) for path in paths]
    header_language = _header_language(values)
    grouped: dict[str, list[str]] = {}
    for path in values:
        spec = language_for_path(path, header_language=header_language)
        if spec is None or spec.anti_slop_backend is None:
            continue
        if path.suffix.lower() == ".h" and header_language is None:
            continue
        grouped.setdefault(spec.anti_slop_backend, []).append(path.as_posix())
    return {key: tuple(sorted(set(values))) for key, values in sorted(grouped.items())}


def ambiguous_header_paths(paths: Iterable[str | Path]) -> tuple[str, ...]:
    values = [Path(path) for path in paths]
    return tuple(sorted(path.as_posix() for path in values if _suffix(path) == ".h" and _header_language(values) is None))


def comment_style_for_path(path: str | Path) -> str | None:
    spec = language_for_path(path)
    return spec.comment_style if spec else None
