"""Standard-library Python AST anti-slop checks."""
from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import io
from pathlib import Path
import tokenize
from typing import Sequence

from analysis_budget import AnalysisBudget, AnalysisBudgetExceeded
from .model import AnalysisTarget, BackendDiagnostic, BackendResult


BACKEND_ID = "python-ast"
LANGUAGES = ("python",)
MAX_FILE_BYTES = 10 * 1024 * 1024


def _decode_source(data: bytes) -> str:
    encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
    return data.decode(encoding)


@dataclass
class _Names:
    cast_names: set[str]
    any_names: set[str]
    typing_modules: set[str]


class _ImportVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names = _Names(set(), set(), set())

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            if item.name in {"typing", "typing_extensions"}:
                self.names.typing_modules.add(item.asname or item.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module in {"typing", "typing_extensions"}:
            for item in node.names:
                if item.name == "cast":
                    self.names.cast_names.add(item.asname or item.name)
                elif item.name == "Any":
                    self.names.any_names.add(item.asname or item.name)
        self.generic_visit(node)


def _attribute(node: ast.AST, modules: set[str], name: str) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == name and isinstance(node.value, ast.Name) and node.value.id in modules


def _is_cast(node: ast.AST, names: _Names) -> bool:
    return (isinstance(node, ast.Name) and node.id in names.cast_names) or _attribute(node, names.typing_modules, "cast")


def _is_widening_type(node: ast.AST, names: _Names) -> bool:
    if isinstance(node, ast.Name):
        return node.id == "object" or node.id in names.any_names
    return _attribute(node, names.typing_modules, "Any")


def _parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    return parents


def _container_has_dynamic_protocol(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    current = parents.get(node)
    while current is not None:
        if isinstance(current, (ast.ClassDef, ast.Module)):
            for child in current.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name in {"__getattr__", "__getattribute__"}:
                    return True
            if isinstance(current, ast.ClassDef):
                return False
        current = parents.get(current)
    return False


def _reflection_receiver(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return any(token in node.id.lower() for token in ("proxy", "reflect", "dynamic", "delegate"))
    if isinstance(node, ast.Attribute):
        return any(token in node.attr.lower() for token in ("proxy", "reflect", "dynamic", "delegate"))
    return False


def _location(node: ast.AST) -> tuple[int, int]:
    return max(1, int(getattr(node, "lineno", 1))), max(0, int(getattr(node, "col_offset", 0)))


def _diagnostics(tree: ast.AST, target: AnalysisTarget, names: _Names) -> list[BackendDiagnostic]:
    parents = _parent_map(tree)
    diagnostics: list[BackendDiagnostic] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_cast(node.func, names) and len(node.args) >= 2:
            inner = node.args[1]
            if isinstance(inner, ast.Call) and _is_cast(inner.func, names) and len(inner.args) >= 2 and _is_widening_type(inner.args[0], names):
                line, column = _location(node)
                diagnostics.append(BackendDiagnostic(
                    BACKEND_ID,
                    "python",
                    "anti-slop-python/no-widen-then-cast",
                    target.logical_path,
                    line,
                    column,
                    "A value is widened and immediately narrowed by nested typing.cast calls.",
                    {"confidence": "high", "source_layer": target.source_kind, "content_sha256": target.content_sha256},
                ))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr":
            if len(node.args) != 2 or node.keywords:
                continue
            name = node.args[1]
            if not isinstance(name, ast.Constant) or not isinstance(name.value, str) or not name.value.isidentifier() or name.value.startswith("__"):
                continue
            if _reflection_receiver(node.args[0]) or _container_has_dynamic_protocol(node, parents):
                continue
            line, column = _location(node)
            diagnostics.append(BackendDiagnostic(
                BACKEND_ID,
                "python",
                "anti-slop-python/no-literal-getattr-without-default",
                target.logical_path,
                line,
                column,
                "Literal attribute lookup has no default and may hide a direct attribute contract.",
                {"confidence": "medium", "source_layer": target.source_kind, "content_sha256": target.content_sha256},
            ))
    return diagnostics


def analyse(
    root: Path,
    targets: Sequence[AnalysisTarget],
    budget: AnalysisBudget,
    *,
    max_file_bytes: int = MAX_FILE_BYTES,
) -> BackendResult:
    applicable = tuple(sorted((target for target in targets if target.language_id == "python"), key=lambda item: item.logical_path))
    if not applicable:
        return BackendResult(BACKEND_ID, "structural", LANGUAGES, "not_applicable", 0, 0, 0, [], None, "No applicable Python files.")
    diagnostics: list[BackendDiagnostic] = []
    skipped = 0
    checked = 0
    reason_code: str | None = None
    for target in applicable:
        try:
            budget.claim_file()
            size = target.physical_path.stat().st_size
            if size > max_file_bytes:
                raise AnalysisBudgetExceeded("max_file_bytes", "Python file exceeds the structural analysis limit")
            with target.physical_path.open("rb") as source_file:
                data = source_file.read(max_file_bytes + 1)
            if len(data) > max_file_bytes:
                raise AnalysisBudgetExceeded("max_file_bytes", "Python file exceeds the structural analysis limit")
            budget.claim_bytes(len(data))
            if b"\0" in data[:4096]:
                raise AnalysisBudgetExceeded("binary_source", "NUL byte in Python source prefix")
            source = _decode_source(data)
            tree = ast.parse(source, filename=target.logical_path, type_comments=True)
            budget.check_deadline()
            imports = _ImportVisitor()
            imports.visit(tree)
            diagnostics.extend(_diagnostics(tree, target, imports.names))
            budget.check_deadline()
            checked += 1
        except AnalysisBudgetExceeded as error:
            skipped += 1
            reason_code = reason_code or error.reason_code
        except (OSError, SyntaxError, IndentationError, UnicodeError, ValueError):
            skipped += 1
            reason_code = reason_code or "parse_error"
        except Exception:
            skipped += 1
            reason_code = reason_code or "internal_failure"
    diagnostics.sort(key=lambda item: (item.path, item.line, item.column, item.rule_id, item.message))
    if skipped:
        status = "partial" if checked else "unavailable"
        reason = "Some Python files could not be structurally analysed." if checked else "No applicable Python file completed structural analysis."
    else:
        status = "complete"
        reason = "Completed."
    return BackendResult(BACKEND_ID, "structural", LANGUAGES, status, len(applicable), checked, skipped, diagnostics, reason_code, reason)
