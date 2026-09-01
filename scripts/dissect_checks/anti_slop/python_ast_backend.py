"""Standard-library Python AST anti-slop checks."""
from __future__ import annotations

import ast
from dataclasses import dataclass
import io
from pathlib import Path
import tokenize
from typing import Any, Sequence

from analysis_budget import AnalysisBudget, AnalysisBudgetExceeded
from .model import AnalysisTarget, BackendDiagnostic, BackendResult, LoadedAnalysisTarget, load_target


BACKEND_ID = "python-ast"
LANGUAGES = ("python",)
MAX_FILE_BYTES = 10 * 1024 * 1024


def _decode_source(data: bytes) -> str:
    encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
    return data.decode(encoding)


@dataclass(frozen=True)
class _BindingEvent:
    position: tuple[int, int]
    kind: str


@dataclass
class _Scope:
    node: ast.AST | None
    parent: "_Scope | None"
    kind: str
    class_node: ast.ClassDef | None = None
    declared: set[str] = None  # type: ignore[assignment]
    global_names: set[str] = None  # type: ignore[assignment]
    nonlocal_names: set[str] = None  # type: ignore[assignment]
    events: dict[str, list[_BindingEvent]] = None  # type: ignore[assignment]
    children: list["_Scope"] = None  # type: ignore[assignment]
    lexical_names: set[str] = None  # type: ignore[assignment]
    receiver_name: str = ""

    def __post_init__(self) -> None:
        self.declared = set()
        self.global_names = set()
        self.nonlocal_names = set()
        self.events = {}
        self.children = []
        self.lexical_names = set()


class _LexicalBindings(ast.NodeVisitor):
    """Resolve only the import and rebinding facts needed by narrow rules.

    This is deliberately lexical. It does not infer runtime types and therefore
    stops a rule when a name may have been rebound in the current scope.
    """

    def __init__(self, tree: ast.AST) -> None:
        self.root = _Scope(tree, None, "module")
        self.current = self.root
        self.node_scopes: dict[ast.AST, _Scope] = {}
        self.visit(tree)
        for scope in self._scopes():
            for events in scope.events.values():
                events.sort(key=lambda item: item.position)

    def _scopes(self) -> list[_Scope]:
        output: list[_Scope] = []
        pending = [self.root]
        while pending:
            scope = pending.pop()
            output.append(scope)
            pending.extend(reversed(scope.children))
        return output

    @staticmethod
    def _position(node: ast.AST | None) -> tuple[int, int]:
        return (
            max(0, int(getattr(node, "lineno", 0) or 0)),
            max(0, int(getattr(node, "col_offset", 0) or 0)),
        )

    def _record(self, name: str, kind: str = "unknown", node: ast.AST | None = None) -> None:
        if not name or name == "_":
            return
        position = self._position(node)
        scope = self.current
        if name in scope.global_names and scope.parent is not None:
            scope = self.root
        elif name in scope.nonlocal_names:
            parent = scope.parent
            while parent is not None and parent.kind == "class":
                parent = parent.parent
            if parent is not None:
                scope = parent
        scope.declared.add(name)
        scope.events.setdefault(name, []).append(_BindingEvent(position, kind))

    def _record_target(self, node: ast.AST, kind: str = "unknown") -> None:
        if isinstance(node, ast.Name):
            self._record(node.id, kind, node)
        elif isinstance(node, (ast.Tuple, ast.List)):
            for element in node.elts:
                self._record_target(element, "unknown")
        elif isinstance(node, ast.Starred):
            self._record_target(node.value, "unknown")
        else:
            self.visit(node)

    def _push(self, node: ast.AST, kind: str, class_node: ast.ClassDef | None = None) -> _Scope:
        inherited_class = class_node
        if inherited_class is None and self.current.kind == "class":
            inherited_class = self.current.class_node if isinstance(self.current.node, ast.ClassDef) else None
        scope = _Scope(node, self.current, kind, inherited_class)
        self.node_scopes[node] = scope
        self.current.children.append(scope)
        self.current = scope
        return scope

    @staticmethod
    def _scope_bindings(node: ast.AST, scope: _Scope) -> None:
        """Collect function-local bindings before resolving any call.

        Python determines whether a name is local for the whole function, not
        only after the assignment executes. Without this pre-pass a later
        ``cast = ...`` or ``getattr = ...`` could incorrectly leave an earlier
        call resolved to the module import.
        """
        class Collector(ast.NodeVisitor):
            def visit_Name(self, item: ast.Name) -> None:
                if isinstance(item.ctx, (ast.Store, ast.Del)):
                    scope.lexical_names.add(item.id)

            def visit_Import(self, item: ast.Import) -> None:
                for alias in item.names:
                    scope.lexical_names.add(alias.asname or alias.name.split(".")[0])

            def visit_ImportFrom(self, item: ast.ImportFrom) -> None:
                for alias in item.names:
                    if alias.name != "*":
                        scope.lexical_names.add(alias.asname or alias.name)

            def visit_Global(self, item: ast.Global) -> None:
                scope.global_names.update(item.names)

            def visit_Nonlocal(self, item: ast.Nonlocal) -> None:
                scope.nonlocal_names.update(item.names)

            def visit_ExceptHandler(self, item: ast.ExceptHandler) -> None:
                if item.name:
                    scope.lexical_names.add(item.name)
                for statement in item.body:
                    self.visit(statement)

            def visit_FunctionDef(self, item: ast.FunctionDef) -> None:
                scope.lexical_names.add(item.name)

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_ClassDef(self, item: ast.ClassDef) -> None:
                scope.lexical_names.add(item.name)

            def visit_Lambda(self, _item: ast.Lambda) -> None:
                return

            def visit_ListComp(self, _item: ast.ListComp) -> None:
                return

            visit_SetComp = visit_ListComp
            visit_DictComp = visit_ListComp
            visit_GeneratorExp = visit_ListComp

        collector = Collector()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arguments = [
                *getattr(node.args, "posonlyargs", []), *node.args.args,
                *node.args.kwonlyargs,
            ]
            if node.args.vararg is not None:
                arguments.append(node.args.vararg)
            if node.args.kwarg is not None:
                arguments.append(node.args.kwarg)
            scope.lexical_names.update(argument.arg for argument in arguments)
            for statement in node.body:
                collector.visit(statement)
        elif isinstance(node, ast.Lambda):
            arguments = [*getattr(node.args, "posonlyargs", []), *node.args.args, *node.args.kwonlyargs]
            if node.args.vararg is not None:
                arguments.append(node.args.vararg)
            if node.args.kwarg is not None:
                arguments.append(node.args.kwarg)
            scope.lexical_names.update(argument.arg for argument in arguments)
        scope.lexical_names.difference_update(scope.global_names)
        scope.lexical_names.difference_update(scope.nonlocal_names)

    def _pop(self, previous: _Scope) -> None:
        self.current = previous

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.node_scopes[node] = self.current
        self._record(node.name, "unknown", node)
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        if node.returns is not None:
            self.visit(node.returns)
        previous = self.current
        class_node = previous.class_node if previous.kind == "class" else previous.class_node
        function_scope = self._push(node, "function", class_node)
        self._scope_bindings(node, function_scope)
        arguments = [
            *getattr(node.args, "posonlyargs", []), *node.args.args,
            *node.args.kwonlyargs,
        ]
        if node.args.vararg is not None:
            arguments.append(node.args.vararg)
        if node.args.kwarg is not None:
            arguments.append(node.args.kwarg)
        for argument_index, argument in enumerate(arguments):
            receiver = (
                previous.kind == "class"
                and argument_index == 0
                and argument.arg in {"self", "cls"}
                and not any(
                    isinstance(decorator, ast.Name) and decorator.id == "staticmethod"
                    for decorator in node.decorator_list
                )
            )
            if receiver:
                function_scope.receiver_name = argument.arg
            self._record(argument.arg, "method_receiver" if receiver else "unknown", argument)
            if argument.annotation is not None:
                self.visit(argument.annotation)
        for statement in node.body:
            self.visit(statement)
        self._pop(previous)
        assert function_scope.parent is previous

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.node_scopes[node] = self.current
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        previous = self.current
        function_scope = self._push(node, "function", previous.class_node)
        self._scope_bindings(node, function_scope)
        arguments = [*getattr(node.args, "posonlyargs", []), *node.args.args, *node.args.kwonlyargs]
        if node.args.vararg is not None:
            arguments.append(node.args.vararg)
        if node.args.kwarg is not None:
            arguments.append(node.args.kwarg)
        for argument in arguments:
            self._record(argument.arg, "unknown", argument)
        self.visit(node.body)
        self._pop(previous)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.node_scopes[node] = self.current
        self._record(node.name, "unknown", node)
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        previous = self.current
        class_scope = self._push(node, "class", node)
        for statement in node.body:
            self.visit(statement)
        self._pop(previous)
        assert class_scope.parent is previous

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            bound = item.asname or item.name.split(".")[0]
            kind = (
                "typing_module" if item.name in {"typing", "typing_extensions"}
                else "builtins_module" if item.name == "builtins"
                else "unknown"
            )
            self._record(bound, kind, node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for item in node.names:
            if item.name == "*":
                continue
            bound = item.asname or item.name
            kind = "unknown"
            if module in {"typing", "typing_extensions"} and item.name == "cast":
                kind = "typing.cast"
            elif module in {"typing", "typing_extensions"} and item.name == "Any":
                kind = "typing.Any"
            elif module == "builtins" and item.name == "getattr":
                kind = "builtin:getattr"
            self._record(bound, kind, node)

    def visit_Global(self, node: ast.Global) -> None:
        self.current.global_names.update(node.names)
        self.current.declared.difference_update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.current.nonlocal_names.update(node.names)
        self.current.declared.difference_update(node.names)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._record(node.id, "unknown", node)

    def _assignment_kind(self, value: ast.AST) -> str:
        return _expression_kind(value, self.current, self._position(value), self)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        kind = self._assignment_kind(node.value)
        for target in node.targets:
            self._record_target(target, kind if isinstance(target, ast.Name) else "unknown")

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)
        self._record_target(node.target, self._assignment_kind(node.value) if node.value is not None else "unknown")

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._record_target(node.target, self._assignment_kind(node.value))

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is not None:
            self.visit(node.type)
        if node.name:
            self._record(node.name, "unknown", node)
        for statement in node.body:
            self.visit(statement)

    def generic_visit(self, node: ast.AST) -> None:
        self.node_scopes.setdefault(node, self.current)
        super().generic_visit(node)


def _nearest_non_class(scope: _Scope | None) -> _Scope | None:
    while scope is not None and scope.kind == "class":
        scope = scope.parent
    return scope


def _resolve(scope: _Scope | None, name: str, position: tuple[int, int], tracker: _LexicalBindings) -> str:
    if scope is None:
        return "unknown"
    origin = scope
    lookup = scope
    while lookup is not None:
        if name in lookup.global_names:
            lookup = tracker.root
        elif name in lookup.nonlocal_names:
            lookup = _nearest_non_class(lookup.parent)
            if lookup is None:
                return "unknown"
        if name in lookup.declared:
            events = lookup.events.get(name, ())
            if lookup.kind == "module" and origin.kind != "module" and events:
                # Function bodies run after the complete module has executed,
                # so a later module-level rebind wins over an earlier import.
                return events[-1].kind if len(events) == 1 else "unknown"
            current = [event.kind for event in events if event.position <= position]
            return current[-1] if current else "unknown"
        if lookup.kind == "function" and name in lookup.lexical_names:
            return "unknown"
        if lookup.kind == "module":
            events = lookup.events.get(name, ())
            if events:
                # A function body runs after module execution. A later
                # module-level rebinding therefore changes what an unqualified
                # call in that function resolves to, even when the rebinding
                # appears below the function declaration in the source.
                if origin.kind != "module":
                    return events[-1].kind if len(events) == 1 else "unknown"
                current = [event.kind for event in events if event.position <= position]
                if current:
                    return current[-1]
            return "builtin:object" if name == "object" else "builtin:getattr" if name == "getattr" else "unknown"
        # Class attributes are not lexical closures for methods. Skip a class
        # scope while retaining the method's own locals and its real closure.
        lookup = lookup.parent
        if lookup is not None and lookup.kind == "class":
            lookup = lookup.parent
    return "unknown"


def _expression_kind(node: ast.AST | None, scope: _Scope, position: tuple[int, int], tracker: _LexicalBindings) -> str:
    if isinstance(node, ast.Name):
        return _resolve(scope, node.id, position, tracker)
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        base = _resolve(scope, node.value.id, position, tracker)
        if base == "typing_module" and node.attr == "cast":
            return "typing.cast"
        if base == "typing_module" and node.attr == "Any":
            return "typing.Any"
        if base == "builtins_module" and node.attr == "getattr":
            return "builtin:getattr"
    return "unknown"


def _call_kind(node: ast.AST, scope: _Scope, tracker: _LexicalBindings) -> str:
    return _expression_kind(node, scope, _LexicalBindings._position(node), tracker)


def _class_has_dynamic_protocol(scope: _Scope | None) -> bool:
    class_node = scope.class_node if scope is not None else None
    if class_node is None:
        return False
    return any(
        isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
        and statement.name in {"__getattr__", "__getattribute__"}
        for statement in class_node.body
    )


def _is_dynamic_receiver(
    receiver: ast.AST,
    scope: _Scope,
    position: tuple[int, int],
    tracker: _LexicalBindings,
) -> bool:
    """Return true only for the receiver parameter of this class method."""
    if not isinstance(receiver, ast.Name) or receiver.id not in {"self", "cls"}:
        return False
    if receiver.id in scope.declared and scope.receiver_name != receiver.id:
        return False
    return _resolve(scope, receiver.id, position, tracker) == "method_receiver"


def _location(node: ast.AST) -> tuple[int, int]:
    return max(1, int(getattr(node, "lineno", 1))), max(0, int(getattr(node, "col_offset", 0)))


def _diagnostics(
    tree: ast.AST,
    target: AnalysisTarget,
    _legacy_names: Any = None,
    *,
    enable_getattr: bool = False,
) -> list[BackendDiagnostic]:
    tracker = _LexicalBindings(tree)
    diagnostics: list[BackendDiagnostic] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        scope = tracker.node_scopes.get(node, tracker.root)
        if _call_kind(node.func, scope, tracker) == "typing.cast" and len(node.args) >= 2:
            inner = node.args[1]
            if (
                isinstance(inner, ast.Call)
                and _call_kind(inner.func, scope, tracker) == "typing.cast"
                and len(inner.args) >= 2
                and _expression_kind(inner.args[0], scope, _LexicalBindings._position(inner.args[0]), tracker) in {"typing.Any", "builtin:object"}
            ):
                line, column = _location(node)
                diagnostics.append(BackendDiagnostic(
                    BACKEND_ID,
                    "python",
                    "anti-slop-python/no-widen-then-cast",
                    target.logical_path,
                    line,
                    column,
                    "A value is widened and immediately narrowed by nested typing.cast calls.",
                    {
                        "confidence": "high", "source_layer": target.source_kind,
                        "content_sha256": target.content_sha256,
                        "rule_discriminator": f"nested-cast:{line}:{column}",
                    },
                ))
        if enable_getattr and _call_kind(node.func, scope, tracker) == "builtin:getattr":
            if len(node.args) != 2 or node.keywords:
                continue
            name = node.args[1]
            if not isinstance(name, ast.Constant) or not isinstance(name.value, str) or not name.value.isidentifier() or name.value.startswith("__"):
                continue
            receiver = node.args[0]
            dynamic_receiver = (
                _class_has_dynamic_protocol(scope)
                and _is_dynamic_receiver(
                    receiver,
                    scope,
                    _LexicalBindings._position(receiver),
                    tracker,
                )
            )
            if dynamic_receiver:
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
                {
                    "confidence": "medium", "source_layer": target.source_kind,
                    "content_sha256": target.content_sha256,
                    "rule_discriminator": f"literal-getattr:{line}:{column}",
                },
            ))
    return sorted(diagnostics, key=lambda item: (item.path, item.line, item.column, item.rule_id, item.message))


def analyse(
    root: Path,
    targets: Sequence[AnalysisTarget],
    budget: AnalysisBudget,
    *,
    max_file_bytes: int = MAX_FILE_BYTES,
    enable_getattr: bool = False,
) -> BackendResult:
    applicable = tuple(sorted((target for target in targets if target.language_id == "python"), key=lambda item: item.logical_path))
    if not applicable:
        return BackendResult(BACKEND_ID, "structural", LANGUAGES, "not_applicable", 0, 0, 0, [], None, "No applicable Python files.")
    diagnostics: list[BackendDiagnostic] = []
    skipped = 0
    checked = 0
    reason_code: str | None = None
    parse_states: dict[str, str] = {}
    parse_errors: list[dict[str, str]] = []
    for index, target in enumerate(applicable):
        try:
            loaded = target if isinstance(target, LoadedAnalysisTarget) else load_target(
                root, target, budget, max_file_bytes=max_file_bytes,
            )
            target = loaded.target
            data = loaded.data
            source = _decode_source(data)
            tree = ast.parse(source, filename=target.logical_path, type_comments=True)
            budget.check_deadline()
            diagnostics.extend(_diagnostics(tree, target, enable_getattr=enable_getattr))
            budget.check_deadline()
            checked += 1
            parse_states[target.target_id] = "complete"
        except AnalysisBudgetExceeded as error:
            skipped += 1
            reason_code = reason_code or error.reason_code
            parse_states[target.target_id] = "failed"
            parse_errors.append({"path": target.logical_path, "reason_code": error.reason_code})
            if error.reason_code in {"total_timeout", "max_files", "max_total_bytes"}:
                for remaining in applicable[index + 1:]:
                    remaining_target = remaining.target if isinstance(remaining, LoadedAnalysisTarget) else remaining
                    parse_states[remaining_target.target_id] = "not_verified"
                skipped += len(applicable) - index - 1
                break
        except (OSError, SyntaxError, IndentationError, UnicodeError, ValueError) as error:
            skipped += 1
            reason_code = reason_code or "parse_error"
            parse_states[target.target_id] = "failed"
            parse_errors.append({"path": target.logical_path, "reason_code": "parse_error", "detail": str(error)[:240]})
        except Exception:
            skipped += 1
            reason_code = reason_code or "internal_failure"
            parse_states[target.target_id] = "failed"
            parse_errors.append({"path": target.logical_path, "reason_code": "internal_failure"})
    diagnostics.sort(key=lambda item: (item.path, item.line, item.column, item.rule_id, item.message))
    if skipped:
        status = "partial" if checked else "unavailable"
        reason = "Some Python files could not be structurally analysed." if checked else "No applicable Python file completed structural analysis."
    else:
        status = "complete"
        reason = "Completed."
    return BackendResult(
        BACKEND_ID, "structural", LANGUAGES, status, len(applicable), checked,
        skipped, diagnostics, reason_code, reason, parse_states, parse_errors,
    )
