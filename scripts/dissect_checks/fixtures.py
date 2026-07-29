from __future__ import annotations

import ast
from pathlib import Path


_STRUCTURED_RULE_PATH = "scripts/dissect_checks/rules.py"
_LEGACY_RULE_PATH = "scripts/dissect_checks/legacy.py"
_FIXTURE_REGISTRY_PATH = "scripts/dissect_checks/fixtures.py"
_TEST_PREFIX = "tests/"
_HISTORICAL_SYNTHETIC_VALUES = (
    "sk_live_1234567890abcdefghij",
)


def is_owned_dissect_root(root: Path) -> bool:
    try:
        return (
            (root / "scripts" / "dissect_checks" / "fixtures.py").resolve()
            == Path(__file__).resolve()
            and
            (root / "scripts" / "scan_ai_gotchas.py").is_file()
            and "name: dissect" in (root / "SKILL.md").read_text(encoding="utf-8")
        )
    except OSError:
        return False


def _call_name(node: ast.Call) -> str:
    return node.func.id if isinstance(node.func, ast.Name) else ""


def _fixture_nodes(path: str, tree: ast.AST) -> list[ast.AST]:
    nodes = []
    for node in ast.walk(tree):
        if (
            path == _FIXTURE_REGISTRY_PATH
            and isinstance(node, (ast.Assign, ast.AnnAssign))
        ):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(
                isinstance(target, ast.Name)
                and target.id == "_HISTORICAL_SYNTHETIC_VALUES"
                for target in targets
            ):
                nodes.append(node.value)
            continue
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if path == _STRUCTURED_RULE_PATH and name == "Rule" and len(node.args) >= 9:
            nodes.extend(node.args[7:9])
        elif path == _LEGACY_RULE_PATH and name == "_rule" and len(node.args) >= 5:
            nodes.extend(node.args[3:5])
        elif path.startswith(_TEST_PREFIX) and name == "synthetic" and node.args:
            nodes.append(node.args[0])
    if path.startswith(_TEST_PREFIX):
        nodes.extend(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and any(value in node.value for value in _HISTORICAL_SYNTHETIC_VALUES)
        )
    return nodes


def _character_offset(lines: list[str], line: int, byte_column: int) -> int:
    prefix = lines[line - 1].encode("utf-8")[:byte_column]
    return sum(len(value) for value in lines[:line - 1]) + len(
        prefix.decode("utf-8", errors="ignore")
    )


def mask_owned_fixture_spans(root: Path, path: str, text: str) -> str:
    """Blank only AST-proven fixture literals owned by Dissect itself."""
    if not is_owned_dissect_root(root):
        return text
    if path not in {
        _STRUCTURED_RULE_PATH, _LEGACY_RULE_PATH, _FIXTURE_REGISTRY_PATH,
    } and not (
        path.startswith(_TEST_PREFIX) and path.endswith(".py")
    ):
        return text
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return text
    lines = text.splitlines(keepends=True)
    spans = []
    for node in _fixture_nodes(path, tree):
        if not all(hasattr(node, attr) for attr in ("lineno", "col_offset", "end_lineno", "end_col_offset")):
            continue
        start = _character_offset(lines, node.lineno, node.col_offset)
        end = _character_offset(lines, node.end_lineno, node.end_col_offset)
        spans.append((start, end))
    if not spans:
        return text
    masked = list(text)
    for start, end in spans:
        for index in range(start, end):
            if masked[index] not in "\r\n":
                masked[index] = " "
    return "".join(masked)
