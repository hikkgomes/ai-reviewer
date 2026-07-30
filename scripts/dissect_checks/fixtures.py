from __future__ import annotations

import ast
from functools import lru_cache
import hashlib
import json
from pathlib import Path


_MANIFEST_VERSION = 2
_SELF_REVIEW_DOMAIN = b"dissect-trusted-self-review-v2\0"
_STRUCTURED_RULE_PATH = "scripts/dissect_checks/rules.py"
_LEGACY_RULE_PATH = "scripts/dissect_checks/legacy.py"
_FIXTURE_REGISTRY_PATH = "scripts/dissect_checks/fixtures.py"
_TEST_PREFIX = "tests/"
_HISTORICAL_SYNTHETIC_VALUES = (
    "sk_live_1234567890abcdefghij",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _skill_root() -> Path:
    return Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def _trusted_fixture_manifest() -> dict:
    """Build the versioned fixture manifest from the executing skill copy."""
    root = _skill_root()
    fixture_paths = {
        _STRUCTURED_RULE_PATH,
        _LEGACY_RULE_PATH,
        _FIXTURE_REGISTRY_PATH,
        *(
            path.relative_to(root).as_posix()
            for path in (root / "tests").rglob("*.py")
            if path.is_file()
        ),
    }
    fixtures = {}
    for path in sorted(fixture_paths):
        try:
            raw = (root / path).read_bytes()
            tree = ast.parse(raw.decode("utf-8"))
        except (OSError, SyntaxError):
            continue
        node_digests = {
            _sha256(ast.dump(node, include_attributes=False).encode("utf-8"))
            for node in _fixture_nodes(path, tree)
        }
        if node_digests:
            fixtures[path] = {
                "file_sha256": _sha256(raw),
                "ast_sha256": _sha256(
                    ast.dump(tree, include_attributes=False).encode("utf-8")
                ),
                "node_digests": frozenset(node_digests),
            }
    return {
        "version": _MANIFEST_VERSION,
        "fixtures": fixtures,
    }


def _manifest_digest(manifest: dict) -> str:
    serializable = {
        "version": manifest.get("version"),
        "fixtures": {
            path: {
                "file_sha256": values["file_sha256"],
                "ast_sha256": values["ast_sha256"],
                "node_digests": sorted(values["node_digests"]),
            }
            for path, values in sorted((manifest.get("fixtures") or {}).items())
        },
    }
    encoded = json.dumps(
        serializable,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _sha256(encoded)


def _checkout_identity(root: Path) -> dict | None:
    try:
        resolved_root = root.resolve(strict=True)
        git_marker = resolved_root / ".git"
        marker_stat = git_marker.stat()
        root_stat = resolved_root.stat()
    except OSError:
        return None
    return {
        "root": str(resolved_root),
        "root_device": root_stat.st_dev,
        "root_inode": root_stat.st_ino,
        "git_marker_device": marker_stat.st_dev,
        "git_marker_inode": marker_stat.st_ino,
        "git_marker_kind": "directory" if git_marker.is_dir() else "file",
    }


def trusted_self_review_plan(root: Path) -> dict | None:
    """Bind explicit self-review approval to this checkout and fixture file state."""
    manifest = _trusted_fixture_manifest()
    if manifest.get("version") != _MANIFEST_VERSION:
        return None
    identity = _checkout_identity(root)
    if identity is None:
        return None
    target_files = {}
    try:
        for path in manifest["fixtures"]:
            target_files[path] = _sha256((root / path).read_bytes())
    except OSError:
        return None
    return {
        "schema_version": _MANIFEST_VERSION,
        "manifest_sha256": _manifest_digest(manifest),
        "checkout": identity,
        "target_fixture_files": target_files,
    }


def trusted_self_review_digest(root: Path) -> str | None:
    plan = trusted_self_review_plan(root)
    if plan is None:
        return None
    encoded = json.dumps(
        plan,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8", errors="surrogatepass")
    return hashlib.sha256(_SELF_REVIEW_DOMAIN + encoded).hexdigest()


def is_trusted_self_review(root: Path, approval_digest: str) -> bool:
    expected = trusted_self_review_digest(root)
    return bool(
        expected
        and len(approval_digest) == 64
        and approval_digest == expected
    )


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


def mask_owned_fixture_spans(
    root: Path,
    path: str,
    text: str,
    approval_digest: str = "",
) -> str:
    """Blank only AST-proven fixture literals owned by Dissect itself."""
    if not is_trusted_self_review(root, approval_digest):
        return text
    fixture_entry = _trusted_fixture_manifest().get("fixtures", {}).get(path)
    if not fixture_entry:
        return text
    allowed_digests = fixture_entry["node_digests"]
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return text
    lines = text.splitlines(keepends=True)
    spans = []
    for node in _fixture_nodes(path, tree):
        digest = _sha256(ast.dump(node, include_attributes=False).encode("utf-8"))
        if digest not in allowed_digests:
            continue
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
