"""Evidence-first test artefact and subject inventory."""
from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from analysis_budget import AnalysisBudget, AnalysisBudgetExceeded
from file_paths import is_generated_path, is_ignored_path, iter_files
from language_registry import language_for_path
from .model import TestArtifact, TestSubject, sha256_bytes


MAX_INVENTORY_FILE_BYTES = 5 * 1024 * 1024
_TEST_PATH_RE = re.compile(r"(?:^|/)(?:test|tests|spec|specs|__tests__|testdata|fixtures?)(?:/|$)", re.I)
_TEST_NAME_RE = re.compile(r"(?:^|[._-])(test|spec)(?:[._-]|$)", re.I)
_FRAMEWORK_DEPENDENCIES = {
    "pytest": "pytest", "unittest": "python-unittest", "jest": "jest", "vitest": "vitest",
    "mocha": "mocha", "@jest/globals": "jest", "go": "go-testing", "tokio": "rust-tokio",
    "junit-jupiter": "junit5", "junit": "junit", "xunit": "xunit", "nunit": "nunit",
    "mstest": "mstest", "googletest": "googletest", "gtest": "googletest", "catch2": "catch2", "doctest": "doctest",
}


@dataclass(frozen=True)
class InventoryResult:
    artifacts: tuple[TestArtifact, ...]
    subjects: tuple[TestSubject, ...]
    relations: tuple[Mapping[str, Any], ...]
    status: str
    reason_code: str | None = None
    skipped_paths: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason_code": self.reason_code,
            "artifacts": [item.as_dict() for item in self.artifacts],
            "subjects": [item.as_dict() for item in self.subjects],
            "relations": [dict(item) for item in self.relations],
            "skipped_paths": list(self.skipped_paths),
        }


def _read(
    path: Path,
    content_by_path: Mapping[str, bytes | str] | None,
    limit: int = MAX_INVENTORY_FILE_BYTES,
    *,
    logical_path: str | None = None,
) -> bytes | None:
    keys = (logical_path, path.as_posix()) if logical_path is not None else (path.as_posix(),)
    if content_by_path is not None and (key := next((item for item in keys if item in content_by_path), None)) is not None:
        value = content_by_path[key]
        data = value if isinstance(value, bytes) else value.encode("utf-8", errors="surrogatepass")
        return data[:limit + 1]
    if content_by_path is not None:
        return None
    try:
        size = path.stat().st_size
        if size > limit:
            return b"\0" * (limit + 1)
        with path.open("rb") as handle:
            return handle.read(size)
    except OSError:
        return None


def _declared_frameworks(root: Path, content_by_path: Mapping[str, bytes | str] | None = None) -> set[str]:
    """Read framework declarations from the analysed source layer.

    The current checkout is only a fallback for paths which were not supplied
    by a materialised snapshot. This prevents a head inventory from inheriting
    framework dependencies from a different index or commit layer.
    """
    frameworks: set[str] = set()
    snapshot = content_by_path or {}
    has_snapshot = content_by_path is not None

    def read_text(relative: str) -> str | None:
        if relative in snapshot:
            value = snapshot[relative]
            return (value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value)
        if has_snapshot:
            return None
        try:
            return (root / relative).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    package_text = read_text("package.json")
    try:
        data = json.loads(package_text) if package_text is not None else {}
    except ValueError:
        data = {}
    if isinstance(data, dict):
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            values = data.get(section)
            if isinstance(values, dict):
                for dependency in values:
                    key = str(dependency).lower()
                    for marker, framework in _FRAMEWORK_DEPENDENCIES.items():
                        if marker.lower() in key:
                            frameworks.add(framework)
    for name in ("pyproject.toml", "requirements.txt", "requirements-dev.txt"):
        text = read_text(name)
        if text is None:
            continue
        if "pytest" in text.lower():
            frameworks.add("pytest")
    if "go.mod" in snapshot or (not has_snapshot and (root / "go.mod").exists()):
        frameworks.add("go-testing")
    if "Cargo.toml" in snapshot or (not has_snapshot and (root / "Cargo.toml").exists()):
        frameworks.add("rust")
    ci_texts = [
        value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
        for path, value in snapshot.items()
        if path.startswith(".github/workflows/") or path == ".gitlab-ci.yml"
    ]
    if not ci_texts and not has_snapshot:
        for path in (root / ".github" / "workflows", root / ".gitlab-ci.yml"):
            if path.is_dir():
                try:
                    ci_texts.extend(item.read_text(encoding="utf-8", errors="replace") for item in path.glob("*.y*ml"))
                except OSError:
                    pass
            elif path.is_file():
                try:
                    ci_texts.append(path.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    pass
    if any("test" in value.lower() for value in ci_texts):
        frameworks.add("ci")
    return frameworks


def _syntax_framework(path: str, text: str, declared: set[str]) -> str:
    lower = text.lower()
    suffix = Path(path).suffix.lower()
    if suffix in {".py", ".pyi"}:
        if re.search(r"\b(?:unittest|pytest)\b|\bTestCase\b|\bpytest\.", text):
            return "pytest" if "pytest" in lower or "pytest" in declared else "python-unittest"
        if "pytest" in declared and (_TEST_PATH_RE.search(path) or _TEST_NAME_RE.search(Path(path).name)):
            return "pytest"
        return "python-unittest" if "test" in path.lower() else "unknown-python"
    if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}:
        for framework, marker in (("vitest", "vitest"), ("jest", "jest"), ("mocha", "mocha"), ("node-test", "node:test")):
            if marker in lower:
                return framework
        for framework in ("vitest", "jest", "mocha", "node-test"):
            if framework in declared and (_TEST_PATH_RE.search(path) or _TEST_NAME_RE.search(Path(path).name)):
                return framework
    if suffix == ".go" and (path.endswith("_test.go") or '"testing"' in text):
        return "go-testing"
    if suffix == ".rs" and re.search(r"#\s*\[(?:tokio::)?test\]|\bmod\s+tests\b", text):
        return "rust"
    if suffix == ".java" and re.search(r"@(?:Test|ParameterizedTest|TestFactory)\b|org\.junit", text):
        return "junit5" if "jupiter" in lower else "junit"
    if suffix == ".cs" and re.search(r"\[(?:Fact|Theory|Test|TestCase|TestMethod)\]", text):
        return "xunit" if re.search(r"\[(?:fact|theory)\]", text, re.I) else "mstest" if "[testmethod]" in lower else "nunit"
    if suffix in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}:
        if re.search(r"\b(?:TEST|TEST_F|TEST_P)\s*\(|\bEXPECT_|\bASSERT_", text):
            return "googletest"
        if "catch2" in lower or re.search(r"\bTEST_CASE\s*\(", text):
            return "catch2"
        if "doctest" in lower:
            return "doctest"
    for declared_name in sorted(declared):
        if declared_name in lower:
            return declared_name
    return "unknown"


def _role(path: str, text: str, framework: str) -> str:
    lower_path = path.lower()
    suffix = Path(path).suffix.lower()
    name = Path(path).name.lower()
    if ".snap" in name or name.endswith((".golden", ".gold", ".approved")) or "/snapshots/" in f"/{lower_path}/":
        return "snapshot or golden file"
    if name in {"pytest.ini", "tox.ini", "jest.config.js", "jest.config.ts", "vitest.config.ts", "vitest.config.js", "conftest.py", "testcontainers.json"} or "test.config" in name:
        return "test configuration"
    if "/fixtures/" in f"/{lower_path}/" or "/testdata/" in f"/{lower_path}/" or name.startswith("fixture"):
        return "fixture"
    helper = any(token in lower_path for token in ("/helpers/", "/support/", "/utils/", "test_helper", "test-support"))
    test_syntax = bool(re.search(
        r"(?:\b(?:test|spec)[A-Za-z0-9_$-]*\s*\(|\b(?:it|describe|TEST|TEST_CASE|Fact|Theory|TestMethod)\s*\(|#\s*\[(?:tokio::)?test|\bdef\s+test_[A-Za-z0-9_]*\s*\()",
        text,
        re.I,
    ))
    if suffix in {".yml", ".yaml"} and ("test" in lower_path or "ci" in lower_path):
        return "CI test command"
    test_path = bool(_TEST_PATH_RE.search(path) or _TEST_NAME_RE.search(name) or name.endswith("_test.go"))
    if not test_path and (Path(path).stem.lower().startswith(("config", "settings")) or any(token in lower_path.split("/") for token in ("config", "configs", "configuration"))):
        return "shared build or manifest file"
    if helper and (test_path or test_syntax):
        return "test helper"
    if test_path or test_syntax:
        return "test"
    if name in {"package.json", "pyproject.toml", "go.mod", "cargo.toml", "pom.xml", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}:
        return "shared build or manifest file"
    return "production source"


def _python_subjects(path: str, text: str, digest: str, source_kind: str) -> list[TestSubject]:
    try:
        tree = ast.parse(text, filename=path)
    except (SyntaxError, ValueError, TypeError):
        return []
    result: list[TestSubject] = []
    def walk(node: ast.AST, prefix: str = "") -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = f"{prefix}.{child.name}" if prefix else child.name
                result.append(TestSubject(path, name, child.lineno, getattr(child, "end_lineno", child.lineno), source_kind, digest))
                walk(child, name)
            else:
                walk(child, prefix)
    walk(tree)
    return result


_DECLARATION_PATTERNS = {
    ".js": re.compile(r"\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)|\bclass\s+([A-Za-z_$][\w$]*)"),
    ".ts": re.compile(r"\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)|\bclass\s+([A-Za-z_$][\w$]*)"),
    ".go": re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)"),
    ".rs": re.compile(r"\b(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)"),
    ".java": re.compile(r"\b(?:public|private|protected|static|final|synchronized|abstract|native|\s)+\s*([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:throws[^{}]+)?\{"),
    ".cs": re.compile(r"\b(?:public|private|protected|internal|static|async|virtual|override|sealed|\s)+\s*[A-Za-z_<>,.?]+\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:throws[^{}]+)?\{"),
    ".c": re.compile(r"\b[A-Za-z_]\w*(?:\s+\*?)\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{"),
    ".cc": re.compile(r"\b[A-Za-z_]\w*(?:\s+\*?)\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{"),
    ".cpp": re.compile(r"\b[A-Za-z_]\w*(?:\s+\*?)\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{"),
}


def _text_subjects(path: str, text: str, digest: str, source_kind: str) -> list[TestSubject]:
    pattern = _DECLARATION_PATTERNS.get(Path(path).suffix.lower())
    if pattern is None:
        return []
    result: list[TestSubject] = []
    lines = text.splitlines()
    for match in pattern.finditer(text):
        name = next((value for value in match.groups() if value), "")
        if not name:
            continue
        line = text.count("\n", 0, match.start()) + 1
        depth = 0
        end_line = line
        for index in range(line - 1, len(lines)):
            depth += lines[index].count("{") - lines[index].count("}")
            end_line = index + 1
            if index >= line - 1 and depth <= 0 and "{" in "\n".join(lines[line - 1:index + 1]):
                break
        result.append(TestSubject(path, name, line, max(line, end_line), source_kind, digest))
    return result


def _subjects(path: str, text: str, digest: str, source_kind: str) -> list[TestSubject]:
    if Path(path).suffix.lower() in {".py", ".pyi"}:
        return _python_subjects(path, text, digest, source_kind)
    return _text_subjects(path, text, digest, source_kind)


def _relations(test: TestArtifact, text: str, subjects: Iterable[TestSubject]) -> list[Mapping[str, Any]]:
    result: list[Mapping[str, Any]] = []
    for subject in subjects:
        name = subject.qualified_name.rsplit(".", 1)[-1]
        if not re.search(rf"(?<![\w$]){re.escape(name)}(?![\w$])", text):
            continue
        imported = bool(re.search(rf"(?:from|import|require|use|using|include|mod)\b[^\n;]*{re.escape(name)}", text, re.I))
        result.append({
            "test_artifact_id": test.artifact_id,
            "subject_id": subject.subject_id,
            "evidence_kind": "direct_import_or_reference" if imported else "direct_symbol_reference",
            "confidence": "high" if imported else "medium",
            "path": test.logical_path,
            "line": text[:max(0, text.find(name))].count("\n") + 1,
        })
    return result


def build_inventory(
    root: Path,
    paths: Iterable[str | Path] | None = None,
    *,
    source_kind: str = "working-tree",
    content_by_path: Mapping[str, bytes | str] | None = None,
    config: Mapping[str, Any] | None = None,
    budget: AnalysisBudget | None = None,
    max_file_bytes: int = MAX_INVENTORY_FILE_BYTES,
    source_kind_by_path: Mapping[str, str] | None = None,
) -> InventoryResult:
    root = root.resolve()
    configured = config or {}
    if paths is None:
        values = [path.relative_to(root).as_posix() for path in iter_files(root)]
    else:
        values = sorted({Path(path).as_posix() for path in paths})
    declared = _declared_frameworks(root, content_by_path)
    artifacts: list[TestArtifact] = []
    subjects: list[TestSubject] = []
    readable_sources: list[tuple[TestArtifact, str]] = []
    skipped: list[str] = []
    for relative in sorted(values):
        if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
            continue
        physical = root / relative
        if is_ignored_path(root, relative) or is_generated_path(root, physical, dict(configured)):
            continue
        try:
            if budget is not None:
                budget.claim_file()
            if content_by_path is None and budget is not None:
                size = physical.stat().st_size
                if size > max_file_bytes:
                    data = b"\0" * (max_file_bytes + 1)
                else:
                    budget.claim_bytes(size)
                    with physical.open("rb") as handle:
                        data = handle.read(size)
                    if len(data) != size or physical.stat().st_size != size:
                        raise OSError("source changed during bounded inventory read")
            else:
                data = _read(physical, content_by_path, max_file_bytes, logical_path=relative)
            if data is not None and budget is not None and content_by_path is not None:
                budget.claim_bytes(min(len(data), max_file_bytes))
                budget.check_deadline()
        except AnalysisBudgetExceeded:
            skipped.append(relative)
            break
        except OSError:
            skipped.append(relative)
            continue
        if data is None or len(data) > max_file_bytes:
            skipped.append(relative)
            continue
        digest = sha256_bytes(data)
        text = data.decode("utf-8", errors="replace")
        artifact_source_kind = (source_kind_by_path or {}).get(relative, source_kind)
        framework = _syntax_framework(relative, text, declared)
        role = _role(relative, text, framework)
        if role == "production source":
            if framework == "unknown":
                language = language_for_path(relative)
                framework = language.language_id if language else "unknown"
            subjects.extend(_subjects(relative, text, digest, artifact_source_kind))
        elif framework == "unknown":
            framework = "repository-test"
        uncertainty = "framework inferred from syntax or path" if framework.startswith("unknown") or framework == "repository-test" else ""
        artifact = TestArtifact(relative, framework, role, artifact_source_kind, digest, uncertainty)
        artifacts.append(artifact)
        readable_sources.append((artifact, text))
    # Build subjects before relations. A production file may sort after its
    # tests, so a single source-order pass would silently lose valid mappings.
    relations: list[Mapping[str, Any]] = []
    for artifact, text in readable_sources:
        if artifact.role in {"test", "test helper", "fixture", "snapshot or golden file"}:
            relations.extend(_relations(artifact, text, subjects))
    status = "partial" if skipped else "complete"
    if not artifacts and not subjects:
        status = "not_applicable"
    return InventoryResult(
        tuple(sorted(artifacts, key=lambda item: (item.logical_path, item.source_kind, item.content_sha256))),
        tuple(sorted(subjects, key=lambda item: (item.logical_path, item.start_line, item.qualified_name))),
        tuple(sorted(relations, key=lambda item: (str(item.get("test_artifact_id")), str(item.get("subject_id"))))),
        status,
        "read_failure" if skipped else None,
        tuple(skipped),
    )


inventory_tests = build_inventory
