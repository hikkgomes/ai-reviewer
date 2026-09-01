"""High-signal static checks for changed or selected test evidence."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ast
import difflib
import fnmatch
import io
import json
import re
from pathlib import Path
import tokenize
from typing import Any, Iterable, Mapping, Sequence

from analysis_budget import AnalysisBudget, AnalysisBudgetExceeded
from dissect_checks.redaction import redact_payload
from review_ledger import blank_candidate, validate_candidate
from .inventory import InventoryResult
from .model import TestArtifact, TestChange, TestSubject, digest_payload


RULE_PREFIX = "GOV-TESTS-"
RULES = tuple(f"{RULE_PREFIX}{index:03d}" for index in range(1, 11))
DEFAULT_ENABLED_RULES = frozenset(f"{RULE_PREFIX}{index:03d}" for index in range(1, 7)) | {"GOV-TESTS-010"}
NEW_TEST_ARTIFACT_ROLES = frozenset({"test", "test helper", "fixture", "snapshot or golden file"})
MAX_CANDIDATES = 500
MAX_DIFF_LINES = 5_000
MAX_DIFF_COMPARISONS = 1_000_000
NEW_TEST_APPROVAL_DOMAIN = b"dissect-test-creation-approval-v1\0"


@dataclass(frozen=True)
class StaticAnalysisResult:
    status: str
    applicable_files: int
    checked_files: int
    skipped_files: int
    candidates: tuple[dict[str, Any], ...]
    evidence: tuple[Mapping[str, Any], ...]
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"complete", "partial", "not_applicable", "failed"}:
            raise ValueError("invalid static test-integrity status")
        if min(self.applicable_files, self.checked_files, self.skipped_files) < 0:
            raise ValueError("static test-integrity counts must not be negative")
        if self.checked_files > self.applicable_files or self.checked_files + self.skipped_files > self.applicable_files:
            raise ValueError("static test-integrity counts exceed applicable files")
        if self.status == "complete" and self.checked_files != self.applicable_files:
            raise ValueError("complete static test-integrity results require every file to be checked")
        if self.status == "not_applicable" and any((self.applicable_files, self.checked_files, self.skipped_files)):
            raise ValueError("not_applicable static results cannot contain files")

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "applicable_files": self.applicable_files,
            "checked_files": self.checked_files,
            "skipped_files": self.skipped_files,
            "candidates": list(self.candidates),
            "evidence": [dict(item) for item in self.evidence],
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True)
class NewTestApproval:
    """A path- and revision-bound approval for newly added test artefacts."""

    path_patterns: tuple[str, ...]
    roles: tuple[str, ...]
    max_count: int
    production_subjects: tuple[str, ...]
    base_revision: str
    head_revision: str
    digest: str
    source: str

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "path_patterns": list(self.path_patterns),
            "roles": list(self.roles),
            "max_count": self.max_count,
            "production_subjects": list(self.production_subjects),
            "base_revision": self.base_revision,
            "head_revision": self.head_revision,
        }

    @property
    def expected_digest(self) -> str:
        encoded = json.dumps(self.payload(), ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return hashlib.sha256(NEW_TEST_APPROVAL_DOMAIN + encoded).hexdigest()


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def _source_text(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def _artifact_for(path: str, artifacts: Sequence[TestArtifact]) -> TestArtifact | None:
    return next((item for item in artifacts if item.logical_path == path), None)


def _subjects_for(path: str, subjects: Sequence[TestSubject]) -> tuple[TestSubject, ...]:
    return tuple(item for item in subjects if item.logical_path == path)


def _candidate(
    rule_id: str,
    path: str,
    line: int,
    column: int,
    message: str,
    *,
    artifact: TestArtifact | None,
    subject: TestSubject | None = None,
    source_kind: str = "working-tree",
    content_sha256: str = "",
    evidence_kind: str = "static_test_analysis",
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    discriminator = dict(details or {})
    identity = {
        "rule_id": rule_id,
        "path": path,
        "line": line,
        "column": column,
        "source_kind": source_kind,
        "content_sha256": content_sha256,
        "message": message,
        "discriminator": discriminator,
    }
    candidate_id = digest_payload(identity, prefix="candidate-")
    candidate = blank_candidate(
        candidate_id,
        source=rule_id,
        claim=message,
        contract="Confirm the test contract, independent oracle, reachability, and fault sensitivity before reporting.",
    )
    candidate["trigger_path"] = [f"{path}:{line}"]
    record: dict[str, Any] = {
        "kind": evidence_kind,
        "rule_id": rule_id,
        "file": path,
        "line": line,
        "column": column,
        "source_layer": source_kind,
        "content_sha256": content_sha256,
        "rule_discriminator": digest_payload({"message": message, "details": discriminator}),
        "analysis_level": "structural",
        "does_not_prove": ["test failure", "independent oracle", "focal reachability", "unique behavioural value"],
        "oracle_source": {
            "kind": "not_recorded",
            "reference": "Static analysis cannot establish an independent oracle; use the matrix or proof-test workflow.",
        },
    }
    if artifact is not None:
        record["test_artifact_id"] = artifact.artifact_id
        record["framework_id"] = artifact.framework_id
        record["role"] = artifact.role
    if subject is not None:
        record["focal_subject_id"] = subject.subject_id
        record["focal_subject"] = subject.qualified_name
    record.update(discriminator)
    candidate["supporting_evidence"] = [record]
    candidate = redact_payload(candidate)
    errors = validate_candidate(candidate)
    if errors:
        raise ValueError("invalid test-integrity candidate: " + "; ".join(errors))
    return candidate


def _changed(path: str, changed_paths: set[str] | None) -> bool:
    return changed_paths is None or path in changed_paths


def _disabled_matches(text: str, base: str = "") -> Iterable[tuple[int, int, str]]:
    # Shell, YAML, Terraform, and Python use ``#`` comments. Ignore full
    # comment lines so a note which mentions a disable marker is not treated as
    # a runtime bypass.
    text = re.sub(r"(?m)^[ \t]*#(?!\s*\[)[^\n]*", "", text)
    base = re.sub(r"(?m)^[ \t]*#(?!\s*\[)[^\n]*", "", base)
    patterns = (
        (r"\b(?:pytest\.mark\.(?:skip|skipif|xfail)|pytest\.skip|unittest\.skip(?:If|Unless)?|(?:test|it|describe)\.(?:skip|todo)|t\.Skip(?:f|Now)?|GTEST_SKIP\s*\(\)|#\s*\[\s*ignore\s*\]|@(?:skip|ignore|disabled|todo)|\[(?:Ignore|IgnoreIf)|Skip\s*=)", "test was disabled or marked as incomplete"),
        (r"continue-on-error\s*:\s*true", "CI test execution was made non-blocking"),
        (r"(?:\|\||&&)\s*true\b", "test failure is explicitly ignored"),
        (r"--passWithNoTests\b|--allow-no-tests\b", "zero collected tests can be accepted"),
        (r"(?:--ignore(?:[-=]|\s+)|testPathIgnorePatterns\s*[:=])[^\n]*?(?:test|spec|__tests__)", "test discovery was changed to exclude a test path"),
        (r"(?:fail-under|coverageThreshold|minimumCoverage)\s*[:=]\s*0(?:\.0+)?\b", "a test or coverage threshold was reduced to zero"),
    )
    changed_lines = _changed_head_lines(base, text) if base else None
    for pattern, message in patterns:
        for match in re.finditer(pattern, text, re.I):
            if changed_lines is not None and _line(text, match.start()) not in changed_lines:
                continue
            line_start = text.rfind("\n", 0, match.start()) + 1
            yield _line(text, match.start()), match.start() - line_start, message
    if base:
        threshold_pattern = re.compile(
            r"(?im)\b(?:fail-under|coverageThreshold|minimumCoverage)\b\s*[:=]\s*([0-9]+(?:\.[0-9]+)?)"
        )
        old_values = [float(match.group(1)) for match in threshold_pattern.finditer(base)]
        for match in threshold_pattern.finditer(text):
            if old_values and float(match.group(1)) < min(old_values):
                line_start = text.rfind("\n", 0, match.start()) + 1
                yield _line(text, match.start()), match.start() - line_start, "a test or coverage threshold was reduced"


def _test_declarations(path: str, text: str) -> set[str]:
    """Return framework-neutral test declaration names for deletion checks."""
    suffix = Path(path).suffix.lower()
    if suffix in {".py", ".pyi"}:
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, TypeError):
            return set()
        return {
            node.name for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and re.match(r"(?:test|spec)[_$-]?", node.name, re.I)
        }
    patterns = {
        ".go": r"\bfunc\s+(Test[A-Za-z0-9_]*)\s*\(",
        ".rs": r"\bfn\s+((?:test|spec)[A-Za-z0-9_]*)\s*\(",
        ".java": r"\b(?:void|boolean|public\s+void)\s+((?:test|should|spec)[A-Za-z0-9_]*)\s*\(",
        ".cs": r"\b(?:void|Task|async\s+Task)\s+((?:test|should|spec)[A-Za-z0-9_]*)\s*\(",
    }
    pattern = patterns.get(suffix, r"\b(?:test|it|spec)\s*\(\s*['\"]([^'\"]+)")
    return {match.group(1) for match in re.finditer(pattern, text, re.I)}


def _deleted_test_matches(path: str, base: str, head: str) -> Iterable[tuple[int, str]]:
    if not base:
        return
    removed = sorted(_test_declarations(path, base) - _test_declarations(path, head))
    if not removed:
        return
    for name in removed:
        declaration = re.search(rf"(?m)^\s*(?:async\s+def|def|func|fn|(?:public\s+)?(?:void|Task|boolean))\s+{re.escape(name)}\b", base)
        line = _line(base, declaration.start()) if declaration is not None else 1
        yield line, f"test declaration {name!r} was removed from the head source"


def _python_parameter_cases(text: str) -> dict[str, tuple[int, int]]:
    """Return literal pytest parameter counts keyed by test function."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, TypeError):
        return {}
    result: dict[str, tuple[int, int]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            if decorator.func.attr != "parametrize" or len(decorator.args) < 2:
                continue
            values = decorator.args[1]
            if isinstance(values, (ast.List, ast.Tuple, ast.Set)):
                result[node.name] = (len(values.elts), decorator.lineno)
    return result


def _reduced_parameter_cases(path: str, base: str, head: str) -> Iterable[tuple[int, str]]:
    if Path(path).suffix.lower() not in {".py", ".pyi"} or not base or not head:
        return
    before = _python_parameter_cases(base)
    after = _python_parameter_cases(head)
    for name in sorted(set(before) & set(after)):
        old_count, _old_line = before[name]
        new_count, new_line = after[name]
        if new_count < old_count:
            yield new_line, f"parameter cases for test {name!r} were reduced"


_TEST_COMMAND_RE = re.compile(
    r"\b(?:pytest|unittest|jest|vitest|mocha|go\s+test|cargo\s+test|dotnet\s+test|"
    r"npm\s+(?:run\s+)?test|pnpm\s+(?:run\s+)?test|yarn\s+test)\b",
    re.I,
)
_TEST_PATH_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])(?:tests?|specs?|testdata|__tests__)/[A-Za-z0-9_./-]+|"
    r"(?:[A-Za-z0-9_.-]+_test\.(?:py|go|rs|js|jsx|ts|tsx|java|cs|c|cc|cpp))",
    re.I,
)


def _test_command_lines(text: str) -> list[tuple[int, str]]:
    return [
        (line_number, line)
        for line_number, line in enumerate(text.splitlines(), 1)
        if _TEST_COMMAND_RE.search(line) and not line.lstrip().startswith(("#", "//", "/*", "*"))
    ]


def _excluded_test_paths(base: str, head: str) -> Iterable[tuple[int, str]]:
    """Find changed test commands which no longer select an old test path."""
    old_commands = _test_command_lines(base)
    new_commands = _test_command_lines(head)
    if not old_commands or not new_commands:
        return
    old_paths = {token.lower() for _line_number, line in old_commands for token in _TEST_PATH_TOKEN_RE.findall(line)}
    new_text = "\n".join(line for _line_number, line in new_commands).lower()
    missing = sorted(path for path in old_paths if path not in new_text)
    if not missing:
        return
    for line_number, _line_text in new_commands:
        yield line_number, f"test command no longer selects prior test path(s): {', '.join(missing[:3])}"


def _invalid_fixture_matches(path: str, text: str) -> Iterable[tuple[int, str]]:
    """Identify explicit parser-only evidence without guessing from names alone."""
    lower_path = path.lower().replace("\\", "/")
    marker = re.search(
        r"(?im)(?:parser[- ]only|undefined placeholder|invalid signature|behavioural proof|behavioral proof)",
        text,
    )
    syntax_error = False
    if Path(path).suffix.lower() in {".py", ".pyi"}:
        try:
            ast.parse(text)
        except (SyntaxError, ValueError, TypeError):
            syntax_error = True
    if marker is None and not (syntax_error and ("pattern" in lower_path or "fixture" in lower_path or "malformed" in lower_path)):
        return
    line = _line(text, marker.start()) if marker is not None else 1
    yield line, "fixture is parser-only or compiler-invalid behavioural evidence"


def _changed_head_lines(base: str, head: str) -> set[int]:
    """Return head lines in changed regions for bounded diff-only checks."""
    base_lines = base.splitlines()
    head_lines = head.splitlines()
    if base_lines == head_lines:
        return set()
    # Static checks are candidates, so a very large file is allowed to be
    # incomplete rather than making an unbounded similarity computation.
    if (
        len(base_lines) > MAX_DIFF_LINES
        or len(head_lines) > MAX_DIFF_LINES
        or len(base_lines) * len(head_lines) > MAX_DIFF_COMPARISONS
    ):
        return set(range(1, len(head_lines) + 1))
    changed: set[int] = set()
    matcher = difflib.SequenceMatcher(a=base_lines, b=head_lines, autojunk=False)
    for tag, _before_start, _before_end, after_start, after_end in matcher.get_opcodes():
        if tag != "equal":
            changed.update(range(after_start + 1, max(after_start + 1, after_end + 1)))
    return changed


def _observable_line(line: str) -> bool:
    return bool(re.search(
        r"\b(?:assert|expect|raises|snapshot|EXPECT_|ASSERT_|check_call|check_output|"
        r"assert[A-Z][A-Za-z0-9_]*|fail|subTest)\b|"
        r"\.to(?:Equal|StrictEqual|Be|HaveLength|BeTruthy|BeDefined)\s*\(",
        line,
    ))


def _assertion_weakening(base: str, head: str) -> Iterable[tuple[int, str]]:
    """Compare changed syntax regions, rather than pairing source line numbers."""
    base_lines = base.splitlines()
    head_lines = head.splitlines()
    if (
        len(base_lines) > MAX_DIFF_LINES
        or len(head_lines) > MAX_DIFF_LINES
        or len(base_lines) * len(head_lines) > MAX_DIFF_COMPARISONS
    ):
        # A full similarity map is quadratic in the worst case. Large files
        # remain eligible for the other bounded checks, but this comparison is
        # deliberately left unverified rather than spending the whole budget.
        return
    matcher = difflib.SequenceMatcher(
        a=[line.strip() for line in base_lines],
        b=[line.strip() for line in head_lines],
        autojunk=False,
    )
    seen: set[tuple[int, str]] = set()
    for tag, before_start, before_end, after_start, after_end in matcher.get_opcodes():
        if tag == "equal":
            continue
        before_block = base_lines[before_start:before_end]
        after_block = head_lines[after_start:after_end]
        before_text = "\n".join(before_block)
        after_text = "\n".join(after_block)
        line = max(1, after_start + 1 if after_block else min(len(head_lines), after_start + 1))
        message: str | None = None
        if re.search(r"\bassert\b.*(?:==|!=|<=|>=|<|>)", before_text) and re.search(r"\bassert\b(?!.*(?:==|!=|<=|>=|<|>))", after_text):
            message = "an exact assertion was weakened to a truthiness assertion"
        elif re.search(r"\.to(?:Equal|StrictEqual|Be|HaveLength)\s*\(", before_text) and re.search(r"\.toBeTruthy\s*\(|\.toBeDefined\s*\(", after_text):
            message = "an exact JavaScript assertion was weakened to existence or truthiness"
        elif re.search(r"(?:pytest|assertRaises)\s*\.?(?:raises)?\s*\(\s*(?:ValueError|TypeError|AssertionError|[A-Za-z_]\w*)", before_text) and re.search(r"(?:pytest\.raises|assertRaises)\s*\(\s*Exception\s*", after_text):
            message = "an expected exception was broadened to Exception"
        elif re.search(r"assert\s+[^#]+\bin\s+\{", before_text) and re.search(r"assert\s+[^#]+\bin\s+\(", after_text):
            message = "an accepted value set was broadened"
        else:
            tolerance = re.compile(r"(?:<=|abs\s*=|tolerance\s*=|atol\s*=)\s*([0-9]+(?:\.[0-9]+)?)", re.I)
            old_tolerances = [float(value) for value in tolerance.findall(before_text)]
            new_tolerances = [float(value) for value in tolerance.findall(after_text)]
            if old_tolerances and new_tolerances and max(new_tolerances) > max(old_tolerances):
                message = "numeric assertion tolerance was broadened"
            else:
                old_sets = re.findall(r"\bin\s*[\[{]([^\]}]*)[\]}]", before_text)
                new_sets = re.findall(r"\bin\s*[\[{]([^\]}]*)[\]}]", after_text)
                if old_sets and new_sets:
                    old_count = max(len(item.split(",")) for item in old_sets)
                    new_count = max(len(item.split(",")) for item in new_sets)
                    if new_count > old_count:
                        message = "an accepted value set was broadened"
        if message is None and tag == "delete" and any(_observable_line(item) for item in before_block):
            message = "an observable test check was removed"
        if message is not None and (line, message) not in seen:
            seen.add((line, message))
            yield line, message


def _assertion_moved_behind_branch(base: str, head: str) -> Iterable[tuple[int, str]]:
    """Find an existing assertion which became conditional in the head."""
    base_lines = base.splitlines()
    head_lines = head.splitlines()
    if not base_lines or not head_lines:
        return
    base_assertions = {
        line.strip()
        for line in base_lines
        if _observable_line(line) and re.search(r"\b(?:assert|expect)\b", line, re.I)
    }
    if not base_assertions:
        return
    for index, line in enumerate(head_lines):
        stripped = line.strip()
        if stripped not in base_assertions:
            continue
        if index == 0:
            continue
        indentation = len(line) - len(line.lstrip())
        previous = next(
            (head_lines[position].strip() for position in range(index - 1, -1, -1) if head_lines[position].strip()),
            "",
        )
        if indentation > 0 and re.match(r"(?:if|unless|when)\b", previous, re.I):
            yield index + 1, "an existing assertion was moved behind a conditional branch"


def _circular_oracles(text: str) -> Iterable[tuple[int, str, str]]:
    call = r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\([^;\n]*\)"
    patterns = (
        (rf"\bassert\s+(?P<left>{call})\s*==\s*(?P<right>{call})", "expected and actual values call production code symmetrically"),
        (rf"expect\s*\(\s*(?P<left>{call})\s*\)\s*\.to(?:Equal|StrictEqual)\s*\(\s*(?P<right>{call})\s*\)", "expected value is generated by the same call as the actual value"),
    )
    for pattern, message in patterns:
        for match in re.finditer(pattern, text):
            left = match.group("left").split("(", 1)[0]
            right = match.group("right").split("(", 1)[0]
            if left == right:
                yield _line(text, match.start()), message, left


def _derived_oracles(text: str) -> Iterable[tuple[int, str, str]]:
    """Find expected values derived directly from a focal implementation."""
    assignment = re.compile(
        r"(?im)^\s*(?:expected|expected_value|golden|want)\s*=\s*(?P<subject>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\([^\n]*\)"
    )
    for match in assignment.finditer(text):
        subject = match.group("subject")
        remainder = text[match.end():]
        if re.search(rf"\b(?:assert|expect)\b[^\n]*\b(?:expected|expected_value|golden|want)\b", remainder, re.I):
            yield _line(text, match.start()), "the expected value is generated by the focal implementation", subject


def _python_circular_oracles(text: str) -> Iterable[tuple[int, str, str]]:
    """Handle multiline Python call comparisons without textual pairing."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, TypeError):
        return
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1 or not isinstance(node.ops[0], ast.Eq) or len(node.comparators) != 1:
            continue
        left, right = node.left, node.comparators[0]
        if not isinstance(left, ast.Call) or not isinstance(right, ast.Call):
            continue
        if ast.dump(left, include_attributes=False) != ast.dump(right, include_attributes=False):
            continue
        function = left.func.id if isinstance(left.func, ast.Name) else left.func.attr if isinstance(left.func, ast.Attribute) else "call"
        yield node.lineno, "expected and actual values call production code symmetrically", function


def _python_derived_oracles(text: str) -> Iterable[tuple[int, str, str]]:
    """Find expected values assigned from a call and later asserted."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, TypeError):
        return
    expected_names = {"expected", "expected_value", "golden", "want"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name) or not isinstance(node.value, ast.Call):
            continue
        if node.targets[0].id.lower() not in expected_names:
            continue
        function = node.value.func.id if isinstance(node.value.func, ast.Name) else node.value.func.attr if isinstance(node.value.func, ast.Attribute) else "call"
        if any(
            isinstance(candidate, ast.Assert)
            and any(
                isinstance(name, ast.Name) and name.id == node.targets[0].id
                for name in ast.walk(candidate)
            )
            for candidate in ast.walk(tree)
        ):
            yield node.lineno, "the expected value is generated by the focal implementation", function


def _implementation_oracle_matches(text: str) -> Iterable[tuple[int, str, str]]:
    """Find assertions coupled to source text, implementation shape, or test-file existence."""
    source_read = re.compile(
        r"\b(?:inspect\.getsource|(?:[A-Za-z_$][\w$]*\.)?toString\s*\(|"
        r"(?:Path|pathlib\.Path)\s*\([^\)\n]*\)\.read_text\s*\(|"
        r"(?:fs\.)?readFileSync\s*\([^\)\n]*\))",
        re.I,
    )
    assertion = re.compile(r"\b(?:assert|expect|assertThat)\b|\.to(?:Contain|Match|Include|Equal)\s*\(", re.I)
    source_names: set[str] = set()
    lines = text.splitlines()
    for match in source_read.finditer(text):
        line_start = text.rfind("\n", 0, match.start()) + 1
        line_end = text.find("\n", match.end())
        line_end = len(text) if line_end < 0 else line_end
        line_text = text[line_start:line_end]
        prefix = text[line_start:match.start()]
        assignment = re.search(r"\b([A-Za-z_]\w*)\s*=\s*$", prefix)
        if assignment:
            source_names.add(assignment.group(1))
        if assertion.search(line_text):
            yield _line(text, match.start()), "the test asserts source text or generated implementation shape", "source_string_assertion"
    if source_names:
        for line_number, line_text in enumerate(lines, 1):
            if assertion.search(line_text) and any(re.search(rf"\b{re.escape(name)}\b", line_text) for name in source_names):
                yield line_number, "the test asserts source text or generated implementation shape", "source_string_assertion"
    existence = re.compile(
        r"\.(?:exists|is_file|is_dir)\s*\(|(?:fs\.)?existsSync\s*\(|\btest\s+-[fed]\b",
        re.I,
    )
    for line_number, line_text in enumerate(lines, 1):
        if line_text.lstrip().startswith(("#", "//", "/*", "*")):
            continue
        if assertion.search(line_text) and existence.search(line_text) and re.search(r"\b(?:tests?|specs?)\b", line_text, re.I):
            yield line_number, "the test asserts that a test or spec file exists", "test_existence_assertion"


def _snapshot_derived_oracle(text: str) -> Iterable[tuple[int, str, str]]:
    """Flag a generated golden update unless it has an external oracle."""
    header = "\n".join(text.splitlines()[:8])
    if not re.search(r"(?:generated|regenerated|snapshot\s+update|golden\s+update)", header, re.I):
        return
    if re.search(r"(?:independent|reviewed)\s+(?:fixture|oracle|reference)", header, re.I):
        return
    yield 1, "snapshot or golden data appears to be generated by the changed implementation", "snapshot"


def _mock_matches(text: str, subjects: Sequence[TestSubject]) -> Iterable[tuple[int, TestSubject, str]]:
    for subject in subjects:
        name = re.escape(subject.qualified_name.rsplit(".", 1)[-1])
        patterns = (
            rf"\b(?:mock\.patch(?:\.object)?|patch\.object)\s*\([^\n;]*\b{name}\b",
            rf"\bpatch\s*\(\s*['\"][^'\"]*\b{name}\b",
            rf"\bmonkeypatch\.setattr\s*\([^\n;]*\b{name}\b",
            rf"\b(?:jest|vi|sinon)\.(?:spyOn|mock|stub)\s*\([^\n;]*\b{name}\b",
        )
        for pattern in patterns:
            match = re.search(pattern, text, re.I)
            if match:
                yield _line(text, match.start()), subject, "the focal subject is replaced by a test double"
                break


def _tautologies(text: str) -> Iterable[tuple[int, str]]:
    patterns = (
        (r"\bassert\s+(?:True|False)\b", "the test asserts a constant boolean"),
        (r"\bassert\s+([A-Za-z_$][\w$]*)\s*==\s*\1\b", "the test compares a value with itself"),
        (r"\bassert\s+([-+]?\d+(?:\.\d+)?)\s*={2,3}\s*\1\b", "the test asserts an identical constant expression"),
        (r"\bexpect\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\.to(?:Be|Equal)\s*\(\s*\1\s*\)", "the test compares a value with itself"),
        (r"\bexpect\s*\(\s*((?:true|false|null|undefined))\s*\)\s*\.to(?:Be|Equal)\s*\(\s*\1\s*\)", "the test asserts an identical constant expression"),
        (r"\bexpect\s*\(\s*([-+]?\d+(?:\.\d+)?)\s*\)\s*\.to(?:Be|Equal)\s*\(\s*\1\s*\)", "the test asserts an identical constant expression"),
        (r"except\s+(?:BaseException|Exception)\s*:\s*(?:(?:\n\s+[^\n]*)*\n\s*|\s+)(?:pass|return)\b", "the test catches every exception without failing"),
    )
    for pattern, message in patterns:
        for match in re.finditer(pattern, text, re.I):
            yield _line(text, match.start()), message


def _python_tautologies(text: str) -> Iterable[tuple[int, str]]:
    """Find exact Python self-comparisons without treating call symmetry as tautology."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, TypeError):
        return
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assert) or not isinstance(node.test, ast.Compare):
            continue
        if len(node.test.ops) != 1 or len(node.test.comparators) != 1:
            continue
        left = node.test.left
        right = node.test.comparators[0]
        if not isinstance(left, (ast.Name, ast.Attribute, ast.Constant)) or not isinstance(right, (ast.Name, ast.Attribute, ast.Constant)):
            continue
        if ast.dump(left, include_attributes=False) == ast.dump(right, include_attributes=False):
            yield node.lineno, "the test compares a value with itself"
        elif isinstance(left, ast.Constant) and isinstance(right, ast.Constant) and left.value == right.value:
            yield node.lineno, "the test compares identical constants"


def _python_early_return_matches(text: str) -> Iterable[tuple[int, str]]:
    """Find the high-confidence form of a test that exits before checking."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, TypeError):
        return
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not re.match(r"(?:test|spec)[_$-]?", node.name, re.I) or not node.body:
            continue
        first = node.body[0]
        if isinstance(first, ast.Return):
            yield first.lineno, "the test returns before performing an observable verification"


def _python_catch_all_matches(text: str) -> Iterable[tuple[int, str]]:
    """Find test handlers which swallow every exception without failing."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, TypeError):
        return
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not re.match(r"(?:test|spec)[_$-]?", function.name, re.I):
            continue
        for node in ast.walk(function):
            if not isinstance(node, ast.Try):
                continue
            for handler in node.handlers:
                exception_name = (
                    handler.type.id
                    if isinstance(handler.type, ast.Name)
                    else None
                )
                if handler.type is not None and exception_name not in {"Exception", "BaseException"}:
                    continue
                if not handler.body or any(
                    isinstance(statement, (ast.Raise, ast.Assert))
                    for statement in handler.body
                ):
                    continue
                if all(isinstance(statement, (ast.Pass, ast.Return, ast.Expr)) for statement in handler.body):
                    yield handler.lineno, "the test catches every exception without failing"


def _has_quarantine_evidence(text: str, line: int) -> bool:
    """Recognise a documented quarantine only with an issue and guard."""
    lines = text.splitlines()
    start = max(0, line - 3)
    end = min(len(lines), line + 2)
    nearby = "\n".join(lines[start:end]).lower()
    return (
        "quarantin" in nearby
        and bool(re.search(r"\b(?:issue|ticket|bug|#\d+)\b", nearby))
        and bool(re.search(r"\b(?:replacement|guard|regression|tracked)\b", nearby))
    )


def _has_explicit_contract_change(evidence: str | None) -> bool:
    """Accept a caller-supplied intent only when it states the change."""
    if not evidence:
        return False
    return bool(re.search(
        r"\b(?:intentional(?:ly)?|approved|documented)\b.{0,80}\b(?:contract|behavio[u]?r|test|api)\b.{0,80}\b(?:change|changed|remove|removed|no longer supported|deprecated)\b|"
        r"\b(?:contract|behavio[u]?r|api)\s+(?:change|changed)\b|"
        r"\bno longer (?:support(?:s|ed)?|available|required)\b|\bbreaking\s+(?:api|contract|behavio[u]?r)\s+change\b",
        evidence,
        re.I | re.S,
    ))


_NEW_TEST_TARGET = r"(?:unit|integration|end[- ]to[- ]end|e2e|spec(?:ification)?|test(?:[- ]only)?|fixture|helper)(?:\s+test)?"
_NEW_TEST_APPROVAL_PATTERNS = (
    re.compile(
        rf"\b(?:create|write|introduce|author)\s+(?:(?:a|an|one)\s+)?(?:new\s+|additional\s+)?{_NEW_TEST_TARGET}s?(?:\s+(?:file|files|helper|helpers|fixture|fixtures))?\b",
        re.I,
    ),
    re.compile(
        rf"\badd\s+(?:(?:a|an|one)\s+)?(?:new\s+|additional\s+)?{_NEW_TEST_TARGET}s?(?:\s+(?:file|files|helper|helpers|fixture|fixtures))?\b",
        re.I,
    ),
    re.compile(
        rf"\b(?:approve|approved|authori[sz]e|authorised|authorise)\b.{{0,80}}\b(?:creation|addition|create|creating|add|adding|write|writing|introduce|introducing)\b.{{0,80}}{_NEW_TEST_TARGET}s?\b",
        re.I | re.S,
    ),
    re.compile(
        rf"\b(?:request|requested|requests)\b.{{0,40}}\b(?:creation|addition|create|creating|add|adding|write|writing|introduce|introducing)\b.{{0,80}}{_NEW_TEST_TARGET}s?\b",
        re.I | re.S,
    ),
)


def _has_explicit_new_test_approval(intent_text: str | None) -> bool:
    """Recognise only explicit creation or approval, not a generic test task."""
    if not intent_text:
        return False
    for pattern in _NEW_TEST_APPROVAL_PATTERNS:
        for match in pattern.finditer(intent_text):
            prefix = intent_text[max(0, match.start() - 80):match.start()]
            if re.search(r"\b(?:do\s+not|don't|never|avoid|without|no)\b", prefix, re.I):
                continue
            return True
    return False


def _normalise_approval_paths(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or not values or not all(isinstance(value, str) and value.strip() for value in values):
        raise ValueError("new-test approval paths must be a non-empty-string array")
    patterns: list[str] = []
    for value in values:
        pattern = value.replace("\\", "/").strip()
        path = Path(pattern)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("new-test approval paths must contain repository-relative patterns")
        patterns.append(pattern)
    return tuple(dict.fromkeys(patterns))


def _approval_payload(
    path_patterns: Iterable[str],
    roles: Iterable[str],
    max_count: int,
    production_subjects: Iterable[str],
    base_revision: str,
    head_revision: str,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "path_patterns": sorted(set(path_patterns)),
        "roles": sorted(set(roles)),
        "max_count": max_count,
        "production_subjects": sorted(set(production_subjects)),
        "base_revision": base_revision,
        "head_revision": head_revision,
    }


def new_test_approval_digest(scope: Mapping[str, Any]) -> str:
    """Create the full digest used by external test-creation approvals."""
    payload = _approval_payload(
        scope.get("path_patterns", scope.get("paths", ())),
        scope.get("roles", ()),
        scope.get("max_count", 0),
        scope.get("production_subjects", ()),
        str(scope.get("base_revision", "")),
        str(scope.get("head_revision", "")),
    )
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(NEW_TEST_APPROVAL_DOMAIN + encoded).hexdigest()


def _approval_from_mapping(
    value: Mapping[str, Any],
    *,
    source: str,
    base_revision: str,
    head_revision: str,
) -> NewTestApproval | None:
    try:
        paths = _normalise_approval_paths(value.get("path_patterns", value.get("paths", value.get("allowed_paths"))))
        roles_value = value.get("roles", value.get("artifact_roles"))
        if not isinstance(roles_value, (list, tuple)) or not roles_value or not all(isinstance(item, str) and item in NEW_TEST_ARTIFACT_ROLES for item in roles_value):
            return None
        roles = tuple(dict.fromkeys(roles_value))
        max_count = value.get("max_count")
        if isinstance(max_count, bool) or not isinstance(max_count, int) or max_count < 1:
            return None
        subjects_value = value.get("production_subjects", value.get("subjects", ()))
        if not isinstance(subjects_value, (list, tuple)) or not all(isinstance(item, str) and item for item in subjects_value):
            return None
        expected_base = value.get("base_revision", "")
        expected_head = value.get("head_revision", "")
        if not isinstance(expected_base, str) or not isinstance(expected_head, str):
            return None
        if expected_base != base_revision or expected_head != head_revision:
            return None
        payload = _approval_payload(paths, roles, max_count, subjects_value, expected_base, expected_head)
        digest = value.get("digest", value.get("approval_digest"))
        if not isinstance(digest, str) or digest != new_test_approval_digest(payload):
            return None
    except (TypeError, ValueError):
        return None
    return NewTestApproval(
        tuple(payload["path_patterns"]), tuple(payload["roles"]), max_count,
        tuple(payload["production_subjects"]), expected_base, expected_head,
        digest, source,
    )


def _configured_new_test_approval(
    config: Mapping[str, Any] | None,
    *,
    base_revision: str,
    head_revision: str,
) -> NewTestApproval | None:
    options = config.get("review_options") if isinstance(config, Mapping) else None
    if not isinstance(options, Mapping):
        return None
    structured = options.get("test_integrity_new_test_approval")
    if isinstance(structured, Mapping):
        return _approval_from_mapping(
            structured,
            source="review_options.test_integrity_new_test_approval",
            base_revision=base_revision,
            head_revision=head_revision,
        )
    # The former path-list option is intentionally not an approval source. It
    # has no artifact-role, count, subject, or revision binding.
    return None


def _intent_paths(intent_text: str) -> tuple[str, ...]:
    values = re.findall(r"(?<![A-Za-z0-9_])(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+(?:\.[A-Za-z0-9_-]+)?", intent_text)
    paths = []
    for value in values:
        normalised = value.replace("\\", "/")
        if Path(normalised).is_absolute() or ".." in Path(normalised).parts:
            continue
        if "/" in normalised and (Path(normalised).suffix or "*" in normalised):
            paths.append(normalised)
    return tuple(dict.fromkeys(paths))


def _intent_role(intent_text: str) -> str:
    lower = intent_text.lower()
    if "fixture" in lower:
        return "fixture"
    if "helper" in lower:
        return "test helper"
    if any(token in lower for token in ("snapshot", "golden")):
        return "snapshot or golden file"
    return "test"


def _intent_new_test_approval(
    intent_text: str | None,
    new_artifacts: Sequence[TestArtifact],
    related_subjects: Mapping[str, Sequence[TestSubject]],
    *,
    base_revision: str,
    head_revision: str,
) -> NewTestApproval | None:
    if not _has_explicit_new_test_approval(intent_text):
        return None
    text = intent_text or ""
    paths = _intent_paths(text)
    role = _intent_role(text)
    singular = bool(re.search(r"\b(?:a|an|one|single)\b", text, re.I))
    if not paths:
        if len(new_artifacts) != 1:
            return None
        paths = (new_artifacts[0].logical_path,)
    max_count = 1 if singular or len(paths) == 1 else len(paths)
    matched = [item for item in new_artifacts if any(fnmatch.fnmatchcase(item.logical_path, pattern) for pattern in paths)]
    subjects = tuple(sorted({
        subject.subject_id
        for artifact in matched
        for subject in related_subjects.get(artifact.artifact_id, ())
    }))
    payload = _approval_payload(paths, (role,), max_count, subjects, base_revision, head_revision)
    return NewTestApproval(
        tuple(payload["path_patterns"]), tuple(payload["roles"]), max_count,
        tuple(payload["production_subjects"]), base_revision, head_revision,
        new_test_approval_digest(payload), "trusted_intent",
    )


def _new_test_approval(
    path: str,
    artifact: TestArtifact,
    approval: NewTestApproval | None,
    new_artifacts: Sequence[TestArtifact],
    related_subjects: Mapping[str, Sequence[TestSubject]],
) -> tuple[bool, str]:
    if approval is None:
        return False, "none"
    matched_artifacts = [
        item for item in new_artifacts
        if item.role in approval.roles
        and any(fnmatch.fnmatchcase(item.logical_path, pattern) for pattern in approval.path_patterns)
    ]
    if len(matched_artifacts) > approval.max_count:
        return False, approval.source
    if artifact not in matched_artifacts:
        return False, approval.source
    actual_subjects = {subject.subject_id for subject in related_subjects.get(artifact.artifact_id, ())}
    if approval.production_subjects != ("*",):
        approved_subjects = set(approval.production_subjects)
        linked = related_subjects.get(artifact.artifact_id, ())
        if linked and any(
            not any(
                fnmatch.fnmatchcase(value, pattern)
                for pattern in approved_subjects
                for value in (subject.subject_id, subject.logical_path, subject.qualified_name)
            )
            for subject in linked
        ):
            return False, approval.source
        if not actual_subjects and approved_subjects:
            return False, approval.source
    return True, approval.source


def _new_test_file_matches(
    path: str,
    artifact: TestArtifact,
    *,
    is_new: bool,
    approved: bool,
) -> Iterable[tuple[int, int, str]]:
    """Find newly added test-only artefacts which lack explicit approval."""
    if is_new and artifact.role in NEW_TEST_ARTIFACT_ROLES and not approved:
        yield 1, 0, "new test file or test-only helper/fixture was added without explicit creation approval"


def _brace_end(text: str, opening: int) -> int | None:
    """Find a bounded test body without treating braces in literals as syntax."""
    pairs = {"{": "}", "(": ")", "[": "]"}
    stack: list[str] = []
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    index = opening
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
                return None
            if not stack:
                return index
        index += 1
    return None


def _non_python_no_observable_test_bodies(path: str, text: str) -> Iterable[tuple[int, str]]:
    """Find assertion-free test bodies for the supported non-Python styles."""
    suffix = Path(path).suffix.lower()
    if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}:
        declarations = re.finditer(
            r"\b(?:test|it|specify)\s*\([^,\n]+,\s*(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{|"
            r"\b(?:test|it|specify)\s*\([^,\n]+,\s*function\s*\([^)]*\)\s*\{",
            text,
            re.I,
        )
        observable = re.compile(
            r"\b(?:assert|expect|snapshot|throws|rejects|compile|check|fail|verify)\b|"
            r"\.to(?:Equal|StrictEqual|Be|HaveLength|Match|Snapshot)\s*\(",
            re.I,
        )
    elif suffix == ".go":
        declarations = re.finditer(r"\bfunc\s+(Test[A-Za-z0-9_]*)\s*\([^)]*\)\s*\{", text)
        observable = re.compile(r"\b(?:Assert|Require|Error|Fail|Fatal|Run|Log|Cleanup|Helper|check|compile|typecheck)\s*\w*\s*\(|\b(?:assert|require)\.", re.I)
    elif suffix == ".rs":
        declarations = re.finditer(r"#\s*\[(?:tokio::)?test[^\]]*\][\s\S]*?\bfn\s+[A-Za-z_][\w]*\s*\([^)]*\)\s*\{", text, re.I)
        observable = re.compile(r"\b(?:assert!?|assert_eq!|assert_ne!|panic!|todo!|unimplemented!)\s*\(", re.I)
    elif suffix == ".java":
        declarations = re.finditer(r"@(?:Test|ParameterizedTest|TestFactory)\b[\s\S]*?\b[A-Za-z_]\w*\s*\([^)]*\)\s*(?:throws[^\{]+)?\{", text, re.I)
        observable = re.compile(r"\b(?:assert|fail|verify|expect|Assertions\.)\w*\s*\(|\bthrow\s+", re.I)
    elif suffix == ".cs":
        declarations = re.finditer(r"\[(?:Fact|Theory|Test|TestCase|TestMethod)\][\s\S]*?\b[A-Za-z_]\w*\s*\([^)]*\)\s*\{", text, re.I)
        observable = re.compile(r"\b(?:Assert|Throws|Does|Should|Verify|Fail)\.?\w*\s*\(|\bthrow\s+", re.I)
    elif suffix in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}:
        declarations = re.finditer(r"\b(?:TEST|TEST_F|TEST_P|TEST_CASE)\s*\([^)]*\)\s*\{", text, re.I)
        observable = re.compile(r"\b(?:ASSERT|EXPECT|REQUIRE|CHECK|FAIL|SUCCEED)_?\w*\s*\(", re.I)
    else:
        return
    for match in declarations:
        opening = text.find("{", match.start(), match.end())
        if opening < 0:
            continue
        closing = _brace_end(text, opening)
        if closing is None:
            continue
        declaration_name = match.group(0)
        if suffix == ".go" and re.search(r"\bTest(?:Compile|Build|Typecheck)\b", declaration_name, re.I):
            continue
        body = _mask_non_code(text[opening + 1:closing], python=False)
        if not observable.search(body):
            yield _line(text, match.start()), "test body contains setup but no observable verification"


def _no_observable_test_bodies(text: str) -> Iterable[tuple[int, str]]:
    """Find Python test functions which contain setup only.

    Compile, type, subprocess, property, and snapshot checks are recognised as
    observable operations even when they do not use a normal assertion call.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, TypeError):
        return
    observable = re.compile(
        r"\b(?:assert|expect|raises|snapshot|check_call|check_output|subprocess\.run|compile|"
        r"cargo\s+check|go\s+test|property|hypothesis|given|example|mypy|pyright|"
        r"assert_type|reveal_type|assert[A-Z][A-Za-z0-9_]*|subTest|fail)\b|"
        r"\.to(?:Equal|StrictEqual|Be|HaveLength|Match|Snapshot)\s*\(",
        re.I,
    )
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not re.match(r"(?:test|spec)[_$-]?", node.name, re.I):
            continue
        if re.search(r"(?:compile|typecheck|type_check|build)", node.name, re.I):
            continue
        segment = ast.get_source_segment(text, node) or ""
        decorators = " ".join(ast.get_source_segment(text, item) or "" for item in node.decorator_list)
        if segment and not observable.search(_mask_non_code(segment, python=True)) and not observable.search(_mask_non_code(decorators, python=True)):
            yield node.lineno, "test body contains setup but no observable verification"


def _test_only_production(text: str, *, python: bool = True) -> Iterable[tuple[int, str]]:
    original = text
    text = _mask_non_code(text, python=python)
    patterns = (
        r"(?m)^\s*(?:from\s+(?:unittest\.mock|pytest|unittest)\s+import|import\s+(?:pytest|unittest(?:\.mock)?))\b",
        r"\b(?:types\.)?FunctionType\b|\b(?:Mock|MagicMock|AsyncMock)\s*\(",
        r"(?m)^\s*if\b[^\n]*(?:TESTING|PYTEST_CURRENT_TEST)\b",
        r"\b(?:IS_TEST|NODE_ENV)\s*(?:===|==)\s*['\"]test['\"]",
        r"(?m)^\s*(?:import|export)\s+[^\n]*from\s*['\"](?:jest|vitest|mocha)['\"]",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.I):
            yield _line(text, match.start()), "production behaviour is conditional on a test-only seam or runtime marker"
    # The comparison value is a string literal, so the normal code mask hides
    # the very evidence this rule needs. Use the original source only for this
    # high-signal form and require the marker itself to remain unmasked. This
    # avoids matching a comment or a string which merely describes the branch.
    environment_pattern = re.compile(
        r"\b(?:process\.env\.)?(?:NODE_ENV|IS_TEST|TEST_MODE)\s*(?:===|!==|==|!=)\s*(['\"])test\1",
        re.I,
    )
    for match in environment_pattern.finditer(original):
        if match.start() < len(text) and text[match.start()] != " ":
            yield _line(text, match.start()), "production behaviour is conditional on a test-only seam or runtime marker"


def _mask_non_code(text: str, *, python: bool = False) -> str:
    """Mask strings and comments while preserving source positions."""
    lines = text.splitlines(keepends=True)
    offsets: list[int] = []
    total = 0
    for line in lines:
        offsets.append(total)
        total += len(line)
    chars = list(text)

    def mask(start: tuple[int, int], end: tuple[int, int]) -> None:
        start_line, start_col = start
        end_line, end_col = end
        if not offsets or start_line < 1 or end_line < 1 or start_line > len(offsets):
            return
        first = offsets[start_line - 1] + start_col
        last = offsets[min(len(offsets) - 1, end_line - 1)] + end_col
        for index in range(max(0, first), min(len(chars), last)):
            if chars[index] not in "\r\n":
                chars[index] = " "

    # Python's tokenizer is precise and handles quoted strings spanning lines.
    if python:
        try:
            tokens = tokenize.generate_tokens(io.StringIO(text).readline)
            for token in tokens:
                if token.type in {tokenize.STRING, tokenize.COMMENT}:
                    mask(token.start, token.end)
            return "".join(chars)
        except (tokenize.TokenError, IndentationError, SyntaxError, UnicodeError):
            pass

    # Keep a bounded fallback for non-Python source and malformed Python.
    chars = list(text)
    index = 0
    quote = ""
    line_comment = False
    block_comment = False
    escaped = False
    while index < len(chars):
        current = chars[index]
        following = chars[index + 1] if index + 1 < len(chars) else ""
        if line_comment:
            if current in "\r\n":
                line_comment = False
            elif current != "\n":
                chars[index] = " "
            index += 1
            continue
        if block_comment:
            if current == "*" and following == "/":
                chars[index] = chars[index + 1] = " "
                block_comment = False
                index += 2
            else:
                if current not in "\r\n":
                    chars[index] = " "
                index += 1
            continue
        if quote:
            if current in "\r\n":
                index += 1
                continue
            chars[index] = " "
            if escaped:
                escaped = False
            elif current == "\\":
                escaped = True
            elif current == quote:
                quote = ""
            index += 1
            continue
        if python and current == "#":
            chars[index] = " "
            line_comment = True
            index += 1
            continue
        if current == "/" and following == "/":
            chars[index] = chars[index + 1] = " "
            line_comment = True
            index += 2
            continue
        if current == "/" and following == "*":
            chars[index] = chars[index + 1] = " "
            block_comment = True
            index += 2
            continue
        if current in {'"', "'", "`"}:
            quote = current
            chars[index] = " "
        index += 1
    return "".join(chars)


def _test_matches(
    path: str,
    artifact: TestArtifact,
    text: str,
    base: str,
    code_text: str,
    base_code: str,
    *,
    changed: set[str] | None,
    deleted_source: bool,
    is_new: bool,
    documented_contract_change: bool,
    linked_subjects: Sequence[TestSubject],
    creation_approval: NewTestApproval | None,
    new_artifacts: Sequence[TestArtifact],
    related_subjects: Mapping[str, Sequence[TestSubject]],
) -> list[tuple[str, int, int, str, TestSubject | None, dict[str, Any]]]:
    matches: list[tuple[str, int, int, str, TestSubject | None, dict[str, Any]]] = []
    approved, approval_source = _new_test_approval(
        path, artifact, creation_approval, new_artifacts, related_subjects,
    )
    for line, offset, message in _new_test_file_matches(
        path, artifact, is_new=is_new, approved=approved,
    ):
        matches.append((
            "GOV-TESTS-010", line, offset, message, None,
            {
                "change_kind": "new_test_file_without_approval",
                "approval_required": True,
                "approval_source": approval_source,
                "approval_digest": creation_approval.digest if creation_approval else "",
                "approval_scope": creation_approval.payload() if creation_approval else {},
            },
        ))
    if base and _changed(path, changed) and not documented_contract_change:
        compare_head = "" if deleted_source else text
        matches.extend(
            ("GOV-TESTS-001", line, 0, message, None, {"change_kind": "test_removed"})
            for line, message in _deleted_test_matches(path, base, compare_head)
        )
    if not deleted_source:
        matches.extend(
            ("GOV-TESTS-001", line, offset, message, None, {"change_kind": "disabled_or_bypassed"})
            for line, offset, message in _disabled_matches(code_text, base_code)
            if not _has_quarantine_evidence(text, line)
        )
    if base and _changed(path, changed) and not documented_contract_change:
        matches.extend(
            ("GOV-TESTS-002", line, 0, message, None, {"change_kind": "assertion_weakened"})
            for line, message in _assertion_weakening(base_code, code_text)
        )
        matches.extend(
            ("GOV-TESTS-002", line, 0, message, None, {"change_kind": "assertion_moved_behind_branch"})
            for line, message in _assertion_moved_behind_branch(base_code, code_text)
        )
        matches.extend(
            ("GOV-TESTS-001", line, 0, message, None, {"change_kind": "parameter_cases_reduced"})
            for line, message in _reduced_parameter_cases(path, base, text)
        )
        matches.extend(
            ("GOV-TESTS-001", line, 0, message, None, {"change_kind": "test_path_excluded"})
            for line, message in _excluded_test_paths(base, text)
        )
    for line, message, subject_name in _circular_oracles(code_text):
        subject = next((item for item in linked_subjects if item.qualified_name.endswith(subject_name)), None)
        matches.append(("GOV-TESTS-003", line, 0, message, subject, {"change_kind": "circular_oracle", "called_symbol": subject_name}))
    for line, message, subject_name in _derived_oracles(code_text):
        subject = next((item for item in linked_subjects if item.qualified_name.endswith(subject_name)), None)
        matches.append(("GOV-TESTS-003", line, 0, message, subject, {"change_kind": "implementation_derived_oracle", "called_symbol": subject_name}))
    python_source = Path(path).suffix.lower() in {".py", ".pyi"}
    if python_source:
        for line, message, subject_name in _python_circular_oracles(text):
            subject = next((item for item in linked_subjects if item.qualified_name.endswith(subject_name)), None)
            matches.append(("GOV-TESTS-003", line, 0, message, subject, {"change_kind": "circular_oracle", "called_symbol": subject_name}))
        for line, message, subject_name in _python_derived_oracles(text):
            subject = next((item for item in linked_subjects if item.qualified_name.endswith(subject_name)), None)
            matches.append(("GOV-TESTS-003", line, 0, message, subject, {"change_kind": "implementation_derived_oracle", "called_symbol": subject_name}))
    for line, message, subject_name in _implementation_oracle_matches(text):
        matches.append(("GOV-TESTS-003", line, 0, message, None, {"change_kind": subject_name}))
    if artifact.role == "snapshot or golden file":
        matches.extend(
            ("GOV-TESTS-003", line, 0, message, None, {"change_kind": "generated_snapshot", "called_symbol": subject_name})
            for line, message, subject_name in _snapshot_derived_oracle(text)
        )
    matches.extend(
        ("GOV-TESTS-004", line, 0, message, subject, {"change_kind": "focal_subject_mocked"})
        for line, subject, message in _mock_matches(text, linked_subjects)
    )
    matches.extend(
        ("GOV-TESTS-005", line, 0, message, None, {"change_kind": "tautology_or_catch_all"})
        for line, message in _tautologies(code_text)
    )
    if python_source:
        matches.extend(
            ("GOV-TESTS-005", line, 0, message, None, {"change_kind": "tautology_or_catch_all"})
            for line, message in _python_tautologies(text)
        )
        matches.extend(
            ("GOV-TESTS-005", line, 0, message, None, {"change_kind": "early_return"})
            for line, message in _python_early_return_matches(text)
        )
        matches.extend(
            ("GOV-TESTS-005", line, 0, message, None, {"change_kind": "tautology_or_catch_all"})
            for line, message in _python_catch_all_matches(text)
        )
    else:
        matches.extend(
            ("GOV-TESTS-005", line, 0, message, None, {"change_kind": "no_observable_verification"})
            for line, message in _non_python_no_observable_test_bodies(path, text)
        )
    matches.extend(
        ("GOV-TESTS-005", line, 0, message, None, {"change_kind": "no_observable_verification"})
        for line, message in _no_observable_test_bodies(text)
    )
    if artifact.role in {"fixture", "test"}:
        matches.extend(
            ("GOV-TESTS-007", line, 0, message, None, {"change_kind": "invalid_fixture"})
            for line, message in _invalid_fixture_matches(path, text)
        )
    return matches


def _production_matches(
    text: str,
    path: str,
) -> list[tuple[str, int, int, str, TestSubject | None, dict[str, Any]]]:
    return [
        ("GOV-TESTS-006", line, 0, message, None, {"change_kind": "test_only_production_path"})
        for line, message in _test_only_production(
            text,
            python=Path(path).suffix.lower() in {".py", ".pyi"},
        )
    ]


def _normalise_static_paths(root: Path, values: Iterable[str | Path]) -> set[str]:
    result: set[str] = set()
    for value in values:
        candidate = Path(value)
        if candidate.is_absolute():
            try:
                result.add(candidate.resolve().relative_to(root.resolve()).as_posix())
            except (OSError, ValueError):
                continue
        else:
            result.add(candidate.as_posix())
    return result


def _related_static_subjects(
    inventory: InventoryResult,
) -> dict[str, tuple[TestSubject, ...]]:
    subjects_by_id = {item.subject_id: item for item in inventory.subjects}
    result: dict[str, tuple[TestSubject, ...]] = {}
    for relation in inventory.relations:
        artifact_id = relation.get("test_artifact_id") if isinstance(relation, Mapping) else None
        subject_id = relation.get("subject_id") if isinstance(relation, Mapping) else None
        subject = subjects_by_id.get(subject_id) if isinstance(subject_id, str) else None
        if isinstance(artifact_id, str) and subject is not None:
            result.setdefault(artifact_id, tuple())
            result[artifact_id] = tuple(dict.fromkeys((*result[artifact_id], subject)))
    return result


def _creation_approval(
    config: Mapping[str, Any] | None,
    explicit_scope: Mapping[str, Any] | None,
    approval_digest: str | None,
    trusted_intent_text: str | None,
    new_artifacts: Sequence[TestArtifact],
    related_subjects: Mapping[str, Sequence[TestSubject]],
    *,
    base_revision: str,
    head_revision: str,
) -> NewTestApproval | None:
    configured = _configured_new_test_approval(
        config,
        base_revision=base_revision,
        head_revision=head_revision,
    )
    scope = explicit_scope
    if scope is None and approval_digest is not None:
        options = config.get("review_options") if isinstance(config, Mapping) else None
        value = options.get("test_integrity_new_test_approval") if isinstance(options, Mapping) else None
        scope = value if isinstance(value, Mapping) else None
    if scope is not None:
        value = dict(scope)
        if approval_digest is not None:
            value["digest"] = approval_digest
        configured = _approval_from_mapping(
            value,
            source="explicit_approval_digest",
            base_revision=base_revision,
            head_revision=head_revision,
        )
    elif approval_digest is not None:
        configured = None
    intent = _intent_new_test_approval(
        trusted_intent_text,
        new_artifacts,
        related_subjects,
        base_revision=base_revision,
        head_revision=head_revision,
    ) if trusted_intent_text else None
    return configured or intent


def _append_static_candidate(
    candidates: list[dict[str, Any]],
    evidence: list[Mapping[str, Any]],
    seen: set[str],
    *,
    rule_id: str,
    path: str,
    line: int,
    column: int,
    message: str,
    artifact: TestArtifact | None,
    subject: TestSubject | None,
    digest: str,
    source_kind: str,
    details: Mapping[str, Any],
    candidate_limit: int,
    budget: AnalysisBudget | None,
) -> tuple[bool, str | None]:
    if candidate_limit <= len(candidates):
        return False, "max_candidates"
    evidence_source_kind = artifact.source_kind if artifact is not None else subject.source_kind if subject is not None else source_kind
    candidate = _candidate(
        rule_id, path, line, column, message,
        artifact=artifact, subject=subject, source_kind=evidence_source_kind,
        content_sha256=digest, details=details,
    )
    if candidate["id"] in seen:
        return True, None
    if budget is not None:
        try:
            budget.claim_candidate()
        except AnalysisBudgetExceeded as error:
            return False, error.reason_code
    seen.add(candidate["id"])
    candidates.append(candidate)
    evidence.extend(candidate["supporting_evidence"])
    return len(candidates) < candidate_limit, None


def _read_static_source(
    root: Path,
    path: str,
    base_contents: Mapping[str, str] | None,
    head_contents: Mapping[str, str] | None,
) -> tuple[str | None, bool, str | None]:
    if head_contents is not None:
        text = head_contents.get(path)
        if text is not None:
            return text, False, None
        if path in (base_contents or {}):
            return (base_contents or {}).get(path), True, None
        return None, False, "source_unavailable"
    try:
        return (root / path).read_text(encoding="utf-8", errors="replace"), False, None
    except OSError:
        return None, False, "read_failure"


def _scan_static_files(
    root: Path,
    selected: Sequence[str],
    artifact_by_path: Mapping[str, TestArtifact],
    subjects: Sequence[TestSubject],
    related_subjects: Mapping[str, Sequence[TestSubject]],
    *,
    new_artifacts: Sequence[TestArtifact],
    base_contents: Mapping[str, str] | None,
    head_contents: Mapping[str, str] | None,
    added: set[str],
    changed: set[str] | None,
    source_kind: str,
    budget: AnalysisBudget | None,
    enabled: set[str],
    creation_approval: NewTestApproval | None,
    documented_contract_change: bool,
    candidate_limit: int,
) -> StaticAnalysisResult:
    candidates: list[dict[str, Any]] = []
    evidence: list[Mapping[str, Any]] = []
    seen: set[str] = set()
    applicable = 0
    checked = 0
    skipped = 0
    skip_reason: str | None = None
    for index, path in enumerate(selected):
        if budget is not None:
            try:
                budget.check_deadline()
            except AnalysisBudgetExceeded as error:
                skipped += len(selected) - index
                skip_reason = error.reason_code
                break
        artifact = artifact_by_path.get(path)
        is_test = artifact is not None and artifact.role in {"test", "test helper", "fixture", "snapshot or golden file", "test configuration", "CI test command"}
        production = artifact is not None and artifact.role == "production source"
        if production and changed is not None and path not in changed:
            continue
        if not is_test and not production:
            continue
        if not _changed(path, changed) and not production:
            continue
        text, deleted_source, read_reason = _read_static_source(root, path, base_contents, head_contents)
        if text is None:
            skipped += 1
            skip_reason = skip_reason or read_reason or "source_unavailable"
            continue
        applicable += 1
        checked += 1
        digest = _hash_text(text)
        if artifact is not None and artifact.content_sha256 == digest:
            digest = artifact.content_sha256
        base = (base_contents or {}).get(path, "")
        python_source = Path(path).suffix.lower() in {".py", ".pyi"}
        code_text = _mask_non_code(text, python=python_source)
        base_code = _mask_non_code(base, python=python_source) if base else ""
        linked_subjects = related_subjects.get(artifact.artifact_id, ()) if artifact is not None else ()
        if not linked_subjects:
            linked_subjects = _subjects_for(path, subjects)
        is_new = path in added or (
            base_contents is not None
            and head_contents is not None
            and path in head_contents
            and path not in base_contents
        )
        matches = (
            _test_matches(
                path, artifact, text, base, code_text, base_code,
                changed=changed,
                deleted_source=deleted_source,
                is_new=is_new,
                documented_contract_change=documented_contract_change,
                linked_subjects=linked_subjects,
                creation_approval=creation_approval,
                new_artifacts=new_artifacts,
                related_subjects=related_subjects,
            )
            if is_test
            else _production_matches(text, path)
            if production
            else []
        )
        for rule_id, line, column, message, subject, details in matches:
            if rule_id not in enabled:
                continue
            keep_going, candidate_reason = _append_static_candidate(
                candidates, evidence, seen,
                rule_id=rule_id, path=path, line=line, column=column,
                message=message, artifact=artifact, subject=subject,
                digest=digest, source_kind=source_kind, details=details,
                candidate_limit=candidate_limit, budget=budget,
            )
            if candidate_reason is not None:
                skip_reason = skip_reason or candidate_reason
            if not keep_going:
                return StaticAnalysisResult("partial", applicable, checked, skipped, tuple(candidates), tuple(evidence), skip_reason or "max_candidates")
    if not applicable:
        return StaticAnalysisResult("not_applicable", 0, 0, 0, tuple(candidates), tuple(evidence), "no_test_or_production_artifacts")
    if skipped:
        return StaticAnalysisResult("partial", applicable, checked, skipped, tuple(candidates), tuple(evidence), skip_reason or "read_failure")
    return StaticAnalysisResult("complete", applicable, checked, skipped, tuple(candidates), tuple(evidence), None)


def _analyse_static(
    root: Path,
    inventory: InventoryResult,
    *,
    paths: Iterable[str] | None = None,
    base_contents: Mapping[str, str] | None = None,
    head_contents: Mapping[str, str] | None = None,
    changed_paths: Iterable[str] | None = None,
    source_kind: str = "working-tree",
    budget: AnalysisBudget | None = None,
    enabled_rules: Iterable[str] | None = None,
    intent_text: str | None = None,
    trusted_intent_text: str | None = None,
    config: Mapping[str, Any] | None = None,
    new_paths: Iterable[str] | None = None,
    new_test_approval: Mapping[str, Any] | None = None,
    approval_digest: str | None = None,
    base_revision: str = "",
    head_revision: str = "",
) -> StaticAnalysisResult:
    """Analyse only evidence-bearing test files and selected production seams."""
    if base_contents is not None:
        base_contents = {path: _source_text(value) for path, value in base_contents.items()}
    if head_contents is not None:
        head_contents = {path: _source_text(value) for path, value in head_contents.items()}
    requested_values = paths or [item.logical_path for item in inventory.artifacts]
    requested_set = _normalise_static_paths(root, requested_values)
    requested = sorted(requested_set)
    changed = _normalise_static_paths(root, changed_paths) if changed_paths is not None else None
    added = _normalise_static_paths(root, new_paths or ())
    enabled = set(enabled_rules) if enabled_rules is not None else set(DEFAULT_ENABLED_RULES)
    artifacts = inventory.artifacts
    artifact_by_path = {item.logical_path: item for item in artifacts}
    selected = [
        path for path in requested
        if artifact_by_path.get(path) is not None
        and artifact_by_path[path].role in {
            "test", "test helper", "fixture", "snapshot or golden file",
            "test configuration", "CI test command", "production source",
        }
    ]
    subjects = inventory.subjects
    related_subjects = _related_static_subjects(inventory)
    new_artifacts = [
        item for item in artifacts
        if item.role in NEW_TEST_ARTIFACT_ROLES
        and (
            item.logical_path in added
            or (
                base_contents is not None
                and head_contents is not None
                and item.logical_path in head_contents
                and item.logical_path not in base_contents
            )
        )
    ]
    trusted_approval_text = intent_text if trusted_intent_text is None else trusted_intent_text
    creation_approval = _creation_approval(
        config,
        new_test_approval,
        approval_digest,
        trusted_approval_text,
        new_artifacts,
        related_subjects,
        base_revision=base_revision,
        head_revision=head_revision,
    )
    candidate_limit = min(
        MAX_CANDIDATES,
        budget.max_candidates if budget is not None and budget.max_candidates is not None else MAX_CANDIDATES,
    )
    return _scan_static_files(
        root,
        selected,
        artifact_by_path,
        subjects,
        related_subjects,
        new_artifacts=new_artifacts,
        base_contents=base_contents,
        head_contents=head_contents,
        added=added,
        changed=changed,
        source_kind=source_kind,
        budget=budget,
        enabled=enabled,
        creation_approval=creation_approval,
        documented_contract_change=_has_explicit_contract_change(trusted_approval_text),
        candidate_limit=candidate_limit,
    )


def analyse_static(
    root: Path,
    inventory: InventoryResult,
    *,
    paths: Iterable[str] | None = None,
    base_contents: Mapping[str, str] | None = None,
    head_contents: Mapping[str, str] | None = None,
    changed_paths: Iterable[str] | None = None,
    source_kind: str = "working-tree",
    budget: AnalysisBudget | None = None,
    enabled_rules: Iterable[str] | None = None,
    intent_text: str | None = None,
    trusted_intent_text: str | None = None,
    config: Mapping[str, Any] | None = None,
    new_paths: Iterable[str] | None = None,
    new_test_approval: Mapping[str, Any] | None = None,
    approval_digest: str | None = None,
    base_revision: str = "",
    head_revision: str = "",
) -> StaticAnalysisResult:
    """Prepare the inventory and delegate file scanning to its own pass."""
    return _analyse_static(
        root,
        inventory,
        paths=paths,
        base_contents=base_contents,
        head_contents=head_contents,
        changed_paths=changed_paths,
        source_kind=source_kind,
        budget=budget,
        enabled_rules=enabled_rules,
        intent_text=intent_text,
        trusted_intent_text=trusted_intent_text,
        config=config,
        new_paths=new_paths,
        new_test_approval=new_test_approval,
        approval_digest=approval_digest,
        base_revision=base_revision,
        head_revision=head_revision,
    )


static_analysis = analyse_static
