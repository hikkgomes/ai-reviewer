"""High-signal static checks for changed or selected test evidence."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ast
import difflib
import io
import re
from pathlib import Path
import tokenize
from typing import Any, Iterable, Mapping, Sequence

from analysis_budget import AnalysisBudget, AnalysisBudgetExceeded
from review_ledger import blank_candidate, validate_candidate
from .inventory import InventoryResult
from .model import TestArtifact, TestChange, TestSubject, digest_payload


RULE_PREFIX = "GOV-TESTS-"
RULES = tuple(f"{RULE_PREFIX}{index:03d}" for index in range(1, 10))
DEFAULT_ENABLED_RULES = frozenset(f"{RULE_PREFIX}{index:03d}" for index in range(1, 7))
MAX_CANDIDATES = 500
MAX_DIFF_LINES = 20_000


@dataclass(frozen=True)
class StaticAnalysisResult:
    status: str
    applicable_files: int
    checked_files: int
    skipped_files: int
    candidates: tuple[dict[str, Any], ...]
    evidence: tuple[Mapping[str, Any], ...]
    reason_code: str | None = None

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


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


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
    errors = validate_candidate(candidate)
    if errors:
        raise ValueError("invalid test-integrity candidate: " + "; ".join(errors))
    return candidate


def _changed(path: str, changed_paths: set[str] | None) -> bool:
    return changed_paths is None or path in changed_paths


def _disabled_matches(text: str, base: str = "") -> Iterable[tuple[int, int, str]]:
    patterns = (
        (r"\b(?:pytest\.mark\.(?:skip|xfail)|pytest\.skip|unittest\.skip|@(?:skip|ignore|disabled)|\b(?:TODO|todo|xfail|Ignore)\b)", "test was disabled or marked as incomplete"),
        (r"continue-on-error\s*:\s*true", "CI test execution was made non-blocking"),
        (r"(?:\|\||&&)\s*true\b", "test failure is explicitly ignored"),
        (r"--passWithNoTests\b|--allow-no-tests\b", "zero collected tests can be accepted"),
        (r"(?:fail-under|coverageThreshold|minimumCoverage)\s*[:=]\s*0(?:\.0+)?\b", "a test or coverage threshold was reduced to zero"),
    )
    changed_lines = _changed_head_lines(base, text) if base else None
    for pattern, message in patterns:
        for match in re.finditer(pattern, text, re.I):
            if changed_lines is not None and _line(text, match.start()) not in changed_lines:
                continue
            yield _line(text, match.start()), match.start(), message


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
    if len(base_lines) > MAX_DIFF_LINES or len(head_lines) > MAX_DIFF_LINES:
        return set(range(1, len(head_lines) + 1))
    changed: set[int] = set()
    matcher = difflib.SequenceMatcher(a=base_lines, b=head_lines, autojunk=False)
    for tag, _before_start, _before_end, after_start, after_end in matcher.get_opcodes():
        if tag != "equal":
            changed.update(range(after_start + 1, max(after_start + 1, after_end + 1)))
    return changed


def _observable_line(line: str) -> bool:
    return bool(re.search(r"\b(?:assert|expect|raises|snapshot|EXPECT_|ASSERT_|check_call|check_output)\b|\.to(?:Equal|StrictEqual|Be|HaveLength|BeTruthy|BeDefined)\s*\(", line))


def _assertion_weakening(base: str, head: str) -> Iterable[tuple[int, str]]:
    """Compare changed syntax regions, rather than pairing source line numbers."""
    base_lines = base.splitlines()
    head_lines = head.splitlines()
    if len(base_lines) > MAX_DIFF_LINES or len(head_lines) > MAX_DIFF_LINES:
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
        elif tag == "delete" and any(_observable_line(item) for item in before_block):
            message = "an observable test check was removed"
        if message is not None and (line, message) not in seen:
            seen.add((line, message))
            yield line, message


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


def _mock_matches(text: str, subjects: Sequence[TestSubject]) -> Iterable[tuple[int, TestSubject, str]]:
    for subject in subjects:
        name = re.escape(subject.qualified_name.rsplit(".", 1)[-1])
        patterns = (
            rf"\b(?:mock\.patch(?:\.object)?|patch\.object)\s*\([^\n;]*\b{name}\b",
            rf"\bpatch\s*\(\s*['\"][^'\"]*\b{name}\b",
            rf"\bmonkeypatch\.setattr\s*\([^\n;]*\b{name}\b",
            rf"\b(?:jest|vi|sinon)\.(?:spyOn|mock|stub)\s*\([^\n;]*\b{name}\b",
            rf"\b(?:mock|stub|spy)\s*\([^\n;]*\b{name}\b",
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
        (r"\bexpect\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\.to(?:Be|Equal)\s*\(\s*\1\s*\)", "the test compares a value with itself"),
        (r"except\s+BaseException\s*:\s*(?:\n\s+[^\n]*)*\n\s*(?:pass|return)\b", "the test catches every exception without failing"),
    )
    for pattern, message in patterns:
        for match in re.finditer(pattern, text, re.I):
            yield _line(text, match.start()), message


def _no_observable_test_bodies(text: str) -> Iterable[tuple[int, str]]:
    """Find Python test functions which contain setup only.

    Compile, type, subprocess, property, and snapshot checks are recognised as
    observable operations even when they do not use a normal assertion call.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, TypeError):
        return
    observable = re.compile(r"\b(?:assert|expect|raises|snapshot|check_call|check_output|subprocess\.run|compile|cargo\s+check|go\s+test|property|hypothesis|given|example|mypy|pyright|assert_type|reveal_type)\b|\.to(?:Equal|StrictEqual|Be|HaveLength|Match|Snapshot)\s*\(", re.I)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not re.match(r"(?:test|spec)[_$-]?", node.name, re.I):
            continue
        segment = ast.get_source_segment(text, node) or ""
        decorators = " ".join(ast.get_source_segment(text, item) or "" for item in node.decorator_list)
        if segment and not observable.search(_mask_non_code(segment, python=True)) and not observable.search(_mask_non_code(decorators, python=True)):
            yield node.lineno, "test body contains setup but no observable verification"


def _test_only_production(text: str, *, python: bool = True) -> Iterable[tuple[int, str]]:
    text = _mask_non_code(text, python=python)
    patterns = (
        r"(?m)^\s*(?:from\s+unittest\.mock\s+import|import\s+(?:pytest|unittest\.mock))\b",
        r"\btypes\.FunctionType\b|\b(?:Mock|MagicMock|AsyncMock)\s*\(",
        r"(?m)^\s*if\b[^\n]*(?:TESTING|PYTEST_CURRENT_TEST)\b",
        r"\b(?:IS_TEST|NODE_ENV)\s*(?:===|==)\s*['\"]test['\"]",
        r"(?m)^\s*(?:import|export)\s+[^\n]*from\s*['\"](?:jest|vitest|mocha)['\"]",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.I):
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
) -> StaticAnalysisResult:
    """Analyse only evidence-bearing test files and selected production seams."""
    selected = sorted(set(paths or [item.logical_path for item in inventory.artifacts]))
    changed = set(changed_paths) if changed_paths is not None else None
    enabled = set(enabled_rules) if enabled_rules is not None else set(DEFAULT_ENABLED_RULES)
    artifacts = inventory.artifacts
    artifact_by_path = {item.logical_path: item for item in artifacts}
    subjects = inventory.subjects
    subjects_by_id = {item.subject_id: item for item in subjects}
    related_subjects: dict[str, tuple[TestSubject, ...]] = {}
    for relation in inventory.relations:
        artifact_id = relation.get("test_artifact_id") if isinstance(relation, Mapping) else None
        subject_id = relation.get("subject_id") if isinstance(relation, Mapping) else None
        subject = subjects_by_id.get(subject_id) if isinstance(subject_id, str) else None
        if isinstance(artifact_id, str) and subject is not None:
            related_subjects.setdefault(artifact_id, tuple())
            related_subjects[artifact_id] = tuple(dict.fromkeys((*related_subjects[artifact_id], subject)))
    candidates: list[dict[str, Any]] = []
    evidence: list[Mapping[str, Any]] = []
    seen: set[str] = set()
    applicable = 0
    checked = 0
    skipped = 0
    skip_reason: str | None = None
    candidate_limit = min(
        MAX_CANDIDATES,
        budget.max_candidates if budget is not None and budget.max_candidates is not None else MAX_CANDIDATES,
    )

    def add_candidate(
        rule_id: str,
        path: str,
        line: int,
        column: int,
        message: str,
        artifact: TestArtifact | None,
        subject: TestSubject | None,
        digest: str,
        details: Mapping[str, Any],
    ) -> bool:
        nonlocal skip_reason
        if candidate_limit <= len(candidates):
            skip_reason = skip_reason or "max_candidates"
            return False
        if budget is not None:
            try:
                budget.claim_candidate()
            except AnalysisBudgetExceeded as error:
                skip_reason = skip_reason or error.reason_code
                return False
        evidence_source_kind = (
            artifact.source_kind if artifact is not None
            else subject.source_kind if subject is not None
            else source_kind
        )
        candidate = _candidate(
            rule_id,
            path,
            line,
            column,
            message,
            artifact=artifact,
            subject=subject,
            source_kind=evidence_source_kind,
            content_sha256=digest,
            details=details,
        )
        if candidate["id"] in seen:
            return True
        seen.add(candidate["id"])
        candidates.append(candidate)
        evidence.extend(candidate["supporting_evidence"])
        return len(candidates) < candidate_limit

    for path in selected:
        if budget is not None:
            try:
                budget.check_deadline()
            except AnalysisBudgetExceeded as error:
                skipped += 1
                skip_reason = error.reason_code
                break
        artifact = artifact_by_path.get(path)
        is_test = artifact is not None and artifact.role in {"test", "test helper", "fixture", "snapshot or golden file", "test configuration", "CI test command"}
        production = artifact is not None and artifact.role == "production source"
        if production and path.startswith("scripts/dissect_checks/test_integrity/"):
            # Rule implementation strings are not evidence about repository
            # runtime seams. Self-review covers this module separately.
            continue
        if not is_test and not production:
            continue
        if not _changed(path, changed) and not production:
            continue
        head_text = head_contents.get(path) if head_contents is not None else None
        deleted_source = False
        if head_contents is not None:
            text = head_text
            if text is None and path in (base_contents or {}):
                text = (base_contents or {}).get(path)
                deleted_source = True
        else:
            try:
                text = (root / path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                skipped += 1
                skip_reason = skip_reason or "read_failure"
                continue
        if text is None:
            skipped += 1
            skip_reason = skip_reason or "source_unavailable"
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
        matches: list[tuple[str, int, int, str, TestSubject | None, dict[str, Any]]] = []
        if is_test:
            if base and _changed(path, changed):
                compare_head = "" if deleted_source else text
                for line, message in _deleted_test_matches(path, base, compare_head):
                    matches.append(("GOV-TESTS-001", line, 0, message, None, {"change_kind": "test_removed"}))
            if not deleted_source:
                for line, offset, message in _disabled_matches(code_text, base_code):
                    matches.append(("GOV-TESTS-001", line, offset, message, None, {"change_kind": "disabled_or_bypassed"}))
            if base and _changed(path, changed):
                for line, message in _assertion_weakening(base_code, code_text):
                    matches.append(("GOV-TESTS-002", line, 0, message, None, {"change_kind": "assertion_weakened"}))
            for line, message, subject_name in _circular_oracles(code_text):
                subject = next((item for item in linked_subjects if item.qualified_name.endswith(subject_name)), None)
                matches.append(("GOV-TESTS-003", line, 0, message, subject, {"change_kind": "circular_oracle", "called_symbol": subject_name}))
            for line, message, subject_name in _derived_oracles(code_text):
                subject = next((item for item in linked_subjects if item.qualified_name.endswith(subject_name)), None)
                matches.append(("GOV-TESTS-003", line, 0, message, subject, {"change_kind": "implementation_derived_oracle", "called_symbol": subject_name}))
            for line, subject, message in _mock_matches(text, linked_subjects):
                matches.append(("GOV-TESTS-004", line, 0, message, subject, {"change_kind": "focal_subject_mocked"}))
            for line, message in _tautologies(code_text):
                matches.append(("GOV-TESTS-005", line, 0, message, None, {"change_kind": "tautology_or_catch_all"}))
            for line, message in _no_observable_test_bodies(text):
                matches.append(("GOV-TESTS-005", line, 0, message, None, {"change_kind": "no_observable_verification"}))
            if artifact is not None and artifact.role in {"fixture", "test"}:
                for line, message in _invalid_fixture_matches(path, text):
                    matches.append(("GOV-TESTS-007", line, 0, message, None, {"change_kind": "invalid_fixture"}))
        if production:
            for line, message in _test_only_production(
                text,
                python=Path(path).suffix.lower() in {".py", ".pyi"},
            ):
                matches.append(("GOV-TESTS-006", line, 0, message, None, {"change_kind": "test_only_production_path"}))
        for rule_id, line, column, message, subject, details in matches:
            if rule_id not in enabled:
                continue
            if not add_candidate(rule_id, path, line, column, message, artifact, subject, digest, details):
                return StaticAnalysisResult(
                    "partial",
                    applicable,
                    checked,
                    skipped,
                    tuple(candidates),
                    tuple(evidence),
                    skip_reason or "max_candidates",
                )
    if not applicable:
        status = "not_applicable"
        reason = "no_test_or_production_artifacts"
    elif skipped:
        status = "partial"
        reason = skip_reason or "read_failure"
    else:
        status = "complete"
        reason = None
    return StaticAnalysisResult(status, applicable, checked, skipped, tuple(candidates), tuple(evidence), reason)


static_analysis = analyse_static
