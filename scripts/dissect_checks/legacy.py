from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import fnmatch
import re

from .model import Finding
from language_registry import language_for_path


@dataclass(frozen=True)
class LegacyRule:
    check_id: str
    name: str
    category: str
    pattern: re.Pattern
    explanation: str
    remediation: str
    positive: str
    negative: str
    skip_patterns: tuple[str, ...] = ()
    suffixes: tuple[str, ...] = ()


def _rule(
    check_id: str,
    name: str,
    pattern: str,
    positive: str,
    negative: str,
    *,
    category: str = "legacy-heuristic",
    flags: int = re.I,
    skips: tuple[str, ...] = (),
    suffixes: tuple[str, ...] = (),
) -> LegacyRule:
    return LegacyRule(
        check_id,
        name,
        category,
        re.compile(pattern, flags),
        f"Preserved legacy detector: {name.replace('_', ' ')}.",
        "Inspect the surrounding behavior and replace the risky construct or document why it is safe.",
        positive,
        negative,
        skips,
        suffixes,
    )


# This is the complete regex baseline from the pre-modular scanner. Stable IDs
# and the expected-ID regression test make removals explicit.
LEGACY_RULES = (
    _rule("LEG-PLACEHOLDER-001", "placeholder", r"\b(TODO|FIXME|changeme|dummy[_ -]?key|your[_ -]?api[_ -]?key|lorem ipsum)\b", "TODO fix", "implemented"),
    _rule("COR-EXC-001", "swallowed_exception", r"except\s*:\s*pass|catch\s*\([^)]*\)\s*\{\s*\}", "try: work()\nexcept: pass", "except ValueError: recover()", flags=re.I | re.S),
    _rule("SEC-INJECT-001", "sql_concatenation", r"(SELECT|INSERT|UPDATE|DELETE)[^\n]*(\+|%s|f['\"])[^\n]*", 'query = "SELECT x " + value', 'query = "SELECT x WHERE id = ?"'),
    _rule("SEC-TLS-001", "tls_disabled", r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED", "get(url, verify=False)", "get(url, verify=True)"),
    _rule("SEC-DATA-LEGACY-001", "secret_logging", r"console\.log\(.*(token|secret|password|api[_-]?key)|logger\..*\b(token|secret|password|api[_-]?key)\b", "logger.info(token)", "logger.info(request_id)"),
    _rule("SEC-INJECT-002", "shell_injection_risk", r"(subprocess\.(run|Popen)\(|exec\(|spawn\(|os\.system\().*(\+|f['\"]|\$\{)", 'os.system("tool " + value)', 'subprocess.run(["tool", value])', flags=re.I | re.S),
    _rule("LEG-CONFIG-001", "hardcoded_ip", r"['\"](?:\d{1,3}\.){3}\d{1,3}['\"]", 'host = "10.0.0.1"', "host = config.host", skips=("*.json", "*.yaml", "*.yml", "*.toml", "Dockerfile", "*.cfg")),
    _rule("SEC-SECRETS-LEGACY-001", "hardcoded_credential", r"\b(password|secret|api[_-]?key|access[_-]?key|token)\b\s*[:=]\s*['\"][^'\"]+['\"]", 'api_key = "abcdefghijklmnopqrstuv"', "api_key = os.environ['API_KEY']", category="secrets", skips=("*.example", "*.sample", "*.md")),
    _rule("LEG-DEBUG-001", "debug_print", r"console\.log\s*\(|\bprint\s*\(|fmt\.Print(?:f|ln)?\s*\(|System\.out\.print(?:ln)?\s*\(|\bdebugger\b", "console.log(value)", "logger.info(value)", skips=("*test*", "*spec*", "**/scripts/**", "*.md")),
    _rule("LEG-DEAD-001", "dead_code_marker", r"(//|#|/\*+)\s*(HACK|XXX|TEMP|REMOVEME)\b", "# HACK", "# rationale"),
    _rule("SEC-CODE-001", "unsafe_eval", r"\beval\s*\(|new Function\s*\(|(?<!\.)\bexec\s*\(", "eval(payload)", "json.loads(payload)"),
    _rule("COR-JS-001", "unhandled_promise", r"\.then\s*\((?:(?!\.catch|\.finally).)*\)(?!\s*\.(catch|finally))", "work().then(done)", "await work()", flags=re.I | re.S, skips=("*test*",)),
    _rule("COR-CONFIG-001", "env_no_default", r"process\.env(?:\.[A-Z0-9_]+|\[['\"][A-Z0-9_]+['\"]\])(?!\s*(\|\||\?\?))|os\.environ\[['\"][A-Z0-9_]+['\"]\]", "process.env.API_URL", "config.apiUrl", skips=("*.d.ts", "*.md")),
    _rule("SEC-DESER-001", "unsafe_deserialization", r"pickle\.load\s*\(|yaml\.load\s*\((?![^)]*Loader\s*=)|Marshal\.load\s*\(|\bunserialize\s*\(", "yaml.load(payload)", "yaml.safe_load(payload)", flags=re.I | re.S),
    _rule("COR-EXC-002", "broad_exception", r"catch\s*\(\s*(Exception|Error)\b|except\s+Exception\b|^\s*rescue\s*$", "except Exception:", "except ValueError:", flags=re.I | re.M),
    _rule("LEG-CONFIG-002", "hardcoded_url", r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|staging[\w.-]*|dev[\w.-]*|internal[\w.-]*|corp[\w.-]*|local[\w.-]*)", "https://staging.example", "https://example.com", skips=("*.md", "*.txt", "*.lock")),
    _rule("LEG-MAGIC-001", "magic_number", r"(?<![\w.])(1\d{3,}|[2-9]\d{3,})(?![\w.])", "timeout = 5000", "timeout = DEFAULT_TIMEOUT", skips=("*.json", "*.yaml", "*.yml", "*.css", "*test*", "*.lock")),
    _rule("COR-EXC-003", "empty_catch", r"catch\s*(?:\([^)]*\))?\s*\{\s*\}|except(?:\s+[A-Za-z0-9_., ()]+)?\s*:\s*pass", "catch (err) {}", "catch (err) { report(err); }", flags=re.I | re.S),
    _rule("COR-PY-001", "python_mutable_default", r"^\s*(?:async\s+def|def)\s+\w+\s*\([^)]*=\s*(?:\[\]|\{\}|set\(\))", "def add(items=[]): pass", "def add(items=None): pass", flags=re.M | re.S),
    _rule("COR-GO-001", "go_blank_identifier_error", r"^\s*_\s*=\s*err\b|^\s*(?:_,\s*)+err\s*:=", "_ = err", "if err != nil { return err }", flags=re.M, suffixes=(".go",)),
    _rule("COR-GO-002", "go_panic_recover_business_logic", r"\bpanic\s*\(|\brecover\s*\(", 'panic("bad input")', "return err", suffixes=(".go",)),
    _rule("COR-CS-001", "csharp_throw_ex", r"\bthrow\s+ex\s*;", "throw ex;", "throw;", suffixes=(".cs",)),
    _rule("COR-SQL-001", "sql_null_blind_not_equal", r"(?:!=|<>)\s*['\"][^'\"]+['\"](?![^;\n]*(?:IS\s+NULL|IS\s+NOT\s+NULL|COALESCE|IFNULL))", "status != 'done'", "status != 'done' OR status IS NULL", suffixes=(".sql",)),
    _rule("COR-SQL-002", "sql_window_missing_frame", r"\bOVER\s*\((?=[^)]*\bORDER\s+BY\b)(?![^)]*\b(?:ROWS|RANGE|GROUPS)\b)[^)]*\)", "OVER (ORDER BY created_at)", "OVER (ORDER BY created_at ROWS UNBOUNDED PRECEDING)", flags=re.I | re.S, suffixes=(".sql",)),
    _rule("COR-PHP-001", "php_deprecated_mysql", r"\bmysql_(?:connect|query|fetch_|real_escape_string)", "mysql_connect($host)", "new PDO($dsn)", suffixes=(".php",)),
    _rule("LEG-NAMING-001", "robotic_function_name", r"\b(?:function\s+|def\s+|func\s+|public\s+\w+\s+|private\s+\w+\s+|protected\s+\w+\s+)?((?:calculate|process|handle)[A-Za-z0-9_]{32,})\s*\(", "def calculateComprehensiveUserDataProcessingResultValue():", "def calculate_total():"),
)

CUSTOM_CHECK_IDS = {
    "LEG-TODO-001",
    "LEG-LONG-FUNCTION-001",
    "LEG-DOCSTRING-001",
    "LEG-TS-ASSERT-001",
    "LEG-PHP-STRICT-001",
    "LEG-RUST-REFCELL-001",
    "LEG-MAGIC-STRING-001",
}
LEGACY_EXPECTED_CHECK_IDS = {rule.check_id for rule in LEGACY_RULES} | CUSTOM_CHECK_IDS | {
    "SUP-DEPENDENCY-002",
    "SUP-DEPENDENCY-004",
}


def _matches(path: str, patterns: tuple[str, ...]) -> bool:
    filename = Path(path).name
    return any(
        fnmatch.fnmatch(path, pattern)
        or fnmatch.fnmatch(filename, pattern)
        or (pattern.startswith("**/") and fnmatch.fnmatch(path, pattern[3:]))
        for pattern in patterns
    )


def _finding(check_id: str, name: str, path: str, line: int, evidence: str, source: str) -> Finding:
    return Finding(
        check_id=check_id,
        category=name,
        severity="medium",
        confidence="medium",
        path=path,
        line=line,
        evidence=evidence.replace("\n", " ")[:240],
        explanation=f"Preserved legacy detector: {name.replace('_', ' ')}.",
        remediation="Inspect the surrounding behavior and replace the construct or document why it is safe.",
        disposition="review-candidate",
        source=source,
    )


def _python_long_functions(text: str) -> list[tuple[int, str]]:
    lines = text.splitlines()
    found = []
    current = None
    for index, line in enumerate(lines, 1):
        match = re.match(r"^(\s*)(?:async\s+def|def)\s+([A-Za-z_]\w*)\s*\(", line)
        if match:
            if current and index - current[0] > 80:
                found.append((current[0], current[2]))
            current = (index, len(match.group(1)), match.group(2))
            continue
        if current and line.strip():
            indent = len(line) - len(line.lstrip(" "))
            if indent <= current[1] and not line.lstrip().startswith("#"):
                if index - current[0] > 80:
                    found.append((current[0], current[2]))
                current = None
    if current and len(lines) + 1 - current[0] > 80:
        found.append((current[0], current[2]))
    return found


def _brace_long_functions(text: str) -> list[tuple[int, str]]:
    start = re.compile(
        r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\("
        r"|^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{"
        r"|^\s*([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{"
    )
    found = []
    current = None
    depth = 0
    for index, line in enumerate(text.splitlines(), 1):
        if current is None:
            match = start.match(line)
            if not match:
                continue
            current = (index, next(group for group in match.groups() if group))
            depth = line.count("{") - line.count("}")
            if depth <= 0:
                current = None
            continue
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            if index - current[0] > 80:
                found.append(current)
            current = None
    return found


def _long_docstrings(text: str) -> list[tuple[int, str]]:
    pattern = re.compile(
        r"^(\s*)(?:async\s+def|def)\s+([A-Za-z_]\w*)\s*\([^)]*\).*?:\s*\n"
        r"\1\s+(?P<quote>\"\"\"|''')(?P<body>.*?)(?P=quote)",
        re.M | re.S,
    )
    found = []
    for match in pattern.finditer(text):
        if match.group("body").count("\n") + 2 > 5:
            found.append((text.count("\n", 0, match.start()) + 1, match.group(2)))
    return found


def _magic_strings(text: str) -> list[tuple[int, str]]:
    pattern = re.compile(r"(['\"])([^'\"\n\\]{10,})\1")
    counts = Counter()
    first = {}
    for match in pattern.finditer(text):
        literal = match.group(2).strip()
        if literal.startswith(("http://", "https://")):
            continue
        counts[literal] += 1
        first.setdefault(literal, text.count("\n", 0, match.start()) + 1)
    return [(first[value], value) for value, count in counts.items() if count >= 4]


def scan_legacy(path: str, text: str, source: str = "working-tree") -> list[Finding]:
    findings = []
    for rule in LEGACY_RULES:
        if rule.suffixes and Path(path).suffix.lower() not in rule.suffixes:
            continue
        if _matches(path, rule.skip_patterns):
            continue
        for item in rule.pattern.finditer(text):
            category = "secrets" if rule.category == "secrets" else rule.name
            finding = _finding(rule.check_id, category, path, text.count("\n", 0, item.start()) + 1, item.group(0), source)
            findings.append(finding)

    todo = list(re.finditer(r"\b(TODO|FIXME)\b", text, re.I))
    if len(todo) > 5:
        findings.append(_finding("LEG-TODO-001", "high_todo_density", path, text.count("\n", 0, todo[0].start()) + 1, f"{len(todo)} TODO/FIXME markers", source))

    suffix = Path(path).suffix.lower()
    spec = language_for_path(path)
    language_id = spec.language_id if spec is not None else ""
    if language_id == "python":
        for line, name in _python_long_functions(text):
            findings.append(_finding("LEG-LONG-FUNCTION-001", "long_function", path, line, f"{name} exceeds 80 lines", source))
        for line, name in _long_docstrings(text):
            findings.append(_finding("LEG-DOCSTRING-001", "excessive_docstring", path, line, f"{name} has a long docstring", source))
    elif language_id in {"javascript", "typescript"}:
        for line, name in _brace_long_functions(text):
            findings.append(_finding("LEG-LONG-FUNCTION-001", "long_function", path, line, f"{name} exceeds 80 lines", source))

    if language_id == "typescript":
        assertions = list(re.finditer(r"\bas\s+(?:any|unknown|[A-Za-z_$][\w$]*(?:<[^>\n]+>)?)", text))
        if len(assertions) > 5:
            findings.append(_finding("LEG-TS-ASSERT-001", "typescript_as_density", path, text.count("\n", 0, assertions[0].start()) + 1, f"{len(assertions)} assertions", source))
    if language_id == "php" and text.lstrip().startswith("<?php"):
        if "declare(strict_types=1)" not in "\n".join(text.lstrip().splitlines()[:5]).replace(" ", ""):
            findings.append(_finding("LEG-PHP-STRICT-001", "php_missing_strict_types", path, 1, "missing declare(strict_types=1)", source))
    if language_id == "rust":
        occurrences = list(re.finditer(r"Rc\s*<\s*RefCell\s*<", text))
        if len(occurrences) > 2:
            findings.append(_finding("LEG-RUST-REFCELL-001", "rust_refcell_overuse", path, text.count("\n", 0, occurrences[0].start()) + 1, f"{len(occurrences)} occurrences", source))
    for line, value in _magic_strings(text):
        findings.append(_finding("LEG-MAGIC-STRING-001", "magic_string", path, line, value, source))
    return findings


def validate_legacy_fixtures() -> list[str]:
    errors = []
    for rule in LEGACY_RULES:
        if not rule.pattern.search(rule.positive):
            errors.append(f"{rule.check_id}: positive fixture did not match")
        if rule.pattern.search(rule.negative):
            errors.append(f"{rule.check_id}: negative fixture matched")
    return errors
