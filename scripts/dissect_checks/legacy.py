# dissect: scanner-definition
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from .model import Finding


@dataclass(frozen=True)
class LegacyRule:
    check_id: str
    name: str
    pattern: re.Pattern
    explanation: str
    remediation: str
    positive: str
    negative: str


# These preserve the original generic heuristics while the evidence-first rules
# in rules.py handle security and production-readiness domains.
LEGACY_RULES = (
    LegacyRule("COR-EXC-001", "swallowed_exception", re.compile(r"except\s*:\s*pass|catch\s*\([^)]*\)\s*\{\s*\}", re.I | re.S), "An exception is discarded.", "Handle the expected exception and preserve actionable context.", "try: work()\nexcept: pass", "try: work()\nexcept ValueError as exc: raise BadInput() from exc"),
    LegacyRule("SEC-INJECT-001", "sql_concatenation", re.compile(r"(?:f['\"][^\n]*(?:SELECT|INSERT|UPDATE|DELETE)|(?:SELECT|INSERT|UPDATE|DELETE)[^\n]*\+\s*\w+)", re.I), "A SQL statement is built with string interpolation.", "Use a parameterised query.", 'query = f"SELECT * FROM users WHERE id={value}"', 'query = "SELECT * FROM users WHERE id = ?"'),
    LegacyRule("SEC-INJECT-002", "shell_injection_risk", re.compile(r"(?:subprocess\.(?:run|Popen)|os\.system)\s*\([^)\n]*(?:\+|f['\"])", re.I), "A shell/process command is composed from interpolated text.", "Pass a fixed argument vector and validate values.", 'subprocess.run(f"tool {name}", shell=True)', 'subprocess.run(["tool", name], check=True)'),
    LegacyRule("SEC-DESER-001", "unsafe_deserialization", re.compile(r"pickle\.load\s*\(|yaml\.load\s*\((?![^)]*Loader\s*=)|Marshal\.load\s*\(|\bunserialize\s*\(", re.I), "An unsafe deserialisation API is used.", "Use a safe parser/loader and validate the schema.", "yaml.load(payload)", "yaml.safe_load(payload)"),
    LegacyRule("SEC-CODE-001", "unsafe_eval", re.compile(r"\beval\s*\(|new Function\s*\(|(?<!\.)\bexec\s*\(", re.I), "Dynamic code execution is used.", "Replace dynamic evaluation with explicit parsing/dispatch.", "eval(user_input)", "json.loads(user_input)"),
    LegacyRule("COR-PY-001", "python_mutable_default", re.compile(r"^\s*(?:async\s+def|def)\s+\w+\s*\([^)]*=\s*(?:\[\]|\{\}|set\(\))", re.M | re.S), "A mutable Python default is shared across calls.", "Use None and initialise inside the function.", "def add(items=[]): return items", "def add(items=None): return [] if items is None else items"),
    LegacyRule("COR-CS-001", "csharp_throw_ex", re.compile(r"\bthrow\s+ex\s*;", re.I), "C# rethrow resets the original stack trace.", "Use `throw;` inside the catch block.", "catch(Exception ex) { throw ex; }", "catch(Exception) { throw; }"),
    LegacyRule("COR-PHP-001", "php_deprecated_mysql", re.compile(r"\bmysql_(?:connect|query|fetch_|real_escape_string)", re.I), "A removed legacy PHP MySQL API is used.", "Use PDO or mysqli with prepared statements.", "$db = mysql_connect($host);", "$db = new PDO($dsn);"),
)


def scan_legacy(path: str, text: str, source: str = "working-tree") -> list[Finding]:
    if Path(path).suffix.lower() in {".md", ".txt"}:
        return []
    findings = []
    for rule in LEGACY_RULES:
        for item in rule.pattern.finditer(text):
            findings.append(
                Finding(
                    check_id=rule.check_id,
                    category=rule.name,
                    severity="medium",
                    confidence="medium",
                    path=path,
                    line=text.count("\n", 0, item.start()) + 1,
                    evidence=item.group(0).replace("\n", " ")[:240],
                    explanation=rule.explanation,
                    remediation=rule.remediation,
                    disposition="finding",
                    source=source,
                )
            )
    return findings


def validate_legacy_fixtures() -> list[str]:
    errors = []
    for rule in LEGACY_RULES:
        if not rule.pattern.search(rule.positive):
            errors.append(f"{rule.check_id}: positive fixture did not match")
        if rule.pattern.search(rule.negative):
            errors.append(f"{rule.check_id}: negative fixture matched")
    return errors
