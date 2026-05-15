#!/usr/bin/env python3
from __future__ import annotations

from collections import Counter
from pathlib import Path
import fnmatch
import json
import os
import re
import subprocess
import sys


ROOT = Path.cwd()
DEFAULT_IGNORE_PARTS = {
    ".git",
    ".next",
    ".turbo",
    ".cache",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    "target",
    "__pycache__",
}
LOCKFILES = {
    "Cargo.lock",
    "Gemfile.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "yarn.lock",
}
TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".java",
    ".kt",
    ".kts",
    ".cs",
    ".swift",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".sql",
    ".tf",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".md",
    ".txt",
}
SKIP_PATTERNS = {
    "hardcoded_ip": ["*.json", "*.yaml", "*.yml", "*.toml", "Dockerfile", "*.cfg"],
    "hardcoded_credential": ["*.example", "*.sample", "*.md"],
    "debug_print": ["*test*", "*spec*", "**/scripts/**", "*.md"],
    "unhandled_promise": ["*test*"],
    "env_no_default": ["*.d.ts", "*.md"],
    "hardcoded_url": ["*.md", "*.txt", "*.lock"],
    "magic_number": ["*.json", "*.yaml", "*.yml", "*.css", "*test*", "*.lock"],
    "unknown_dependency_import": ["*.md", "*.d.ts"],
}
PATTERNS = [
    ("placeholder", re.compile(r"\b(TODO|FIXME|changeme|dummy[_ -]?key|your[_ -]?api[_ -]?key|lorem ipsum)\b", re.I)),
    ("swallowed_exception", re.compile(r"except\s*:\s*pass|catch\s*\([^)]*\)\s*\{\s*\}", re.I | re.S)),
    ("sql_concatenation", re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*(\+|%s|f['\"]).*", re.I | re.S)),
    ("tls_disabled", re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED", re.I)),
    ("secret_logging", re.compile(r"console\.log\(.*(token|secret|password|api[_-]?key)|logger\..*\b(token|secret|password|api[_-]?key)\b", re.I)),
    ("shell_injection_risk", re.compile(r"(subprocess\.(run|Popen)\(|exec\(|spawn\(|os\.system\().*(\+|f['\"]|\$\{)", re.I | re.S)),
    ("hardcoded_ip", re.compile(r"['\"](?:\d{1,3}\.){3}\d{1,3}['\"]")),
    ("hardcoded_credential", re.compile(r"\b(password|secret|api[_-]?key|access[_-]?key|token)\b\s*[:=]\s*['\"][^'\"]+['\"]", re.I)),
    ("debug_print", re.compile(r"console\.log\s*\(|\bprint\s*\(|fmt\.Print(?:f|ln)?\s*\(|System\.out\.print(?:ln)?\s*\(|\bdebugger\b")),
    ("dead_code_marker", re.compile(r"(//|#|/\*+)\s*(HACK|XXX|TEMP|REMOVEME)\b", re.I)),
    ("unsafe_eval", re.compile(r"\beval\s*\(|new Function\s*\(|(?<!\.)\bexec\s*\(", re.I)),
    ("unhandled_promise", re.compile(r"\.then\s*\((?:(?!\.catch|\.finally).)*\)(?!\s*\.(catch|finally))", re.I | re.S)),
    ("env_no_default", re.compile(r"process\.env(?:\.[A-Z0-9_]+|\[['\"][A-Z0-9_]+['\"]\])(?!\s*(\|\||\?\?))|os\.environ\[['\"][A-Z0-9_]+['\"]\]", re.I)),
    ("unsafe_deserialization", re.compile(r"pickle\.load\s*\(|yaml\.load\s*\((?![^)]*Loader\s*=)|Marshal\.load\s*\(|\bunserialize\s*\(", re.I | re.S)),
    ("broad_exception", re.compile(r"catch\s*\(\s*(Exception|Error)\b|except\s+Exception\b|^\s*rescue\s*$", re.I | re.M)),
    ("hardcoded_url", re.compile(r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|staging[\w.-]*|dev[\w.-]*|internal[\w.-]*|corp[\w.-]*|local[\w.-]*)", re.I)),
    ("magic_number", re.compile(r"(?<![\w.])(1\d{3,}|[2-9]\d{3,})(?![\w.])")),
    ("empty_catch", re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}|except(?:\s+[A-Za-z0-9_., ()]+)?\s*:\s*pass", re.I | re.S)),
    ("python_mutable_default", re.compile(r"^\s*(?:async\s+def|def)\s+\w+\s*\([^)]*=\s*(?:\[\]|\{\}|set\(\))", re.M | re.S)),
    ("go_blank_identifier_error", re.compile(r"^\s*_\s*=\s*err\b|^\s*(?:_,\s*)+err\s*:=", re.M)),
    ("go_panic_recover_business_logic", re.compile(r"\bpanic\s*\(|\brecover\s*\(", re.I)),
    ("csharp_throw_ex", re.compile(r"\bthrow\s+ex\s*;", re.I)),
    ("sql_null_blind_not_equal", re.compile(r"(?:!=|<>)\s*['\"][^'\"]+['\"](?![^;\n]*(?:IS\s+NULL|IS\s+NOT\s+NULL|COALESCE|IFNULL))", re.I)),
    ("sql_window_missing_frame", re.compile(r"\bOVER\s*\((?=[^)]*\bORDER\s+BY\b)(?![^)]*\b(?:ROWS|RANGE|GROUPS)\b)[^)]*\)", re.I | re.S)),
    ("php_deprecated_mysql", re.compile(r"\bmysql_(?:connect|query|fetch_|real_escape_string)", re.I)),
    ("robotic_function_name", re.compile(r"\b(?:function\s+|def\s+|func\s+|public\s+\w+\s+|private\s+\w+\s+|protected\s+\w+\s+)?((?:calculate|process|handle)[A-Za-z0-9_]{32,})\s*\(", re.I)),
]

JS_BUILTINS = {
    "assert",
    "buffer",
    "child_process",
    "crypto",
    "events",
    "fs",
    "http",
    "https",
    "net",
    "os",
    "path",
    "process",
    "querystring",
    "stream",
    "timers",
    "url",
    "util",
    "zlib",
}
PY_STDLIB = set(getattr(sys, "stdlib_module_names", set()))


def load_local() -> dict:
    path = ROOT / ".ai-review" / "local.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


LOCAL = load_local()


def normalize_rel(path: str) -> str:
    return Path(path).as_posix().lstrip("./")


def workspace_entries() -> list[tuple[str, str]]:
    entries = []
    for name, payload in (LOCAL.get("workspaces") or {}).items():
        rel_root = normalize_rel((payload or {}).get("root") or name)
        entries.append((name, rel_root))
    entries.sort(key=lambda item: len(item[1]), reverse=True)
    return entries


WORKSPACES = workspace_entries()
IGNORE_PREFIXES = [normalize_rel(p) for p in ((LOCAL.get("paths") or {}).get("ignore") or [])]
IGNORE_PREFIXES += [normalize_rel(p) for p in ((LOCAL.get("paths") or {}).get("generated") or [])]


def is_binary(path: Path) -> bool:
    try:
        data = path.read_bytes()
    except Exception:
        return True
    return b"\x00" in data


def matches_any(rel: str, patterns: list[str]) -> bool:
    rel_posix = normalize_rel(rel)
    filename = Path(rel_posix).name
    return any(fnmatch.fnmatch(rel_posix, pattern) or fnmatch.fnmatch(filename, pattern) for pattern in patterns)


def should_ignore(rel: str) -> bool:
    rel_posix = normalize_rel(rel)
    parts = Path(rel_posix).parts
    if any(part in DEFAULT_IGNORE_PARTS for part in parts):
        return True
    if Path(rel_posix).name in LOCKFILES:
        return True
    for prefix in IGNORE_PREFIXES:
        cleaned = prefix.rstrip("/")
        if cleaned and (rel_posix == cleaned or rel_posix.startswith(f"{cleaned}/")):
            return True
    return False


def current_files() -> list[str]:
    file_list = os.environ.get("AI_REVIEW_FILE_LIST", "").strip()
    if file_list:
        try:
            changed = Path(file_list).read_text(encoding="utf-8").splitlines()
        except Exception:
            changed = []
        changed = [normalize_rel(path) for path in changed if path.strip()]
        return [path for path in changed if not should_ignore(path)]

    try:
        changed = subprocess.check_output(
            "(git diff --name-only --cached; git diff --name-only; git ls-files --others --exclude-standard) 2>/dev/null | sort -u",
            shell=True,
            text=True,
            cwd=ROOT,
        ).splitlines()
    except Exception:
        changed = []
    changed = [normalize_rel(path) for path in changed if path.strip()]
    if changed:
        return [path for path in changed if not should_ignore(path)]

    files = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = normalize_rel(path.relative_to(ROOT).as_posix())
        if should_ignore(rel):
            continue
        files.append(rel)
        if len(files) >= 500:
            break
    return files


def label_for_workspace(rel: str) -> str:
    rel_posix = normalize_rel(rel)
    for name, root in WORKSPACES:
        cleaned = root.rstrip("/")
        if cleaned and (rel_posix == cleaned or rel_posix.startswith(f"{cleaned}/")):
            return name
    return ""


def load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def load_package_dependencies() -> set[str]:
    deps = set()
    for package_json in ROOT.rglob("package.json"):
        rel = normalize_rel(package_json.relative_to(ROOT).as_posix())
        if should_ignore(rel):
            continue
        data = {}
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
        except Exception:
            continue
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            deps.update((data.get(key) or {}).keys())
    return deps


JS_DEPENDENCIES = load_package_dependencies()


def package_name(specifier: str) -> str:
    if specifier.startswith("@"):
        parts = specifier.split("/")
        return "/".join(parts[:2])
    return specifier.split("/", 1)[0]


def add_finding(findings: list[tuple[str, str, int, str, str]], pattern: str, rel: str, line: int, snippet: str) -> None:
    findings.append((label_for_workspace(rel), pattern, line, rel, snippet.replace("\n", " ")[:140]))


def detect_python_long_functions(text: str) -> list[tuple[int, str]]:
    lines = text.splitlines()
    findings = []
    current = None
    for index, line in enumerate(lines, start=1):
        match = re.match(r"^(\s*)(async\s+def|def)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
        if match:
            indent = len(match.group(1))
            if current and index - current["start"] > 80:
                findings.append((current["start"], current["name"]))
            current = {"start": index, "indent": indent, "name": match.group(3)}
            continue
        if not current:
            continue
        stripped = line.strip()
        if not stripped:
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= current["indent"] and not stripped.startswith("#"):
            if index - current["start"] > 80:
                findings.append((current["start"], current["name"]))
            current = None
    if current and len(lines) + 1 - current["start"] > 80:
        findings.append((current["start"], current["name"]))
    return findings


def detect_brace_long_functions(text: str) -> list[tuple[int, str]]:
    lines = text.splitlines()
    findings = []
    start_regex = re.compile(
        r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\("
        r"|^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{"
        r"|^\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^)]*\)\s*\{"
    )
    current = None
    brace_depth = 0
    for index, line in enumerate(lines, start=1):
        if current is None:
            match = start_regex.match(line)
            if not match:
                continue
            name = next(group for group in match.groups() if group)
            current = {"start": index, "name": name}
            brace_depth = line.count("{") - line.count("}")
            if brace_depth <= 0:
                current = None
            continue
        brace_depth += line.count("{") - line.count("}")
        if brace_depth <= 0:
            if index - current["start"] > 80:
                findings.append((current["start"], current["name"]))
            current = None
    return findings


def detect_magic_strings(text: str) -> list[tuple[int, str]]:
    pattern = re.compile(r"(['\"])([^'\"\n\\]{10,})\1")
    counts = Counter()
    first_line = {}
    for match in pattern.finditer(text):
        literal = match.group(2).strip()
        if literal.startswith("http://") or literal.startswith("https://"):
            continue
        counts[literal] += 1
        first_line.setdefault(literal, text.count("\n", 0, match.start()) + 1)
    return [(first_line[literal], literal) for literal, count in counts.items() if count >= 4]


def detect_ts_as_density(text: str) -> tuple[int, int] | None:
    matches = list(re.finditer(r"\bas\s+(?:any|unknown|[A-Za-z_$][\w$]*(?:<[^>\n]+>)?)", text))
    if len(matches) > 5:
        return text.count("\n", 0, matches[0].start()) + 1, len(matches)
    return None


def detect_php_missing_strict(text: str) -> bool:
    stripped = text.lstrip()
    if not stripped.startswith("<?php"):
        return False
    first_lines = "\n".join(stripped.splitlines()[:5])
    return "declare(strict_types=1)" not in first_lines.replace(" ", "")


def detect_long_docstrings(text: str) -> list[tuple[int, str]]:
    findings = []
    lines = text.splitlines()
    in_function = False
    function_name = ""
    function_line = 0
    function_indent = 0
    for index, line in enumerate(lines, start=1):
        match = re.match(r"^(\s*)(?:async\s+def|def)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
        if match:
            in_function = True
            function_name = match.group(2)
            function_line = index
            function_indent = len(match.group(1))
            continue
        if not in_function:
            continue
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= function_indent:
            in_function = False
            continue
        doc_start = re.match(r'^\s*("""|\'\'\')', line)
        if not doc_start:
            in_function = False
            continue
        quote = doc_start.group(1)
        count = 1
        if line.count(quote) >= 2 and line.strip() != quote:
            in_function = False
            continue
        for follow in lines[index:]:
            count += 1
            if quote in follow:
                break
        if count > 5:
            findings.append((function_line, f"{function_name} has a {count}-line docstring"))
        in_function = False
    return findings


def detect_unknown_js_imports(text: str) -> list[tuple[int, str]]:
    if not JS_DEPENDENCIES:
        return []
    findings = []
    regex = re.compile(r"(?:import\s+(?:[^'\"\n]+?\s+from\s+)?|require\s*\()\s*['\"]([^'\"\n]+)['\"]", re.M)
    for match in regex.finditer(text):
        specifier = match.group(1)
        if specifier.startswith((".", "/", "#", "@/")) or specifier in JS_BUILTINS or specifier.startswith("node:"):
            continue
        name = package_name(specifier)
        if name not in JS_DEPENDENCIES:
            line = text.count("\n", 0, match.start()) + 1
            findings.append((line, specifier))
    return findings


def detect_unknown_python_imports(text: str) -> list[tuple[int, str]]:
    local_roots = {path.name for path in ROOT.iterdir() if path.is_dir() and not should_ignore(path.name)}
    findings = []
    regex = re.compile(r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+([A-Za-z_][\w.]*))", re.M)
    for match in regex.finditer(text):
        module = (match.group(1) or match.group(2)).split(".", 1)[0]
        if module in PY_STDLIB or module in local_roots or module.startswith("_"):
            continue
        if module in {"pytest", "django", "flask", "fastapi", "pydantic", "sqlalchemy", "requests", "numpy", "pandas"}:
            continue
        line = text.count("\n", 0, match.start()) + 1
        findings.append((line, module))
    return findings


def scan_file(rel: str, findings: list[tuple[str, str, int, str, str]]) -> None:
    path = ROOT / rel
    if not path.exists() or not path.is_file():
        return
    if should_ignore(rel):
        return
    if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in {"Dockerfile", "Makefile"}:
        return
    if is_binary(path):
        return

    text = load_text(path)
    if not text:
        return

    for name, regex in PATTERNS:
        if matches_any(rel, SKIP_PATTERNS.get(name, [])):
            continue
        for match in regex.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            add_finding(findings, name, rel, line, match.group(0))

    todo_matches = list(re.finditer(r"\b(TODO|FIXME)\b", text, re.I))
    if len(todo_matches) > 5:
        add_finding(findings, "high_todo_density", rel, text.count("\n", 0, todo_matches[0].start()) + 1, f"{len(todo_matches)} TODO/FIXME markers")

    if path.suffix.lower() == ".py":
        for line, name in detect_python_long_functions(text):
            add_finding(findings, "long_function", rel, line, f"{name} exceeds 80 lines")
        for line, snippet in detect_long_docstrings(text):
            add_finding(findings, "excessive_docstring", rel, line, snippet)
        for line, module in detect_unknown_python_imports(text):
            add_finding(findings, "unknown_dependency_import", rel, line, module)
    elif path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx"}:
        for line, name in detect_brace_long_functions(text):
            add_finding(findings, "long_function", rel, line, f"{name} exceeds 80 lines")
        for line, specifier in detect_unknown_js_imports(text):
            add_finding(findings, "unknown_dependency_import", rel, line, specifier)

    if path.suffix.lower() in {".ts", ".tsx"}:
        density = detect_ts_as_density(text)
        if density:
            line, count = density
            add_finding(findings, "typescript_as_density", rel, line, f"{count} TypeScript 'as' assertions")

    if path.suffix.lower() == ".php" and detect_php_missing_strict(text):
        add_finding(findings, "php_missing_strict_types", rel, 1, "missing declare(strict_types=1)")

    if path.suffix.lower() == ".rs":
        count = len(re.findall(r"Rc\s*<\s*RefCell\s*<", text))
        if count > 2:
            line = text.count("\n", 0, re.search(r"Rc\s*<\s*RefCell\s*<", text).start()) + 1
            add_finding(findings, "rust_refcell_overuse", rel, line, f"{count} Rc<RefCell< occurrences")

    for line, literal in detect_magic_strings(text):
        add_finding(findings, "magic_string", rel, line, literal)


def main() -> None:
    findings: list[tuple[str, str, int, str, str]] = []
    for rel in current_files():
        scan_file(rel, findings)

    if not findings:
        print("No heuristic gotchas detected.")
        sys.exit(0)

    findings.sort(key=lambda item: (item[3], item[2], item[1], item[0]))
    for workspace, name, line, rel, snippet in findings:
        if workspace:
            print(f"[{workspace}][{name}] {rel}:{line} :: {snippet}")
        else:
            print(f"[{name}] {rel}:{line} :: {snippet}")


if __name__ == "__main__":
    main()
