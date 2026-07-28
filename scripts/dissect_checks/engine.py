from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import fnmatch
import json
import os
import re
import subprocess
import sys

from .legacy import scan_legacy
from .model import Finding
from .rules import RULES


DEFAULT_IGNORES = {
    ".git", ".next", ".turbo", ".cache", "node_modules", "vendor", "dist",
    "build", "coverage", "target", "__pycache__",
}
TEXT_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rs",
    ".rb", ".php", ".java", ".kt", ".kts", ".cs", ".swift", ".sh", ".bash",
    ".zsh", ".ps1", ".sql", ".tf", ".yml", ".yaml", ".json", ".toml",
    ".ini", ".cfg", ".md", ".txt", ".map",
}
JS_BUILTINS = {
    "assert", "buffer", "child_process", "crypto", "events", "fs", "http",
    "https", "module", "net", "os", "path", "process", "querystring",
    "stream", "timers", "tls", "url", "util", "worker_threads", "zlib",
}
PY_STDLIB = set(getattr(sys, "stdlib_module_names", ())) or {
    "argparse", "collections", "dataclasses", "fnmatch", "hashlib", "importlib",
    "json", "os", "pathlib", "re", "shlex", "shutil", "subprocess", "sys",
    "tempfile", "termios", "tomllib", "tty", "typing", "unittest",
}
DISSECT_SELF_EXCLUSIONS = {
    "README.md",
    "reference/methodology.md",
    "reference/check-families.md",
    "reference/report-template.md",
    "adapters/codex-instructions.md",
    "adapters/cursor-rules.md",
    "adapters/generic-instructions.md",
    "scripts/dissect_checks/rules.py",
    "scripts/dissect_checks/legacy.py",
    "tests/fixtures/security_cases.json",
    "tests/test_integration.py",
    "tests/test_rules.py",
    "tests/test_scanner.py",
}


@dataclass(frozen=True)
class ScanOptions:
    root: Path
    include_generated: bool = False
    include_history: bool = False
    history_depth: int = 20
    file_list: tuple[str, ...] = ()
    ignore: tuple[str, ...] = ()
    generated_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanReport:
    findings: tuple[Finding, ...]
    complete: bool
    coverage_errors: tuple[str, ...] = ()


def _normalise(path: str) -> str:
    value = Path(path).as_posix()
    while value.startswith("./"):
        value = value[2:]
    return value


def _configured(root: Path) -> dict:
    try:
        return json.loads((root / ".ai-review" / "local.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def options_from_environment(root: Path, *, include_generated: bool = False, include_history: bool = False) -> ScanOptions:
    config = _configured(root)
    paths = config.get("paths") or {}
    security = config.get("security_review") or {}
    file_list = []
    source = os.environ.get("AI_REVIEW_FILE_LIST", "").strip()
    if source:
        try:
            file_list = Path(source).read_text(encoding="utf-8").splitlines()
        except OSError:
            file_list = []
    try:
        history_depth = max(1, int(security.get("git_history_depth", 20)))
    except (TypeError, ValueError):
        history_depth = 20
    return ScanOptions(
        root=root,
        include_generated=include_generated or bool(security.get("scan_generated_bundles")),
        include_history=include_history or bool(security.get("scan_git_history")),
        history_depth=history_depth,
        file_list=tuple(_normalise(item) for item in file_list if item.strip()),
        ignore=tuple(_normalise(item) for item in paths.get("ignore", [])),
        generated_paths=tuple(dict.fromkeys(
            _normalise(item)
            for item in [*paths.get("generated", []), *paths.get("generated_bundles", [])]
        )),
    )


def _matches_prefix_or_glob(rel: str, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        clean = pattern.rstrip("/")
        if clean and (rel == clean or rel.startswith(clean + "/") or fnmatch.fnmatch(rel, clean)):
            return True
    return False


def _is_dissect_repository(root: Path) -> bool:
    try:
        return (
            (root / "scripts" / "scan_ai_gotchas.py").exists()
            and "name: dissect" in (root / "SKILL.md").read_text(encoding="utf-8")
        )
    except OSError:
        return False


def _ignored(rel: str, options: ScanOptions) -> bool:
    if _is_dissect_repository(options.root):
        if rel in DISSECT_SELF_EXCLUSIONS or rel.startswith("reference/lang/"):
            return True
    parts = Path(rel).parts
    for part in parts:
        if part in DEFAULT_IGNORES:
            if options.include_generated and part in {"dist", "build", ".next"}:
                continue
            return True
    if _matches_prefix_or_glob(rel, options.ignore):
        conventional = any(part in {"dist", "build", ".next"} for part in parts)
        configured = _matches_prefix_or_glob(rel, options.generated_paths)
        if not (options.include_generated and (conventional or configured)):
            return True
    return _matches_prefix_or_glob(rel, options.generated_paths) and not options.include_generated


def _is_text_path(rel: str) -> bool:
    path = Path(rel)
    return (
        path.suffix.lower() in TEXT_SUFFIXES
        or path.name in {"Dockerfile", "Makefile"}
        or path.name.startswith(".env")
    )


def _candidate_files(options: ScanOptions) -> list[str]:
    if options.file_list:
        candidates = list(options.file_list)
    else:
        candidates = [
            path.relative_to(options.root).as_posix()
            for path in options.root.rglob("*")
            if path.is_file()
        ]
    return sorted({
        rel for rel in candidates
        if not _ignored(rel, options) and _is_text_path(rel)
    })


def scan_text(path: str, text: str, source: str = "working-tree") -> list[Finding]:
    findings = []
    for rule in RULES:
        findings.extend(rule.scan(path, text, source))
    findings.extend(scan_legacy(path, text, source))
    return findings


def _scan_history(options: ScanOptions) -> tuple[list[Finding], list[str]]:
    try:
        commits = subprocess.run(
            ["git", "rev-list", f"--max-count={options.history_depth}", "HEAD"],
            cwd=options.root, text=True, capture_output=True, check=False,
        )
    except OSError:
        return [], ["git history: git executable could not be started"]
    if commits.returncode != 0:
        return [], [f"git history: rev-list failed with exit {commits.returncode}"]

    findings = []
    errors = []
    allowed = set(options.file_list)
    for commit in commits.stdout.splitlines():
        names = subprocess.run(
            ["git", "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", commit],
            cwd=options.root, text=True, capture_output=True, check=False,
        )
        if names.returncode != 0:
            errors.append(f"git history: could not list commit {commit[:12]} (exit {names.returncode})")
            continue
        for rel in names.stdout.splitlines():
            rel = _normalise(rel)
            if allowed and rel not in allowed:
                continue
            if _ignored(rel, options) or not _is_text_path(rel):
                continue
            shown = subprocess.run(
                ["git", "show", f"{commit}:{rel}"],
                cwd=options.root, text=True, capture_output=True, check=False,
            )
            if shown.returncode:
                errors.append(f"git history: could not read {rel} at {commit[:12]} (exit {shown.returncode})")
                continue
            findings.extend(scan_text(rel, shown.stdout, source=f"git:{commit[:12]}"))
    return findings, errors


def _package_name(specifier: str) -> str:
    if specifier.startswith("@"):
        return "/".join(specifier.split("/")[:2])
    return specifier.split("/", 1)[0]


def _load_package_manifests(options: ScanOptions) -> tuple[dict[Path, tuple[Path, dict]], list[str]]:
    manifests = {}
    errors = []
    for path in options.root.rglob("package.json"):
        rel = path.relative_to(options.root).as_posix()
        if _ignored(rel, options):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except OSError:
            errors.append(f"dependency context: could not read {rel}")
            continue
        except ValueError:
            errors.append(f"dependency context: invalid JSON in {rel}")
            continue
        manifest = Path(rel)
        manifests[manifest.parent] = (manifest, data)
    return manifests, errors


def _nearest_manifest(rel: str, manifests: dict[Path, tuple[Path, dict]]) -> tuple[Path, dict] | None:
    parent = Path(rel).parent
    for directory in (parent, *parent.parents):
        if directory in manifests:
            return manifests[directory]
    return manifests.get(Path("."))


def _javascript_dependency_findings(
    options: ScanOptions,
    files: list[str],
    manifests: dict[Path, tuple[Path, dict]],
) -> list[Finding]:
    import_re = re.compile(
        r"(?:import\s+(?:[^'\"\n]+?\s+from\s+)?|require\s*\()\s*['\"]([^'\"\n]+)['\"]",
        re.M,
    )
    findings = []
    for rel in files:
        if Path(rel).suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            continue
        applicable = _nearest_manifest(rel, manifests)
        if applicable is None:
            continue
        manifest_path, data = applicable
        declared = set()
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            declared.update((data.get(key) or {}).keys())
        try:
            text = (options.root / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for item in import_re.finditer(text):
            specifier = item.group(1)
            if specifier.startswith((".", "/", "#", "@/", "node:")):
                continue
            package = _package_name(specifier)
            if package in JS_BUILTINS or package in declared:
                continue
            findings.append(Finding(
                check_id="SUP-DEPENDENCY-002",
                category="supply-chain",
                severity="high",
                confidence="medium",
                path=rel,
                line=text.count("\n", 0, item.start()) + 1,
                evidence=specifier,
                explanation=f"An external import is not declared in nearest manifest {manifest_path.as_posix()}.",
                remediation=f"Verify, declare, and lock the intended package in {manifest_path.as_posix()}.",
                disposition="review-candidate",
            ))
    return findings


def _python_dependency_findings(options: ScanOptions, files: list[str]) -> list[Finding]:
    local_roots = {
        path.name for path in options.root.iterdir()
        if path.is_dir() and not _ignored(path.name, options)
    }
    known = {
        "pytest", "django", "flask", "fastapi", "pydantic", "sqlalchemy",
        "requests", "numpy", "pandas",
    }
    import_re = re.compile(
        r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+([A-Za-z_][\w.]*))",
        re.M,
    )
    findings = []
    for rel in files:
        if Path(rel).suffix.lower() != ".py":
            continue
        try:
            text = (options.root / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        source_dir = options.root / Path(rel).parent
        try:
            sibling_modules = {
                child.stem if child.is_file() else child.name
                for child in source_dir.iterdir()
                if child.suffix == ".py" or child.is_dir()
            }
        except OSError:
            sibling_modules = set()
        for item in import_re.finditer(text):
            module = (item.group(1) or item.group(2)).split(".", 1)[0]
            if (
                module in PY_STDLIB
                or module in local_roots
                or module in sibling_modules
                or module in known
                or module.startswith("_")
            ):
                continue
            findings.append(Finding(
                check_id="SUP-DEPENDENCY-004",
                category="supply-chain",
                severity="medium",
                confidence="medium",
                path=rel,
                line=text.count("\n", 0, item.start()) + 1,
                evidence=module,
                explanation="A Python import is not recognised as standard-library, repository-local, or a known ecosystem dependency.",
                remediation="Verify the package name and declare it in the applicable Python dependency manifest.",
                disposition="review-candidate",
            ))
    return findings


def _lockfile_findings(options: ScanOptions, files: list[str], manifests: dict[Path, tuple[Path, dict]]) -> list[Finding]:
    lock_names = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"}
    scoped = set(files)
    findings = []
    for manifest, _data in manifests.values():
        if options.file_list and manifest.as_posix() not in scoped:
            continue
        directory = manifest.parent
        while True:
            if any((options.root / directory / name).exists() for name in lock_names):
                break
            if directory == Path(".") or directory.parent == directory:
                findings.append(Finding(
                    check_id="SUP-DEPENDENCY-003",
                    category="supply-chain",
                    severity="medium",
                    confidence="high",
                    path=manifest.as_posix(),
                    line=1,
                    evidence="no npm/pnpm/yarn/bun lockfile in manifest directory or ancestor",
                    explanation="Dependency resolution is not reproducibly locked.",
                    remediation="Generate and commit the applicable package-manager lockfile.",
                    disposition="review-candidate",
                ))
                break
            directory = directory.parent
    return findings


def scan_report(options: ScanOptions) -> ScanReport:
    findings = []
    errors = []
    files = _candidate_files(options)
    for rel in files:
        try:
            text = (options.root / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            errors.append(f"working tree: could not read {rel}")
            continue
        findings.extend(scan_text(rel, text))

    manifests, manifest_errors = _load_package_manifests(options)
    errors.extend(manifest_errors)
    findings.extend(_javascript_dependency_findings(options, files, manifests))
    findings.extend(_python_dependency_findings(options, files))
    findings.extend(_lockfile_findings(options, files, manifests))
    if options.include_history:
        history_findings, history_errors = _scan_history(options)
        findings.extend(history_findings)
        errors.extend(history_errors)

    unique = {
        (item.check_id, item.path, item.line, item.evidence, item.source): item
        for item in findings
    }
    ordered = tuple(sorted(
        unique.values(),
        key=lambda item: (item.path, item.line, item.check_id, item.source),
    ))
    return ScanReport(ordered, not errors, tuple(errors))


def scan_paths(options: ScanOptions) -> list[Finding]:
    return list(scan_report(options).findings)
