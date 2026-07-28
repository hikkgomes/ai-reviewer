from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import fnmatch
import json
import os
import re
import subprocess

from .legacy import scan_legacy
from .model import Finding
from .rules import RULES


DEFAULT_IGNORES = {
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


@dataclass(frozen=True)
class ScanOptions:
    root: Path
    include_generated: bool = False
    include_history: bool = False
    history_depth: int = 20
    file_list: tuple[str, ...] = ()
    ignore: tuple[str, ...] = ()
    generated_paths: tuple[str, ...] = ()


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
        generated_paths=tuple(
            dict.fromkeys(
                _normalise(item)
                for item in [*paths.get("generated", []), *paths.get("generated_bundles", [])]
            )
        ),
    )


def _matches_prefix_or_glob(rel: str, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        clean = pattern.rstrip("/")
        if not clean:
            continue
        if rel == clean or rel.startswith(clean + "/") or fnmatch.fnmatch(rel, clean):
            return True
    return False


def _ignored(rel: str, options: ScanOptions) -> bool:
    parts = Path(rel).parts
    for part in parts:
        if part in DEFAULT_IGNORES:
            if options.include_generated and part in {"dist", "build", ".next"}:
                continue
            return True
    if _matches_prefix_or_glob(rel, options.ignore):
        conventional_generated = any(part in {"dist", "build", ".next"} for part in parts)
        configured_generated = _matches_prefix_or_glob(rel, options.generated_paths)
        if not (options.include_generated and (conventional_generated or configured_generated)):
            return True
    if _matches_prefix_or_glob(rel, options.generated_paths) and not options.include_generated:
        return True
    return False


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
        if not _ignored(rel, options)
        and _is_text_path(rel)
    })


def _is_text_path(rel: str) -> bool:
    path = Path(rel)
    return (
        path.suffix.lower() in TEXT_SUFFIXES
        or path.name in {"Dockerfile", "Makefile"}
        or path.name.startswith(".env")
    )


def scan_text(path: str, text: str, source: str = "working-tree") -> list[Finding]:
    first_lines = "\n".join(text.splitlines()[:4])
    if "dissect: scanner-definition" in first_lines or '"_dissect": "scanner-fixture"' in first_lines:
        return []
    findings = []
    for rule in RULES:
        findings.extend(rule.scan(path, text, source))
    findings.extend(scan_legacy(path, text, source))
    return findings


def _scan_history(options: ScanOptions) -> list[Finding]:
    try:
        commits = subprocess.run(
            ["git", "rev-list", f"--max-count={options.history_depth}", "HEAD"],
            cwd=options.root,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError:
        return []
    if commits.returncode != 0:
        return []
    findings = []
    for commit in commits.stdout.splitlines():
        names = subprocess.run(
            ["git", "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", commit],
            cwd=options.root,
            text=True,
            capture_output=True,
            check=False,
        )
        for rel in names.stdout.splitlines():
            rel = _normalise(rel)
            if _ignored(rel, options) or not _is_text_path(rel):
                continue
            shown = subprocess.run(
                ["git", "show", f"{commit}:{rel}"],
                cwd=options.root,
                text=True,
                capture_output=True,
                check=False,
            )
            if shown.returncode == 0:
                findings.extend(scan_text(rel, shown.stdout, source=f"git:{commit[:12]}"))
    return findings


def _package_name(specifier: str) -> str:
    if specifier.startswith("@"):
        return "/".join(specifier.split("/")[:2])
    return specifier.split("/", 1)[0]


def _repository_dependency_findings(options: ScanOptions, files: list[str]) -> list[Finding]:
    manifests = []
    declared = set()
    manifest_paths = sorted({
        path.relative_to(options.root).as_posix()
        for path in options.root.rglob("package.json")
        if path.is_file()
        and not _ignored(path.relative_to(options.root).as_posix(), options)
    })
    for rel in manifest_paths:
        try:
            data = json.loads((options.root / rel).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        manifests.append(Path(rel))
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            declared.update((data.get(key) or {}).keys())
    if not manifests:
        return []

    findings = []
    import_re = re.compile(
        r"(?:import\s+(?:[^'\"\n]+?\s+from\s+)?|require\s*\()\s*['\"]([^'\"\n]+)['\"]",
        re.M,
    )
    for rel in files:
        if Path(rel).suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            continue
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
                explanation="An external JavaScript/TypeScript import is not declared in an available manifest.",
                remediation="Declare and lock the intended package after verifying its official name and usage.",
                disposition="review-candidate",
            ))

    lock_names = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"}
    scoped_files = set(files)
    for manifest in manifests:
        if options.file_list and manifest.as_posix() not in scoped_files:
            continue
        directory = manifest.parent
        lock_found = False
        while True:
            if any((options.root / directory / name).exists() for name in lock_names):
                lock_found = True
                break
            if directory == Path(".") or directory.parent == directory:
                break
            directory = directory.parent
        if not lock_found:
            findings.append(Finding(
                check_id="SUP-DEPENDENCY-003",
                category="supply-chain",
                severity="medium",
                confidence="high",
                path=manifest.as_posix(),
                line=1,
                evidence="package.json has no npm/pnpm/yarn/bun lockfile in its directory or an ancestor",
                explanation="Dependency resolution is not reproducibly locked in the available repository.",
                remediation="Generate and commit the package-manager lockfile, or document an intentional exception.",
                disposition="review-candidate",
            ))
    return findings


def scan_paths(options: ScanOptions) -> list[Finding]:
    findings = []
    files = _candidate_files(options)
    for rel in files:
        try:
            text = (options.root / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        findings.extend(scan_text(rel, text))
    findings.extend(_repository_dependency_findings(options, files))
    if options.include_history:
        findings.extend(_scan_history(options))
    unique = {(
        item.check_id, item.path, item.line, item.evidence, item.source
    ): item for item in findings}
    return sorted(unique.values(), key=lambda item: (item.path, item.line, item.check_id, item.source))


def history_scan_available(options: ScanOptions) -> bool:
    if not options.include_history:
        return True
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=options.root,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError:
        return False
    return result.returncode == 0 and result.stdout.strip() == "true"
