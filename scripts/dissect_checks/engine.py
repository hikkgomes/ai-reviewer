from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys

from .fixtures import is_trusted_self_review, mask_owned_fixture_spans
from .legacy import scan_legacy
from .model import Finding, HistoricalSource
from .python_dependencies import (
    KNOWN_IMPORT_ALIASES,
    installed_aliases,
    load_python_manifests,
    nearest_context,
    normalise_name,
)
from .redaction import redact_sensitive_text
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
    "argparse", "ast", "collections", "dataclasses", "fnmatch", "hashlib", "importlib",
    "json", "os", "pathlib", "re", "shlex", "shutil", "subprocess", "sys",
    "tempfile", "termios", "tomllib", "tty", "typing", "unittest",
}
DISSECT_FIXTURE_EXCLUSIONS = {
    "tests/fixtures/security_cases.json",
}


@dataclass(frozen=True)
class ScanOptions:
    root: Path
    include_generated: bool = False
    include_history: bool = False
    history_depth: int = 20
    file_list: tuple[str, ...] = ()
    diff_entries: tuple[tuple[str, str, str, bool, str], ...] = ()
    ignore: tuple[str, ...] = ()
    generated_paths: tuple[str, ...] = ()
    python_import_aliases: tuple[tuple[str, str], ...] = ()
    self_review_approval: str = ""


@dataclass(frozen=True)
class ScanReport:
    findings: tuple[Finding, ...]
    complete: bool
    coverage_errors: tuple[str, ...] = ()


@dataclass
class _HistoryLineage:
    reviewed_path: str
    aliases: set[str]
    copy_ancestry: set[str]

    def follows(self, path: str) -> bool:
        return path in self.aliases or path in self.copy_ancestry


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


def options_from_environment(
    root: Path,
    *,
    include_generated: bool = False,
    include_history: bool = False,
    self_review_approval: str = "",
) -> ScanOptions:
    config = _configured(root)
    paths = config.get("paths") or {}
    security = config.get("security_review") or {}
    file_list = []
    diff_entries = []
    source = os.environ.get("AI_REVIEW_FILE_LIST", "").strip()
    if source:
        try:
            for value in Path(source).read_bytes().split(b"\0"):
                if not value:
                    continue
                try:
                    entry = json.loads(value.decode("utf-8"))
                    status = str(entry["status"])
                    old_path = _normalise(str(entry["old_path"]))
                    new_path = _normalise(str(entry["new_path"]))
                    exists = bool(entry["exists_in_worktree"])
                    base = str(entry.get("base_revision", ""))
                    diff_entries.append((status, old_path, new_path, exists, base))
                    if exists:
                        file_list.append(new_path)
                except (KeyError, TypeError, ValueError, UnicodeDecodeError):
                    # Compatibility with previous NUL-delimited path-only transport.
                    file_list.append(value.decode("utf-8", errors="surrogateescape"))
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
        file_list=tuple(_normalise(item) for item in file_list if item),
        diff_entries=tuple(diff_entries),
        ignore=tuple(_normalise(item) for item in paths.get("ignore", [])),
        generated_paths=tuple(dict.fromkeys(
            _normalise(item)
            for item in [*paths.get("generated", []), *paths.get("generated_bundles", [])]
        )),
        python_import_aliases=tuple(
            (str(module), str(distribution))
            for module, distribution in (security.get("python_import_aliases") or {}).items()
        ),
        self_review_approval=self_review_approval,
    )


def _matches_prefix_or_glob(rel: str, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        clean = pattern.rstrip("/")
        if clean and (rel == clean or rel.startswith(clean + "/") or fnmatch.fnmatch(rel, clean)):
            return True
    return False


def _ignored(rel: str, options: ScanOptions) -> bool:
    if (
        is_trusted_self_review(options.root, options.self_review_approval)
        and rel in DISSECT_FIXTURE_EXCLUSIONS
    ):
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
    if options.diff_entries:
        candidates = [new for _status, _old, new, exists, _base in options.diff_entries if exists]
    elif options.file_list:
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
    lines = text.splitlines()
    ordinals: dict[tuple[str, str, str], int] = {}
    annotated = []
    for finding in findings:
        index = max(0, min(len(lines) - 1, finding.line - 1)) if lines else 0
        current = lines[index].strip() if lines else ""
        after = [
            value.strip()
            for value in lines[index + 1:index + 5]
            if value.strip()
        ][:2]
        symbol = ""
        for candidate in reversed(lines[:index + 1]):
            stripped = candidate.strip()
            if re.match(
                r"(?:async\s+)?(?:def|class|function)\s+[\w$]+|"
                r"(?:const|let|var)\s+[\w$]+\s*=\s*(?:async\s*)?\(",
                stripped,
            ):
                symbol = stripped
                break
        context_payload = json.dumps(
            {
                "symbol": symbol,
                "current": current,
                "after": after,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        context_fingerprint = hashlib.sha256(
            context_payload.encode("utf-8", errors="surrogatepass")
        ).hexdigest()[:16]
        base = (
            finding.check_id,
            finding.match_fingerprint,
            context_fingerprint,
        )
        ordinal = ordinals.get(base, 0)
        ordinals[base] = ordinal + 1
        occurrence_id = hashlib.sha256(
            "\0".join((*base, str(ordinal))).encode(
                "utf-8",
                errors="surrogatepass",
            )
        ).hexdigest()[:20]
        annotated.append(replace(
            finding,
            context_fingerprint=context_fingerprint,
            occurrence_id=occurrence_id,
        ))
    return annotated


def _scan_owned_text(
    options: ScanOptions,
    reviewed_path: str,
    original_path: str,
    text: str,
    source: str,
) -> list[Finding]:
    masked = mask_owned_fixture_spans(
        options.root,
        original_path,
        text,
        options.self_review_approval,
    )
    return scan_text(reviewed_path, masked, source)


def _parse_name_status(data: bytes) -> tuple[list[tuple[str, str, str]], str | None]:
    tokens = data.split(b"\0")
    if tokens and not tokens[-1]:
        tokens.pop()
    entries = []
    index = 0
    while index < len(tokens):
        status = tokens[index].decode("ascii", errors="replace")
        index += 1
        path_count = 2 if status.startswith(("R", "C")) else 1
        if index + path_count > len(tokens):
            return entries, f"truncated name-status record for {status!r}"
        paths = [
            token.decode("utf-8", errors="surrogateescape")
            for token in tokens[index:index + path_count]
        ]
        index += path_count
        old_path = _normalise(paths[0])
        new_path = _normalise(paths[-1])
        entries.append((status, old_path, new_path))
    return entries, None


def _commit_statuses(
    options: ScanOptions,
    commit: str,
) -> tuple[list[tuple[str | None, str, str, str]], list[str]]:
    parents_result = subprocess.run(
        ["git", "rev-list", "--parents", "-n", "1", commit],
        cwd=options.root,
        capture_output=True,
        check=False,
    )
    if parents_result.returncode:
        return [], [f"git history: could not resolve parents for {commit[:12]}"]
    fields = parents_result.stdout.decode("ascii", errors="replace").strip().split()
    parents = fields[1:]
    comparisons: list[tuple[str | None, list[str]]]
    if parents:
        comparisons = [
            (
                parent,
                [
                    "git", "diff-tree", "--no-commit-id", "--name-status", "-z",
                    "-M", "-C", "--find-copies-harder", "-r", parent, commit,
                ],
            )
            for parent in parents
        ]
    else:
        comparisons = [(
            None,
            [
                "git", "diff-tree", "--root", "--no-commit-id", "--name-status",
                "-z", "-M", "-C", "--find-copies-harder", "-r", commit,
            ],
        )]
    statuses = []
    errors = []
    for parent, command in comparisons:
        result = subprocess.run(command, cwd=options.root, capture_output=True, check=False)
        if result.returncode:
            label = parent[:12] if parent else "root"
            errors.append(
                f"git history: diff {label}..{commit[:12]} failed with exit {result.returncode}"
            )
            continue
        parsed, parse_error = _parse_name_status(result.stdout)
        if parse_error:
            errors.append(f"git history: {commit[:12]}: {parse_error}")
            continue
        statuses.extend((parent, status, old, new) for status, old, new in parsed)
    return statuses, errors


def _read_history_blob(
    options: ScanOptions,
    revision: str,
    path: str,
) -> tuple[str | None, str | None]:
    result = subprocess.run(
        ["git", "show", f"{revision}:{path}"],
        cwd=options.root,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        return None, (
            f"git history: could not read {path!r} at {revision[:12]} "
            f"(exit {result.returncode})"
        )
    return result.stdout.decode("utf-8", errors="ignore"), None


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
    lineages = [
        _HistoryLineage(rel, {rel}, set())
        for rel in options.file_list
        if not _ignored(rel, options) and _is_text_path(rel)
    ]

    def create_lineage(path: str) -> _HistoryLineage:
        lineage = _HistoryLineage(path, {path}, set())
        lineages.append(lineage)
        return lineage

    def identity_matches(*paths: str) -> list[_HistoryLineage]:
        return [
            lineage for lineage in lineages
            if any(path in lineage.aliases for path in paths)
        ]

    def traversal_matches(*paths: str) -> list[_HistoryLineage]:
        return [
            lineage for lineage in lineages
            if any(lineage.follows(path) for path in paths)
        ]

    def merge_rename_identities(matches: list[_HistoryLineage]) -> _HistoryLineage | None:
        if not matches:
            return None
        primary = next(
            (
                lineage for lineage in matches
                if (options.root / lineage.reviewed_path).exists()
            ),
            matches[0],
        )
        for duplicate in matches:
            if duplicate is primary:
                continue
            primary.aliases.update(duplicate.aliases)
            primary.copy_ancestry.update(duplicate.copy_ancestry)
            lineages.remove(duplicate)
        return primary

    for commit in commits.stdout.splitlines():
        statuses, status_errors = _commit_statuses(options, commit)
        errors.extend(status_errors)
        targets: set[tuple[str, str, str, str]] = set()
        for parent, status, old_path, new_path in statuses:
            kind = status[:1]
            if kind == "R":
                identities = identity_matches(old_path, new_path)
                primary = merge_rename_identities(identities)
                relevant = traversal_matches(old_path, new_path)
                if primary is None and not options.file_list:
                    primary = create_lineage(new_path)
                    relevant.append(primary)
                relevant = list({
                    id(lineage): lineage for lineage in traversal_matches(old_path, new_path)
                }.values())
                for lineage in relevant:
                    if old_path in lineage.aliases or new_path in lineage.aliases:
                        lineage.aliases.update({old_path, new_path})
                    else:
                        lineage.copy_ancestry.update({old_path, new_path})
                    targets.add((
                        commit,
                        new_path,
                        lineage.reviewed_path,
                        f"rename:{old_path}->{new_path}",
                    ))
                    if parent:
                        targets.add((
                            parent,
                            old_path,
                            lineage.reviewed_path,
                            f"rename-parent:{old_path}",
                        ))
            elif kind == "C":
                relevant = [
                    lineage for lineage in lineages if lineage.follows(new_path)
                ]
                if not identity_matches(new_path) and not options.file_list:
                    relevant.append(create_lineage(new_path))
                for lineage in {
                    id(item): item for item in relevant
                }.values():
                    lineage.copy_ancestry.add(old_path)
                    targets.add((
                        commit,
                        new_path,
                        lineage.reviewed_path,
                        f"copy:{old_path}->{new_path}",
                    ))
                    if parent:
                        targets.add((
                            parent,
                            old_path,
                            lineage.reviewed_path,
                            f"copy-parent:{old_path}",
                        ))
                if not options.file_list and not identity_matches(old_path):
                    source_lineage = create_lineage(old_path)
                    if parent:
                        targets.add((
                            parent,
                            old_path,
                            source_lineage.reviewed_path,
                            f"copy-source:{old_path}",
                        ))
            elif kind == "D":
                relevant = traversal_matches(old_path)
                if not identity_matches(old_path) and not options.file_list:
                    relevant.append(create_lineage(old_path))
                if parent:
                    for lineage in {
                        id(item): item for item in relevant
                    }.values():
                        targets.add((
                            parent,
                            old_path,
                            lineage.reviewed_path,
                            f"deleted-parent:{old_path}",
                        ))
            elif kind in {"A", "M", "T"}:
                relevant = traversal_matches(new_path)
                if not identity_matches(new_path) and not options.file_list:
                    relevant.append(create_lineage(new_path))
                for lineage in {
                    id(item): item for item in relevant
                }.values():
                    targets.add((
                        commit,
                        new_path,
                        lineage.reviewed_path,
                        f"path:{new_path}",
                    ))
        ordered_targets = sorted(
            targets,
            key=lambda target: (
                0 if target[3].startswith(("rename:", "copy:")) else 1,
                target,
            ),
        )
        for revision, original_path, reviewed_path, provenance in ordered_targets:
            text, read_error = _read_history_blob(options, revision, original_path)
            if read_error:
                errors.append(read_error)
                continue
            assert text is not None
            source = f"git:{revision[:12]}:{provenance}"
            for finding in _scan_owned_text(
                options, reviewed_path, original_path, text, source
            ):
                findings.append(replace(
                    finding,
                    historical_sources=(
                        HistoricalSource(
                            source=source,
                            path=original_path,
                            line=finding.line,
                            commit=revision,
                            provenance_type=provenance.split(":", 1)[0],
                            match_fingerprint=finding.match_fingerprint,
                            context_fingerprint=finding.context_fingerprint,
                            occurrence_id=finding.occurrence_id,
                        ),
                    ),
                ))
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


def _python_dependency_findings(
    options: ScanOptions,
    files: list[str],
    manifests: dict,
) -> list[Finding]:
    local_roots = {
        path.name for path in options.root.iterdir()
        if path.is_dir() and not _ignored(path.name, options)
    }
    local_roots.update(
        path.parent.name
        for path in options.root.rglob("__init__.py")
        if not _ignored(path.relative_to(options.root).as_posix(), options)
    )
    metadata_aliases = installed_aliases()
    configured_aliases = {
        normalise_name(module): normalise_name(distribution)
        for module, distribution in options.python_import_aliases
    }
    import_re = re.compile(
        r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+([A-Za-z_][\w.]*))",
        re.M,
    )
    findings = []
    for rel in files:
        if Path(rel).suffix.lower() != ".py":
            continue
        applicable = nearest_context(rel, manifests)
        manifest_paths = applicable.paths if applicable else ()
        declared = applicable.distributions if applicable else frozenset()
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
                or normalise_name(module) in declared
                or KNOWN_IMPORT_ALIASES.get(normalise_name(module)) in declared
                or configured_aliases.get(normalise_name(module)) in declared
                or bool(metadata_aliases.get(normalise_name(module), set()) & declared)
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
                explanation=(
                    "A Python import is not recognised as standard-library, repository-local, "
                    + (
                        "or declared in the nearest manifest(s): "
                        + ", ".join(path.as_posix() for path in manifest_paths)
                        if manifest_paths
                        else "or a known ecosystem dependency."
                    )
                ),
                remediation="Verify the package name and declare it in the nearest Python dependency manifest.",
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


def _aggregate_findings(findings: list[Finding]) -> tuple[Finding, ...]:
    """Correlate only stable, unambiguous occurrences and retain all provenance."""
    current_by_occurrence: dict[tuple, list[Finding]] = {}
    history_by_occurrence: dict[tuple, list[Finding]] = {}
    current_by_context: dict[tuple, set[str]] = {}
    history_by_context: dict[tuple, set[str]] = {}

    for item in findings:
        occurrence = (
            item.check_id,
            item.path,
            item.match_fingerprint,
            item.context_fingerprint,
            item.occurrence_id,
            item.evidence,
        )
        context = (
            item.check_id,
            item.path,
            item.match_fingerprint,
            item.context_fingerprint,
            item.evidence,
        )
        if item.source == "working-tree":
            current_by_occurrence.setdefault(occurrence, []).append(item)
            current_by_context.setdefault(context, set()).add(item.occurrence_id)
        else:
            history_by_occurrence.setdefault(occurrence, []).append(item)
            history_by_context.setdefault(context, set()).add(item.occurrence_id)

    aggregated = []
    consumed_history = set()
    for occurrence, current_items in current_by_occurrence.items():
        context = (
            occurrence[0],
            occurrence[1],
            occurrence[2],
            occurrence[3],
            occurrence[5],
        )
        historical_items = history_by_occurrence.get(occurrence, [])
        unambiguous = (
            len(current_by_context.get(context, ())) == 1
            and len(history_by_context.get(context, ())) == 1
        )
        provenance = {}
        for item in historical_items if unambiguous else ():
            sources = item.historical_sources or (
                HistoricalSource(item.source, item.path, item.line),
            )
            for source in sources:
                provenance[
                    (
                        source.source,
                        source.path,
                        source.line,
                        source.occurrence_id,
                    )
                ] = source
        historical_sources = tuple(provenance.values())
        current = {
            (item.line, item.source, item.occurrence_id): item
            for item in current_items
        }
        aggregated.extend(
            replace(item, historical_sources=historical_sources)
            for item in current.values()
        )
        if historical_items and unambiguous:
            consumed_history.add(occurrence)

    for occurrence, historical_items in history_by_occurrence.items():
        if occurrence in consumed_history:
            continue
        provenance = {}
        for item in historical_items:
            sources = item.historical_sources or (
                HistoricalSource(item.source, item.path, item.line),
            )
            for source in sources:
                provenance[
                    (
                        source.source,
                        source.path,
                        source.line,
                        source.occurrence_id,
                    )
                ] = source
        aggregated.append(replace(
            historical_items[0],
            historical_sources=tuple(provenance.values()),
        ))

    return tuple(sorted(
        aggregated,
        key=lambda item: (item.path, item.line, item.check_id, item.source),
    ))


def scan_report(options: ScanOptions) -> ScanReport:
    findings = []
    errors = []
    files = _candidate_files(options)
    for rel in files:
        try:
            text = (options.root / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            if not (options.include_history and options.file_list):
                errors.append(f"working tree: could not read {rel}")
            continue
        findings.extend(_scan_owned_text(options, rel, rel, text, "working-tree"))

    # A deletion has no current file to open. Its base blob is nevertheless useful
    # evidence and, unlike a failed current read, is not a coverage failure when it
    # can be read successfully.
    for status, old_path, _new_path, _exists, base_revision in options.diff_entries:
        if not status.startswith("D") or _ignored(old_path, options) or not _is_text_path(old_path):
            continue
        if not base_revision:
            errors.append(f"diff scope: deleted {old_path!r} has no applicable base revision")
            continue
        text, read_error = _read_history_blob(options, base_revision, old_path)
        if read_error:
            errors.append(read_error)
            continue
        assert text is not None
        source = f"git:{base_revision[:12]}:deleted-base"
        findings.extend(_scan_owned_text(options, old_path, old_path, text, source))

    manifests, manifest_errors = _load_package_manifests(options)
    errors.extend(manifest_errors)
    python_manifests, python_manifest_errors = load_python_manifests(
        options.root,
        lambda rel: _ignored(rel, options),
    )
    errors.extend(python_manifest_errors)
    findings.extend(_javascript_dependency_findings(options, files, manifests))
    findings.extend(_python_dependency_findings(options, files, python_manifests))
    findings.extend(_lockfile_findings(options, files, manifests))
    if options.include_history:
        history_findings, history_errors = _scan_history(options)
        findings.extend(history_findings)
        errors.extend(history_errors)

    ordered = _aggregate_findings(findings)
    safe_errors = tuple(redact_sensitive_text(error) for error in errors)
    return ScanReport(ordered, not safe_errors, safe_errors)


def scan_paths(options: ScanOptions) -> list[Finding]:
    return list(scan_report(options).findings)
