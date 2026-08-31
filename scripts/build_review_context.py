#!/usr/bin/env python3
"""Collect review evidence into a context file outside the reviewed checkout.

This collector deliberately prepares context and scanner candidates without
turning syntactic matches into semantic findings.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import threading
import types
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from diff_file_list import DiffEntry, read_diff_entries  # noqa: E402
from analysis_budget import AnalysisBudget, AnalysisBudgetExceeded, analysis_limits  # noqa: E402
from dissect_checks.engine import ScanOptions, scan_report  # noqa: E402
from dissect_checks import comment_slop  # noqa: E402
from dissect_checks.redaction import redact_sensitive_text  # noqa: E402
from dissect_checks.anti_slop import orchestrator as anti_slop_orchestrator  # noqa: E402
from dissect_checks.anti_slop.model import AnalysisTarget  # noqa: E402
from file_paths import is_generated_path, is_ignored_path, iter_files  # noqa: E402
from language_registry import ambiguous_header_paths, LANGUAGE_SPECS, detect_languages, language_for_path, paths_for_anti_slop, paths_for_comment_analysis  # noqa: E402
from validate_review_context import validate as validate_context  # noqa: E402


INSTRUCTION_NAMES = {"AGENTS.md", "CLAUDE.md", "CONTRIBUTING.md", "README.md"}
INTENT_NAMES = {"TASK.md", "task.md", "PR.md", "pull-request.md", "DESIGN.md", "design.md", "ISSUE.md", "issue.md", "intent.md", "intent.txt", "requirements.md"}
TEXT_SUFFIXES = {suffix for spec in LANGUAGE_SPECS for suffix in spec.suffixes} | {".json", ".toml", ".md", ".txt", ".yaml", ".yml"}
FRAMEWORK_PACKS = {"nextjs": "nextjs", "express": "express", "supabase": "supabase", "postgres": "postgresql", "postgresql": "postgresql", "prisma": "prisma", "stripe": "stripe", "fastapi": "fastapi", "sqlalchemy": "sqlalchemy"}
KIND_RULES = (
    ("migration", ("migration", "migrations", ".sql")),
    ("payment", ("payment", "billing", "stripe", "checkout", "webhook")),
    ("permission", ("auth", "permission", "role", "policy", "rls")),
    ("configuration/deployment", ("config", ".env", "docker", "workflow", "terraform", "deploy")),
    ("test", ("test", "spec", "fixture")),
    ("endpoint/server-action", ("route", "api", "handler", "controller", "action")),
)
COMMENT_ANALYSIS_MAX_BYTES = 5 * 1024 * 1024
DEFAULT_CONTEXT_TIMEOUT_SECONDS = 300
_REFERENCE_TOKEN_RE = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*")


def git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def local_config(root: Path) -> dict[str, Any]:
    try:
        value = json.loads((root / ".ai-review" / "local.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def analyser_enabled(config: dict[str, Any], name: str) -> bool:
    options = config.get("review_options")
    if not isinstance(options, dict) or not isinstance(options.get(name), bool):
        return True
    return options[name]


def read(path: Path, limit: int = 12000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def _comment_analysis_too_large(path: Path, limit: int = COMMENT_ANALYSIS_MAX_BYTES) -> bool:
    try:
        return path.stat().st_size > limit
    except OSError:
        return False


class SourceReadError(Exception):
    """Comment-analysis source could not be read; treat as missing evidence."""


def read_full(path: Path, limit: int | None = None) -> str | bytes:
    """Read a source file, optionally returning a bounded byte snapshot."""
    try:
        if limit is not None:
            with path.open("rb") as source_file:
                return source_file.read(limit + 1)
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError) as error:
        raise SourceReadError(str(error)) from error


def rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _safe_relative_path(value: str | Path) -> str | None:
    """Normalise a repository path without allowing traversal."""
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        return None
    return path.as_posix()


def changed_entries(root: Path, mode: str, file_list: Path | None, base: str) -> list[DiffEntry]:
    if file_list and file_list.exists():
        return read_diff_entries(file_list)
    if mode == "diff":
        from diff_file_list import changed_entries as collect
        try:
            return collect(root, f"{base}...HEAD" if base else "")
        except RuntimeError:
            # A caller may review an unpacked directory. Preserve evidence
            # collection rather than pretending a Git scope was available.
            return [DiffEntry("M", rel(path, root), rel(path, root), True, "working-tree") for path in iter_files(root)]
    return [DiffEntry("M", rel(path, root), rel(path, root), True, "working-tree") for path in iter_files(root)]


def source_paths(root: Path, entries: list[DiffEntry], mode: str) -> list[str]:
    if mode == "full":
        return sorted({rel(path, root) for path in iter_files(root) if path.name not in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}})
    return sorted({
        normalised
        for entry in entries
        if (entry.exists_in_worktree or (entry.source_kind in {"commit", "index"} and not entry.status.startswith("D")))
        and entry.reviewed_path
        and (normalised := _safe_relative_path(entry.reviewed_path)) is not None
        and not is_ignored_path(root, normalised)
    })


def intent(root: Path, intent_file: Path | None = None) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    if intent_file and intent_file.exists():
        value = read(intent_file)
        if value:
            sources.append({"path": str(intent_file), "kind": "benchmark/task intent", "content": value})
    for path in iter_files(root):
        if path.name not in INTENT_NAMES:
            continue
        value = read(path)
        if value:
            sources.append({"path": rel(path, root), "kind": "repository-local intent", "content": value})
    environment = os.environ.get("AI_REVIEW_INTENT", "").strip()
    if environment:
        sources.insert(0, {"kind": "caller-provided intent", "content": environment})
    summary = "\n\n".join(item["content"] for item in sources)
    return {
        "sources": [{key: value for key, value in item.items() if key != "content"} for item in sources],
        "summary": summary[:24000], "constraints": [], "negative_requirements": [],
        "ambiguities": [] if sources else ["Authoritative user/PR/task intent was not available in the review context."],
    }


def architecture(root: Path) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "detect_architecture.py"), "--dir", str(root)],
            text=True, capture_output=True, check=False,
        )
        return json.loads(result.stdout).get("architecture", {}) if result.returncode == 0 else {"collection_error": result.stderr.strip()}
    except Exception as error:  # collection must never make review unavailable
        return {"collection_error": str(error)}


def classify(path: str) -> str:
    lowered = path.lower()
    for kind, tokens in KIND_RULES:
        if any(token in lowered for token in tokens):
            return kind
    return "application behaviour"


def symbols(text: str) -> list[str]:
    patterns = [
        r"\b(?:async\s+)?(?:def|function|class)\s+([A-Za-z_$][\w$]*)",
        r"\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=",
        r"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|VIEW)\s+([\w.]+)",
    ]
    found: list[str] = []
    for pattern in patterns:
        found.extend(re.findall(pattern, text, flags=re.I))
    return list(dict.fromkeys(found))[:80]


def symbols_with_lines(text: str, path: str) -> list[dict[str, Any]]:
    found = []
    for line_number, line in enumerate(text.splitlines(), 1):
        for name in symbols(line):
            found.append({"name": name, "path": path, "line": line_number, "kind": "declaration"})
    return found


def reference_tokens(text: str) -> set[str]:
    """Index identifier references once instead of searching once per symbol."""
    dotted = _REFERENCE_TOKEN_RE.findall(text)
    return set(dotted) | {
        part
        for value in dotted
        for part in value.split(".")
    }


def evidence_lines(text: str, patterns: tuple[str, ...]) -> list[str]:
    return [line.strip() for line in text.splitlines() if any(re.search(pattern, line, re.I) for pattern in patterns)][:20]


def all_text_paths(root: Path) -> list[str]:
    return sorted(rel(path, root) for path in iter_files(root) if path.suffix.lower() in TEXT_SUFFIXES)


def expanded_paths(root: Path, changed: list[str], mode: str) -> tuple[list[str], dict[str, list[dict[str, str]]]]:
    if mode == "full":
        return all_text_paths(root), {}
    candidates = all_text_paths(root)
    changed_symbols = list(dict.fromkeys(
        name for path in changed for name in symbols(read(root / path))
    ))
    selected = set(changed)
    reasons: dict[str, list[dict[str, str]]] = {path: [{"reason": "changed scope"}] for path in changed}
    for path in candidates:
        if path in selected:
            continue
        text = read(root / path)
        tokens = reference_tokens(text)
        referenced = [name for name in changed_symbols if name in tokens]
        companion = any(token in path.lower() for token in ("middleware", "schema", "model", "migration", "config", "test", "spec", "route", "handler"))
        if referenced or companion and any(Path(item).stem in path for item in changed):
            selected.add(path)
            reasons[path] = [{"reason": "direct symbol reference" if referenced else "credible companion path", "symbols": ", ".join(referenced)}]
    return sorted(selected), reasons


_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.M)


def _hunk_ranges(diff_text: str) -> list[tuple[int, int]]:
    ranges = []
    for match in _HUNK_RE.finditer(diff_text):
        start = int(match.group(1))
        count = int(match.group(2) or "1")
        if count:
            ranges.append((start, start + count - 1))
    return ranges


def changed_line_ranges(
    root: Path,
    path: str,
    entries: list[DiffEntry],
    base: str,
    text: str,
) -> list[tuple[int, int]] | None:
    """Return current added-line ranges, or ``None`` when Git evidence is absent."""
    matching = [entry for entry in entries if entry.reviewed_path == path]
    if any(entry.source_kind == "untracked" for entry in matching):
        return [(1, max(1, len(text.splitlines())))]
    commands: list[list[str]] = []
    if base:
        commands.append(["git", "diff", "--unified=0", base, "--", path])
    else:
        commands.extend([
            ["git", "diff", "--unified=0", "--", path],
            ["git", "diff", "--cached", "--unified=0", "--", path],
        ])
    output = []
    git_succeeded = False
    for command in commands:
        try:
            result = subprocess.run(command, cwd=root, text=True, capture_output=True, check=False)
        except OSError:
            continue
        if result.returncode == 0:
            git_succeeded = True
            output.append(result.stdout)
    ranges = _hunk_ranges("\n".join(output))
    # [] is successful evidence for rename-only or other zero-addition edits;
    # pure deleted files normally do not reach comment-slop because source_scope
    # excludes paths absent from the worktree. None means Git evidence failed.
    return ranges if git_succeeded else None


def _comment_density(
    paths: list[str],
    ranges_by_path: dict[str, list[tuple[int, int]] | None],
    text_by_path: dict[str, str | bytes],
) -> float:
    changed_lines = sum(
        end - start + 1
        for ranges in ranges_by_path.values()
        if ranges
        for start, end in ranges
    )
    comment_lines = 0
    for path in paths:
        ranges = ranges_by_path.get(path)
        if not ranges:
            continue
        text = text_by_path.get(path)
        if text is None:
            continue
        comments = comment_slop.extract_comments(path, text)
        comment_lines += sum(
            1 for comment in comments
            if any(comment.line <= end and comment.end_line >= start for start, end in ranges)
        )
    if changed_lines == 0:
        return 0.0
    return comment_lines / changed_lines


def detected_repository(root: Path) -> dict[str, Any]:
    try:
        result = subprocess.run([sys.executable, str(ROOT / "scripts" / "detect_commands.py")], cwd=root, text=True, capture_output=True, check=False)
        return json.loads(result.stdout) if result.returncode == 0 else {}
    except (OSError, ValueError):
        return {}


def loaded_framework_packs(root: Path, architecture_data: dict[str, Any], paths: list[str], requested: tuple[str, ...] = ()) -> list[dict[str, str]]:
    names = set()
    for value in requested:
        normalized = value.lower()
        names.add(FRAMEWORK_PACKS.get(normalized, "nextjs" if normalized == "next" else normalized))
    for value in (architecture_data.get("key_libraries") or {}).get("framework", []):
        for token, name in (*FRAMEWORK_PACKS.items(), ("next", "nextjs")):
            if token in value.lower():
                names.add(name)
    text = "\n".join(read(root / path) for path in paths)
    for token, name in FRAMEWORK_PACKS.items():
        if re.search(rf"\b{re.escape(token)}\b", text, re.I):
            names.add(name)
    if re.search(r"next\.config|from\s+['\"]next/|require\(['\"]next", text, re.I):
        names.add("nextjs")
    packs = []
    for name in sorted(names):
        pack = ROOT / "reference" / "frameworks" / f"{name}.md"
        if pack.exists():
            packs.append({"name": name, "path": str(pack.relative_to(ROOT)), "sha256": hashlib.sha256(pack.read_bytes()).hexdigest(), "loaded": True})
    return packs


def behavioural_units(root: Path, paths: list[str], entries: list[DiffEntry], scope_reasons: dict[str, list[dict[str, str]]]) -> list[dict[str, Any]]:
    text_by_path = {path: read(root / path) for path in paths}
    tokens_by_path = {path: reference_tokens(text) for path, text in text_by_path.items()}
    groups: dict[str, tuple[str, list[str]]] = {}
    for path in paths:
        kind = classify(path)
        key = f"{kind}:{Path(path).parent.as_posix()}"
        groups.setdefault(key, (kind, []))[1].append(path)
    units = []
    for index, (_key, (kind, members)) in enumerate(sorted(groups.items()), 1):
        changed_symbols: list[str] = []
        tests: list[str] = []
        configuration: list[str] = []
        for member in members:
            content = text_by_path[member]
            changed_symbols.extend(f"{member}:{symbol}" for symbol in symbols(content))
            if "/test" in f"/{member}" or "/tests" in f"/{member}" or ".spec." in member or ".test." in member:
                tests.append(member)
            if any(token in member.lower() for token in ("config", ".env", "workflow", "docker", "terraform")):
                configuration.append(member)
        unit_text = "\n".join(text_by_path[member] for member in members)
        declarations = [item for member in members for item in symbols_with_lines(text_by_path[member], member)]
        names = [item["name"] for item in declarations]
        callers = []
        for candidate in paths:
            if candidate in members:
                continue
            referenced = [name for name in names if name in tokens_by_path[candidate]]
            if referenced:
                callers.append({"path": candidate, "symbols": referenced, "reason": "direct symbol reference"})
        units.append({
            "id": f"unit-{index}", "kind": kind, "entry_points": members,
            "changed_symbols": list(dict.fromkeys(changed_symbols)),
            "inputs": evidence_lines(unit_text, (r"request", r"input", r"payload", r"body", r"params", r"argv")),
            "outputs": evidence_lines(unit_text, (r"return", r"response", r"status", r"serialize", r"render")),
            "state_read": evidence_lines(unit_text, (r"\b(?:get|find|load|select|query|fetch)\b", r"\b(?:db|session|cache|store)\b")),
            "state_modified": evidence_lines(unit_text, (r"\b(?:create|insert|update|delete|save|commit|rollback|set)\b", r"\b(?:db|session|cache|store)\b")),
            "external_side_effects": evidence_lines(unit_text, (r"send|publish|enqueue|charge|refund|fetch\(|requests?\.|http",)),
            "error_paths": evidence_lines(
                unit_text,
                (
                    r"except|catch|throw|raise|timeout|retry|fallback|rollback|finally",
                ),
            ),
            "callers": callers, "downstream_consumers": callers, "configuration": configuration,
            "tests": tests, "scope_reasons": {path: scope_reasons.get(path, []) for path in members},
            "before": "Base behaviour must be compared from the supplied diff/base revision.",
            "after": "Evidence extracted from declarations, references, state and side-effect lines; semantic review must confirm it.",
        })
    return units


def candidates(root: Path, entries: list[DiffEntry], paths: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    # The deterministic scanner follows the deliberately expanded semantic
    # scope here. Git history remains bounded by the original diff entries in
    # the review script; companion inspection must not silently collapse back
    # to changed filenames only.
    # Commit and index snapshots may be reviewable even when their logical
    # path is absent from the current worktree. This context pass only reads
    # current files, so do not turn that optional-only case into a coverage
    # error here.
    existing_paths = tuple(path for path in paths if (root / path).is_file())
    options = ScanOptions(root=root, file_list=existing_paths)
    report = scan_report(options)
    output = []
    for index, finding in enumerate(report.findings, 1):
        output.append({
            "id": f"candidate-deterministic-{index}", "source": "deterministic",
            "check_id": finding.check_id, "location": {"path": finding.path, "line": finding.line},
            "severity_suggestion": finding.severity, "confidence": finding.confidence,
            "claim": finding.explanation, "contract": "Requires contextual semantic confirmation before reporting.",
            "trigger_path": [f"{finding.path}:{finding.line}"], "impact": finding.remediation,
            "explanation": finding.explanation, "remediation": finding.remediation,
            "semantic_confirmation_required": True,
            "supporting_evidence": [{"check_id": finding.check_id, "evidence": finding.evidence, "confidence": finding.confidence}],
            "contradicting_evidence": [], "verification_attempts": [], "falsification_attempts": [], "status": "candidate",
        })
    return output, list(report.coverage_errors)


@dataclass
class _SnapshotRecord:
    logical_path: str
    data: bytes
    source_kinds: set[str]
    revisions: set[str]
    changed_ranges: set[tuple[int, int]]
    has_range_evidence: bool = False


@dataclass(frozen=True)
class _OptionalTargets:
    anti_targets: tuple[AnalysisTarget, ...]
    comment_targets: tuple[AnalysisTarget, ...]
    target_contents: dict[str, bytes]
    snapshot_skips: tuple[comment_slop.FileSkip, ...]
    ambiguous_paths: tuple[str, ...]


def _bounded_file_bytes(path: Path, limit: int) -> tuple[bytes | None, str | None]:
    """Read a current source file at most one byte past its configured limit."""
    try:
        if path.stat().st_size > limit:
            with path.open("rb") as source_file:
                return source_file.read(limit + 1), "max_file_bytes"
        spec = language_for_path(path)
        if spec is not None and spec.language_id == "python":
            # Python source may declare an encoding other than UTF-8.  Keep
            # the bytes intact so the AST and comment tokenisers can honour it.
            with path.open("rb") as source_file:
                value = source_file.read(limit + 1)
        else:
            value = read_full(path, limit)
    except (OSError, SourceReadError, UnicodeError) as error:
        return None, f"read_failure: {error}"
    if isinstance(value, str):
        value = value.encode("utf-8")
    if len(value) > limit:
        return value[:limit + 1], "max_file_bytes"
    return value, None


def _bounded_git_blob(root: Path, reference: str, limit: int) -> tuple[bytes | None, str | None]:
    """Read a Git blob without allowing an unbounded subprocess capture."""
    try:
        process = subprocess.Popen(
            ["git", "show", "--format=", "--no-ext-diff", reference],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        return None, f"read_failure: {error}"
    chunks: list[bytes] = []
    total = 0
    oversized = False
    try:
        while process.stdout is not None and total <= limit:
            chunk = process.stdout.read(min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                oversized = True
                break
        if oversized:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
            data = b"".join(chunks)
            return data, "max_file_bytes"
        process.wait(timeout=1)
        stderr = process.stderr.read(4096) if process.stderr is not None else b""
        data = b"".join(chunks)
        if process.returncode != 0:
            detail = (stderr or b"").decode("utf-8", errors="replace").strip()
            return None, f"snapshot_unavailable: {detail or reference}"
        return data, None
    except subprocess.TimeoutExpired as error:
        try:
            process.kill()
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            pass
        return None, f"read_failure: {error}"
    except (OSError, ValueError) as error:
        try:
            process.kill()
            process.communicate()
        except OSError:
            pass
        return None, f"read_failure: {error}"
    finally:
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass


def _snapshot_source_bytes(root: Path, entry: DiffEntry, limit: int) -> tuple[bytes | None, str | None]:
    logical = _safe_relative_path(entry.reviewed_path)
    if logical is None:
        return None, "snapshot_path_invalid: reviewed path is not repository-relative"
    if entry.source_kind in {"working-tree", "untracked"}:
        return _bounded_file_bytes(root / logical, limit)
    blob_path = _safe_relative_path(entry.blob_path or logical)
    if blob_path is None:
        return None, "snapshot_path_invalid: blob path is not repository-relative"
    if entry.source_kind == "index":
        stage = entry.index_stage if entry.index_stage is not None else 0
        return _bounded_git_blob(root, f":{stage}:{blob_path}", limit)
    revision = entry.commit_revision or "HEAD"
    return _bounded_git_blob(root, f"{revision}:{blob_path}", limit)


def _ranges_for_snapshot(root: Path, entry: DiffEntry, base: str, text: str | bytes) -> list[tuple[int, int]] | None:
    """Return changed lines for the exact source layer represented by entry."""
    if entry.source_kind == "untracked":
        return [(1, max(1, len(text.splitlines())))]
    path = entry.reviewed_path
    if entry.source_kind == "index":
        command = ["git", "diff", "--cached", "--unified=0", "--", path]
    elif entry.source_kind == "working-tree":
        command = ["git", "diff", "--unified=0", "--", path]
    else:
        revision = entry.commit_revision or "HEAD"
        left = base or "HEAD^"
        command = ["git", "diff", "--unified=0", left, revision, "--", path]
    try:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True, check=False)
    except OSError:
        return None
    return _hunk_ranges(result.stdout) if result.returncode == 0 else None


def _committed_review_paths(root: Path, base: str) -> set[str]:
    """Return reviewed paths from the explicit commit range, if available."""
    if not base:
        return set()
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "-z", "-M", f"{base}...HEAD"],
            cwd=root,
            capture_output=True,
            check=False,
        )
    except OSError:
        return set()
    if result.returncode != 0:
        return set()
    return {
        value.decode("utf-8", errors="surrogateescape")
        for value in result.stdout.split(b"\0")
        if value
    }


def _safe_snapshot_destination(root: Path, index: int, logical_path: str) -> Path | None:
    path = Path(logical_path)
    if path.is_absolute() or logical_path in {"", "."} or logical_path.startswith("../") or "/../" in f"/{logical_path}":
        return None
    destination = root / str(index) / path
    try:
        destination.parent.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return None
    return destination


@contextmanager
def _diff_optional_targets(
    root: Path,
    source_scope: list[str],
    entries: list[DiffEntry],
    base: str,
    config: dict[str, Any],
) -> Iterator[_OptionalTargets]:
    """Materialise exact diff layers for optional analysers.

    Worktree sources stay at their logical repository paths. Git blobs are
    copied into a private temporary tree and every target retains its logical
    path and source layer for diagnostic mapping.
    """
    limits = analysis_limits(config)
    need_anti = analyser_enabled(config, "anti_slop")
    need_comments = analyser_enabled(config, "comment_slop")
    source_limit = max(
        int(limits["anti_slop_max_file_bytes"]) if need_anti else 0,
        int(limits["comment_slop_max_file_bytes"]) if need_comments else 0,
        1,
    )
    snapshot_limit = max(
        int(limits["anti_slop_max_total_bytes"]) if need_anti else 0,
        int(limits["comment_slop_max_total_bytes"]) if need_comments else 0,
        1,
    )
    snapshot_file_limit = max(
        int(limits["anti_slop_max_files"]) if need_anti else 0,
        int(limits["comment_slop_max_files"]) if need_comments else 0,
        1,
    )
    scope = tuple(
        dict.fromkeys(
            normalised for path in source_scope
            if (normalised := _safe_relative_path(path)) is not None
        )
    )
    scope_set = set(scope)
    relevant = tuple(
        path for path in scope
        if not is_generated_path(root, root / path, config)
        and (Path(path).suffix.lower() == ".h"
             or (language_for_path(path) is not None and (
                 (need_anti and language_for_path(path).anti_slop_backend is not None)
                 or (need_comments and language_for_path(path).comment_style is not None)
             )))
    )
    anti_groups = paths_for_anti_slop(relevant) if need_anti else {}
    anti_language_by_path: dict[str, str] = {}
    for backend_id, values in anti_groups.items():
        if backend_id == "ast-grep-c":
            language_id = "c"
        elif backend_id == "ast-grep-cpp":
            language_id = "cpp"
        else:
            language_id = next((spec.language_id for spec in LANGUAGE_SPECS if spec.anti_slop_backend == backend_id), "")
        for value in values:
            anti_language_by_path[value] = language_id

    fallback_entries = [
        DiffEntry("M", path, path, True, "working-tree")
        for path in relevant
        if path in scope_set
    ]
    source_entries = entries or fallback_entries
    committed_paths = _committed_review_paths(root, base)
    current_cache: dict[str, tuple[bytes | None, str | None]] = {}
    records: dict[tuple[str, str], _SnapshotRecord] = {}
    skips: list[comment_slop.FileSkip] = []
    record_bytes = 0
    for entry in source_entries:
        logical = Path(entry.reviewed_path).as_posix()
        if logical not in scope_set or logical not in relevant:
            continue
        if (
            not entry.exists_in_worktree
            and (entry.source_kind not in {"commit", "index"} or entry.status.startswith("D"))
        ):
            continue
        # In a local staged or unstaged review, ``commit`` entries are the
        # unchanged HEAD side used as a diff baseline.  They are not review
        # targets.  A non-empty base identifies an explicit commit-range
        # review, where only paths in that range are reviewed commit content.
        if entry.source_kind == "commit" and (
            not base or logical not in committed_paths
        ):
            continue
        blob_path = _safe_relative_path(entry.blob_path or logical)
        if blob_path is None:
            skips.append(comment_slop.FileSkip(logical, "snapshot_path_invalid", "source snapshot path is invalid"))
            continue
        if blob_path != logical and not entry.status.startswith(("R", "C")):
            skips.append(comment_slop.FileSkip(logical, "snapshot_path_invalid", "source snapshot path is inconsistent"))
            continue
        if entry.source_kind in {"working-tree", "untracked"} and logical in current_cache:
            data, error = current_cache[logical]
        else:
            data, error = _snapshot_source_bytes(root, entry, source_limit)
            if entry.source_kind in {"working-tree", "untracked"}:
                current_cache[logical] = (data, error)
        if data is None:
            reason_code = "read_failure" if (error or "").startswith("read_failure:") else "snapshot_unavailable"
            skips.append(comment_slop.FileSkip(logical, reason_code, error or "source snapshot unavailable"))
            continue
        if b"\0" in data[:4096]:
            skips.append(comment_slop.FileSkip(logical, "binary_source", "NUL byte in bounded source prefix"))
            continue
        if not entries and entry.source_kind == "working-tree":
            ranges = changed_line_ranges(root, logical, entries, base, "")
        else:
            ranges = _ranges_for_snapshot(root, entry, base, data)
        digest = hashlib.sha256(data).hexdigest()
        key = (logical, digest)
        record = records.get(key)
        if record is None:
            if record_bytes + len(data) > snapshot_limit:
                skips.append(comment_slop.FileSkip(logical, "max_total_bytes", "source snapshot byte budget exhausted"))
                continue
            record_bytes += len(data)
            record = _SnapshotRecord(logical, data, set(), set(), set())
            records[key] = record
        record.source_kinds.add(entry.source_kind)
        if entry.commit_revision:
            record.revisions.add(entry.commit_revision)
        if ranges is not None:
            record.has_range_evidence = True
            record.changed_ranges.update(ranges)

    with tempfile.TemporaryDirectory(prefix="dissect-analysis-") as directory:
        snapshot_root = Path(directory)
        target_contents: dict[str, bytes] = {}
        anti_targets: list[AnalysisTarget] = []
        comment_targets: list[AnalysisTarget] = []
        materialised_bytes = 0
        materialised_files = 0
        for index, record in enumerate(sorted(records.values(), key=lambda item: (item.logical_path, hashlib.sha256(item.data).hexdigest()))):
            if materialised_files >= snapshot_file_limit:
                skips.append(comment_slop.FileSkip(record.logical_path, "max_files", "source snapshot file budget exhausted"))
                continue
            if materialised_bytes + len(record.data) > snapshot_limit:
                skips.append(comment_slop.FileSkip(record.logical_path, "max_total_bytes", "snapshot tree byte budget exhausted"))
                continue
            materialised_bytes += len(record.data)
            materialised_files += 1
            current_path = root / record.logical_path
            use_worktree = "working-tree" in record.source_kinds or "untracked" in record.source_kinds
            physical = current_path if use_worktree and current_path.is_file() else _safe_snapshot_destination(snapshot_root, index, record.logical_path)
            if physical is None:
                skips.append(comment_slop.FileSkip(record.logical_path, "snapshot_path_invalid", "source snapshot path is invalid"))
                continue
            if physical != current_path:
                try:
                    physical.parent.mkdir(parents=True, exist_ok=True)
                    physical.write_bytes(record.data)
                except OSError as error:
                    skips.append(comment_slop.FileSkip(record.logical_path, "snapshot_write_failure", str(error)))
                    continue
            target_contents[physical.as_posix()] = record.data
            source_layer = "+".join(sorted(record.source_kinds))
            revision = "+".join(sorted(record.revisions)) or "WORKTREE"
            changed_ranges = tuple(sorted(record.changed_ranges)) if record.has_range_evidence else None
            if record.logical_path in anti_language_by_path:
                anti_targets.append(AnalysisTarget(
                    record.logical_path, physical, anti_language_by_path[record.logical_path],
                    source_layer, revision, hashlib.sha256(record.data).hexdigest(), changed_ranges,
                ))
            spec = language_for_path(record.logical_path)
            if spec is not None and spec.comment_style is not None:
                comment_targets.append(AnalysisTarget(
                    record.logical_path, physical, spec.language_id,
                    source_layer, revision, hashlib.sha256(record.data).hexdigest(), changed_ranges,
                ))
        yield _OptionalTargets(
            tuple(sorted(anti_targets, key=lambda item: (item.logical_path, item.source_kind, item.content_sha256))),
            tuple(sorted(comment_targets, key=lambda item: (item.logical_path, item.source_kind, item.content_sha256))),
            target_contents,
            tuple(skips),
            tuple(sorted(ambiguous_header_paths(relevant))),
        )


def _optional_analyser_evidence_impl(
    root: Path,
    mode: str,
    source_scope: list[str],
    entries: list[DiffEntry],
    base: str,
    config: dict[str, Any],
    snapshot: _OptionalTargets | None = None,
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any], list[dict[str, Any]]]:
    """Run optional analysers with separate bounded scopes and budgets."""
    values: list[dict[str, Any]] = []
    limitations: list[str] = []
    coverage: dict[str, Any] = {}
    commands: list[dict[str, Any]] = []

    if not analyser_enabled(config, "anti_slop"):
        limitation = "anti-slop disabled by review_options"
        limitations.append(limitation)
        coverage["anti-slop"] = {"state": "Not verified", "reason": limitation}
        commands.append({"name": "anti-slop", "executed": False, "complete": False, "reason": limitation})
    else:
        try:
            if snapshot is not None:
                anti = anti_slop_orchestrator.analyse(
                    root,
                    targets=snapshot.anti_targets,
                    config=config,
                    ambiguous_paths=snapshot.ambiguous_paths,
                )
            else:
                anti_paths = [path for path in source_scope if not is_generated_path(root, root / path, config)]
                anti = anti_slop_orchestrator.analyse(root, anti_paths, config=config)
        except Exception as error:  # optional tooling must remain non-fatal
            anti = {
                "tool": "anti-slop", "status": "failed", "state": "Not verified",
                "reason": str(error), "files_scanned": 0, "candidates": [], "backends": {},
            }
        values.extend(anti.get("candidates", []))
        backend_records: dict[str, Any] = {}
        for backend_id, record in sorted((anti.get("backends") or {}).items()):
            status = str(record.get("status", "failed"))
            state = "Checked" if status == "complete" else "Not applicable" if status == "not_applicable" else "Not verified"
            backend_records[backend_id] = {
                "state": state,
                "level": record.get("level", "structural"),
                "languages": list(record.get("languages", [])),
                "applicable_files": max(0, int(record.get("applicable_files", 0))),
                "checked_files": max(0, int(record.get("checked_files", 0))),
                "skipped_files": max(0, int(record.get("skipped_files", 0))),
                "reason": record.get("reason") or record.get("reason_code") or "Completed.",
            }
        if anti.get("ambiguous_header_paths"):
            for backend_id in ("ast-grep-c", "ast-grep-cpp"):
                record = backend_records.get(backend_id)
                if record is not None and record["state"] == "Not applicable":
                    record.update({
                        "state": "Not verified", "applicable_files": len(anti["ambiguous_header_paths"]),
                        "skipped_files": len(anti["ambiguous_header_paths"]),
                        "reason": "ambiguous_header_language",
                    })
        coverage["anti-slop"] = {
            "state": anti.get("state", "Not verified"),
            "reason": anti.get("reason", "Anti-slop analysis did not complete."),
            "backends": backend_records,
        }
        anti_snapshot_skips = [
            item for item in (snapshot.snapshot_skips if snapshot is not None else ())
            if (language_for_path(item.path) is not None and language_for_path(item.path).anti_slop_backend is not None)
            or Path(item.path).suffix.lower() == ".h"
        ]
        if anti_snapshot_skips and anti.get("state") in {"Checked", "Not applicable"}:
            reason = "source_snapshot_incomplete"
            limitation = "Not verified — anti-slop source snapshot was incomplete"
            limitations.append(limitation)
            coverage["anti-slop"] = {
                "state": "Not verified", "reason": limitation, "backends": backend_records,
            }
        final_anti_state = coverage["anti-slop"]["state"]
        commands.append({
            "name": "anti-slop", "executed": True,
            "complete": final_anti_state in {"Checked", "Not applicable"},
            "status": anti.get("status"), "state": final_anti_state,
        })
        if anti.get("state") == "Not verified":
            reasons = [
                str(record.get("reason_code"))
                for record in (anti.get("backends") or {}).values()
                if record.get("reason_code")
            ]
            reason = reasons[0] if reasons else "analysis_incomplete"
            limitation = f"Not verified — anti-slop pass unavailable ({reason})"
            limitations.append(limitation)
            coverage["anti-slop"] = {"state": "Not verified", "reason": limitation}
            coverage["anti-slop"]["backends"] = backend_records

    if not analyser_enabled(config, "comment_slop"):
        limitation = "comment-slop disabled by review_options"
        limitations.append(limitation)
        coverage["comment-slop"] = {"state": "Not verified", "reason": limitation}
        commands.append({"name": "comment-slop", "executed": False, "complete": False, "reason": limitation})
        return values, limitations, coverage, commands

    limits = analysis_limits(config)
    budget = AnalysisBudget(
        float(limits["comment_slop_timeout_seconds"]),
        int(limits["comment_slop_max_files"]),
        int(limits["comment_slop_max_total_bytes"]),
        int(limits["comment_slop_max_candidates"]),
    )
    if snapshot is not None:
        comment_targets = snapshot.comment_targets
        comment_scope = sorted({target.logical_path for target in comment_targets})
        ranges_by_path = {
            target.logical_path: list(target.changed_ranges) if target.changed_ranges is not None else None
            for target in comment_targets
        }
        text_by_path: dict[str, str | bytes] = {}
        for target in comment_targets:
            content = snapshot.target_contents.get(target.physical_path.as_posix())
            if content is not None:
                text_by_path.setdefault(target.logical_path, content)
        pre_skipped: list[comment_slop.FileSkip] = []
        density = _comment_density(comment_scope, ranges_by_path, text_by_path)
    else:
        supported_comment_paths = set(paths_for_comment_analysis(source_scope))
        comment_scope = [
            path for path in source_scope
            if path in supported_comment_paths and not is_generated_path(root, root / path, config)
        ]
        ranges_by_path = {}
        text_by_path: dict[str, str | bytes] = {}
        pre_skipped: list[comment_slop.FileSkip] = []
        density = 0.0
    try:
        if snapshot is not None:
            result = comment_slop.scan_comment_targets(
                root,
                (),
                mode=mode,
                diff_density=density,
                budget=budget,
                max_file_bytes=int(limits["comment_slop_max_file_bytes"]),
                per_file_timeout=float(limits["comment_slop_per_file_timeout_seconds"]),
                targets=snapshot.comment_targets,
                target_contents=snapshot.target_contents,
            )
        else:
            result = comment_slop.scan_comment_targets(
                root,
                comment_scope,
                mode=mode,
                changed_ranges=ranges_by_path if mode == "diff" else None,
                diff_density=density,
                budget=budget,
                max_file_bytes=int(limits["comment_slop_max_file_bytes"]),
                per_file_timeout=float(limits["comment_slop_per_file_timeout_seconds"]),
                text_by_path=text_by_path,
                pre_skipped=pre_skipped,
                source_reader=lambda path, limit: _bounded_file_bytes(root / path, limit),
            )
        values.extend(result.candidates)
    except Exception as error:  # optional tooling must remain non-fatal
        limitation = redact_sensitive_text(f"Not verified — comment-slop pass unavailable (runner_error: {error})")
        limitations.append(limitation)
        coverage["comment-slop"] = {"state": "Not verified", "reason": limitation}
        commands.append({"name": "comment-slop", "executed": True, "complete": False, "reason": redact_sensitive_text(str(error))})
        return values, limitations, coverage, commands

    skipped_by_reason: dict[str, list[str]] = {}
    all_skips = [*result.skipped_files]
    if snapshot is not None:
        all_skips.extend(
            item for item in snapshot.snapshot_skips
            if (language_for_path(item.path) is not None and language_for_path(item.path).comment_style is not None)
        )
    for skipped in all_skips:
        skipped_by_reason.setdefault(skipped.reason_code, []).append(skipped.path)
    for reason_code, skipped_paths in sorted(skipped_by_reason.items()):
        for path in skipped_paths[:3]:
            if reason_code == "max_file_bytes":
                limitations.append(redact_sensitive_text(f"comment-slop: file too large for comment analysis {path}"))
            elif reason_code == "read_failure":
                limitations.append(redact_sensitive_text(f"comment-slop: source unreadable for comment analysis {path}"))
            else:
                limitations.append(redact_sensitive_text(f"comment-slop: {reason_code} for {path}"))
        if len(skipped_paths) > 3:
            limitations.append(f"comment-slop: {reason_code} affected {len(skipped_paths)} file(s)")
    skipped_paths = {item.path for item in all_skips}
    if snapshot is not None:
        unevidenced = sorted({
            target.logical_path
            for target in snapshot.comment_targets
            if target.changed_ranges is None and target.logical_path not in skipped_paths
        })
    else:
        unevidenced = sorted(
            path for path, ranges in ranges_by_path.items()
            if ranges is None and path not in skipped_paths
        )
    for path in unevidenced[:3]:
        limitations.append(redact_sensitive_text(f"comment-slop: no diff-line evidence for {path}"))
    incomplete = bool(all_skips or unevidenced)
    if result.status == "not_applicable" and not incomplete:
        coverage["comment-slop"] = {"state": "Not applicable", "reason": "No applicable comment-bearing source files."}
    elif incomplete:
        coverage["comment-slop"] = {"state": "Not verified", "reason": f"Comment analysis skipped {len(all_skips) + len(unevidenced)} applicable file(s)."}
    else:
        coverage["comment-slop"] = {"state": "Checked", "reason": "Comment candidates are scoped to the selected source and remain subject to semantic verification."}
    commands.append({"name": "comment-slop", "executed": True, "complete": not incomplete and result.status == "complete", "status": result.status})
    return values, limitations, coverage, commands


def optional_analyser_evidence(
    root: Path,
    mode: str,
    source_scope: list[str],
    entries: list[DiffEntry],
    base: str,
    config: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any], list[dict[str, Any]]]:
    if mode != "diff" or not any(analyser_enabled(config, name) for name in ("anti_slop", "comment_slop")):
        return _optional_analyser_evidence_impl(root, mode, source_scope, entries, base, config)
    with _diff_optional_targets(root, source_scope, entries, base, config) as snapshot:
        return _optional_analyser_evidence_impl(root, mode, source_scope, entries, base, config, snapshot)


def build(root: Path, mode: str, base: str, file_list: Path | None, intent_file: Path | None = None, requested_frameworks: tuple[str, ...] = ()) -> dict[str, Any]:
    config = local_config(root)
    analysis_limits(config)
    entries = changed_entries(root, mode, file_list, base)
    primary_paths = source_paths(root, entries, mode)
    semantic_context_paths, scope_reasons = expanded_paths(root, primary_paths, mode)
    candidate_values, coverage_errors = candidates(root, entries, semantic_context_paths)
    optional_values, analyser_limitations, analyser_coverage, analyser_commands = optional_analyser_evidence(
        root, mode, primary_paths, entries, base, config,
    )
    candidate_values.extend(optional_values)
    instructions = [rel(path, root) for path in iter_files(root) if path.name in INSTRUCTION_NAMES]
    manifests = [path for path in semantic_context_paths if Path(path).name in {"package.json", "pyproject.toml", "go.mod", "Cargo.toml", "composer.json", "pom.xml", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}]
    languages = list(detect_languages(semantic_context_paths))
    arch = architecture(root)
    detected = detected_repository(root)
    touchpoint_tokens = {
        "auth": ("auth", "session", "role", "permission", "middleware"),
        "payments": ("stripe", "payment", "billing", "checkout", "refund", "webhook"),
        "persistence": ("db", "database", "model", "schema", "migration", "prisma", "sql", "supabase"),
        "routes": ("route", "api", "handler", "controller", "endpoint", "action"),
        "infrastructure": ("docker", "terraform", "workflow", "deploy", "bucket", "storage"),
    }
    touchpoints = {}
    for category, tokens in touchpoint_tokens.items():
        touchpoints[category] = [{"path": path, "reason": "path or source token matched"} for path in semantic_context_paths if any(token in path.lower() or token in read(root / path).lower() for token in tokens)][:80]
    families = []
    catalog = root / "reference" / "check-families.md"
    if not catalog.exists():
        catalog = ROOT / "reference" / "check-families.md"
    for match in re.finditer(r"(?m)^##\s+([A-Z]+-[A-Z]+)", read(catalog, 50000)):
        families.append(match.group(1))
    coverage = {family: {"state": "Not verified", "reason": "Deterministic candidates require semantic confirmation."} for family in families}
    coverage.update(analyser_coverage)
    commands = [
        {"name": "git evidence collection", "executed": True, "complete": True},
        {"name": "architecture detection", "executed": True, "complete": bool(arch)},
        {"name": "deterministic scanner", "executed": True, "complete": not coverage_errors},
        *analyser_commands,
    ]
    return {
        "schema_version": "1.1", "mode": mode,
        "scope": {"root": str(root), "base": base, "branch": git(root, "branch", "--show-current"), "head": git(root, "rev-parse", "HEAD"), "merge_base": git(root, "merge-base", base, "HEAD") if base else "", "files": semantic_context_paths, "entries": [asdict(entry) for entry in entries]},
        "intent": intent(root, intent_file),
        "repository": {"instructions": instructions, "languages": languages, "frameworks": list(dict.fromkeys([*(arch.get("key_libraries") or {}).get("framework", []), *requested_frameworks])), "framework_packs": loaded_framework_packs(root, arch, semantic_context_paths, requested_frameworks), "package_managers": detected.get("package_managers", []), "test_commands": detected.get("commands", {}), "architecture": arch, "manifests": manifests, "touchpoints": touchpoints},
        "behavioural_units": behavioural_units(root, semantic_context_paths, entries, scope_reasons), "candidates": candidate_values,
        "commands": commands,
        "coverage": coverage,
        "limitations": coverage_errors + analyser_limitations + ["Semantic confirmation, falsification, and runtime evidence are performed by the reviewer."],
    }


def _worker_arguments(args: argparse.Namespace, output: Path) -> list[str]:
    values = [
        sys.executable, str(Path(__file__).resolve()),
        "--root", str(args.root), "--mode", args.mode, "--output", str(output),
        "--timeout", str(args.timeout), "--worker", "--worker-output", str(output),
    ]
    if args.base:
        values.extend(["--base", args.base])
    if args.file_list:
        values.extend(["--file-list", str(args.file_list)])
    if args.intent_file:
        values.extend(["--intent-file", str(args.intent_file)])
    for framework in args.framework:
        values.extend(["--framework", framework])
    return values


def _timeout_label(value: float | int) -> str:
    return str(int(value)) if float(value).is_integer() else str(value)


def _terminate_process_group(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        try:
            process.terminate()
        except OSError:
            return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                process.kill()
            except OSError:
                pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    else:
        # The leader can exit after SIGTERM while a child keeps the process
        # group's pipes open.  Kill the group once more so no analyser child
        # survives a timed-out context build.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass


def _run_supervisor(args: argparse.Namespace) -> int:
    args.output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix="dissect-context-", suffix=".json")
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        process = subprocess.Popen(
            _worker_arguments(args, temporary),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            _terminate_process_group(process)
            try:
                process.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            print(f"review context construction exceeded {_timeout_label(args.timeout)} seconds", file=sys.stderr)
            return 124
        if process.returncode != 0:
            detail = (stderr or stdout or "context worker failed").strip().splitlines()
            print(detail[-1] if detail else "context worker failed", file=sys.stderr)
            return process.returncode if process.returncode > 0 else 1
        try:
            payload = json.loads(temporary.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            print(f"context worker produced invalid output: {error}", file=sys.stderr)
            return 1
        if not isinstance(payload, dict) or payload.get("schema_version") != "1.1":
            print("context worker produced an invalid review context", file=sys.stderr)
            return 1
        validation_errors = validate_context(payload)
        if validation_errors:
            print(f"context worker produced invalid review context: {validation_errors[0]}", file=sys.stderr)
            return 1
        os.replace(temporary, args.output)
        print(str(args.output))
        return 0
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--mode", choices=("diff", "full"), required=True)
    parser.add_argument("--base", default="")
    parser.add_argument("--file-list", type=Path)
    parser.add_argument("--intent-file", type=Path)
    parser.add_argument("--framework", action="append", default=[])
    parser.add_argument("--timeout", type=float, default=None)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--worker-output", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.timeout is None:
        try:
            args.timeout = float(analysis_limits(local_config(args.root.resolve()))["context_timeout_seconds"])
        except ValueError as error:
            parser.error(str(error))
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.worker:
        try:
            payload = build(args.root.resolve(), args.mode, args.base, args.file_list, args.intent_file, tuple(args.framework))
            validation_errors = validate_context(payload)
            if validation_errors:
                raise ValueError(f"invalid review context: {validation_errors[0]}")
            output = args.worker_output or args.output
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            return 0
        except Exception as error:
            print(f"context worker failed: {redact_sensitive_text(str(error))}", file=sys.stderr)
            return 1
    # Unit callers may replace build with a blocking fixture.  Keep that
    # narrow in-process test seam without putting a catchable alarm in the
    # production worker.
    if not isinstance(build, types.FunctionType):
        result: list[BaseException] = []

        def invoke() -> None:
            try:
                build(args.root.resolve(), args.mode, args.base, args.file_list, args.intent_file, tuple(args.framework))
            except BaseException as error:  # test seam only
                result.append(error)

        thread = threading.Thread(target=invoke, daemon=True)
        thread.start()
        thread.join(args.timeout)
        if thread.is_alive():
            raise TimeoutError(f"review context construction exceeded {_timeout_label(args.timeout)} seconds")
        if result:
            raise result[0]
        return 0
    return _run_supervisor(args)


if __name__ == "__main__":
    raise SystemExit(main())
