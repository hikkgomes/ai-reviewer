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
import time
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from diff_file_list import DiffEntry, read_diff_entries  # noqa: E402
from analysis_budget import AnalysisBudget, AnalysisBudgetExceeded, analysis_limits  # noqa: E402
from dissect_checks.engine import ScanOptions, scan_report  # noqa: E402
from dissect_checks import comment_slop  # noqa: E402
from dissect_checks.redaction import redact_payload, redact_sensitive_text  # noqa: E402
from dissect_checks.anti_slop import orchestrator as anti_slop_orchestrator  # noqa: E402
from dissect_checks.anti_slop.model import AnalysisTarget  # noqa: E402
from dissect_checks.test_integrity import orchestrator as test_integrity_orchestrator  # noqa: E402
from dissect_checks.complexity import orchestrator as complexity_orchestrator  # noqa: E402
from review_ledger import blank_candidate, validate_candidate  # noqa: E402
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
    except FileNotFoundError:
        return {}
    except OSError as error:
        raise ValueError(f"could not read review configuration: {error}") from error
    except ValueError as error:
        raise ValueError(f"review configuration is not valid JSON: {error}") from error
    if not isinstance(value, dict):
        raise ValueError("review configuration must be a JSON object")
    return value


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
    summary = redact_sensitive_text("\n\n".join(item["content"] for item in sources))
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
    return [
        redact_sensitive_text(line.strip())[:240]
        for line in text.splitlines()
        if any(re.search(pattern, line, re.I) for pattern in patterns)
    ][:20]


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
        # Diff mode analyses the reviewed commit, not any unrelated mutable
        # worktree edits which happen to exist while the context is built.
        left = base.split("...", 1)[0] if "..." in base else base
        right = base.split("...", 1)[1] if "..." in base else "HEAD"
        commands.append(["git", "diff", "--unified=0", left, right, "--", path])
    else:
        matching = [entry for entry in entries if entry.reviewed_path == path]
        has_unstaged = any(entry.source_kind == "working-tree" for entry in matching)
        if has_unstaged:
            try:
                unstaged = subprocess.run(
                    ["git", "diff", "--quiet", "--", path],
                    cwd=root,
                    capture_output=True,
                    check=False,
                )
                has_unstaged = unstaged.returncode == 1
            except OSError:
                has_unstaged = False
        if has_unstaged:
            commands.append(["git", "diff", "--unified=0", "--", path])
        elif any(entry.source_kind == "index" for entry in matching):
            commands.append(["git", "diff", "--cached", "--unified=0", "--", path])
        elif any(entry.source_kind == "commit" for entry in matching):
            commands.append(["git", "diff", "--unified=0", "HEAD^", "HEAD", "--", path])
        else:
            commands.append(["git", "diff", "--unified=0", "--", path])
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


def _complexity_candidates(payload: dict[str, Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in payload.get("candidates", []):
        if not isinstance(item, dict):
            continue
        function = item.get("function") if isinstance(item.get("function"), dict) else {}
        path = str(function.get("logical_path", ""))
        line = int(function.get("start_line", 1) or 1)
        reason_code = str(item.get("reason_code", "complexity_candidate"))
        head = function.get("cyclomatic", item.get("head_complexity", "unknown"))
        candidate = blank_candidate(
            str(item.get("candidate_id", "")),
            source="COR-COMPLEXITY",
            claim=f"{function.get('qualified_name', '<unknown>')} has complexity {head} ({reason_code}).",
            contract="Review branch cohesion, failure paths, state transitions, and testability before treating complexity as a defect.",
        )
        candidate["trigger_path"] = [f"{path}:{line}"]
        candidate["supporting_evidence"] = [{
            "kind": "complexity",
            "file": path,
            "line": line,
            "source_layer": function.get("source_layer", "working-tree"),
            "content_sha256": function.get("content_sha256", ""),
            "qualified_name": function.get("qualified_name", ""),
            "function_id": function.get("function_id", ""),
            "reason_code": reason_code,
            "threshold": item.get("threshold"),
            "threshold_source": item.get("threshold_source"),
            "base_complexity": item.get("base_complexity"),
            "head_complexity": item.get("head_complexity"),
            "delta": item.get("delta"),
            "changed_lines": item.get("changed_lines", []),
            "is_test": function.get("is_test", False),
            "analysis_level": "structural",
            "does_not_prove": ["automatic defect", "poor design", "missing test", "unsafe behaviour"],
        }]
        errors = validate_candidate(candidate)
        if errors:
            raise ValueError("invalid complexity candidate: " + "; ".join(errors))
        output.append(candidate)
    return output


def _head_source_layer(mode: str, entries: list[DiffEntry]) -> str:
    if mode != "diff":
        return "working-tree"
    layers = {entry.source_kind for entry in entries if not entry.status.startswith("D")}
    for layer in ("working-tree", "untracked", "index", "commit"):
        if layer in layers:
            return layer
    return "working-tree"


@dataclass
class _SnapshotRecord:
    logical_path: str
    data: bytes
    source_kind: str
    revision: str
    changed_ranges: set[tuple[int, int]]
    has_range_evidence: bool = False


@dataclass(frozen=True)
class _OptionalTargets:
    anti_targets: tuple[AnalysisTarget, ...]
    comment_targets: tuple[AnalysisTarget, ...]
    target_contents: dict[str, bytes]
    snapshot_skips: tuple[comment_slop.FileSkip, ...]
    ambiguous_paths: tuple[str, ...]


def _materialise_optional_records(
    root: Path,
    records: Iterable[_SnapshotRecord],
    source_entries: list[DiffEntry],
    anti_language_by_path: dict[str, str],
    manifest_cache: dict[tuple[str, str, str, str], tuple[str, str, str, bool] | None],
    snapshot_root: Path,
    *,
    source_limit: int,
    snapshot_limit: int,
    snapshot_file_limit: int,
    snapshot_budget: AnalysisBudget,
    skips: list[comment_slop.FileSkip],
) -> tuple[list[AnalysisTarget], list[AnalysisTarget], dict[str, bytes]]:
    target_contents: dict[str, bytes] = {}
    anti_targets: list[AnalysisTarget] = []
    comment_targets: list[AnalysisTarget] = []
    materialised_bytes = 0
    materialised_files = 0
    ordered_records = sorted(records, key=lambda item: (item.logical_path, hashlib.sha256(item.data).hexdigest()))
    for index, record in enumerate(ordered_records):
        target_id = comment_slop._target_id(
            record.logical_path,
            record.source_kind,
            hashlib.sha256(record.data).hexdigest(),
        )
        if materialised_files >= snapshot_file_limit:
            skips.append(comment_slop.FileSkip(
                record.logical_path,
                "max_files",
                "source snapshot file budget exhausted",
                target_id,
                len(ordered_records) - index,
            ))
            break
        if materialised_bytes + len(record.data) > snapshot_limit:
            skips.append(comment_slop.FileSkip(
                record.logical_path,
                "max_total_bytes",
                "snapshot tree byte budget exhausted",
                target_id,
                len(ordered_records) - index,
            ))
            break
        materialised_bytes += len(record.data)
        materialised_files += 1
        # Every backend reads an immutable materialised path. Keeping a
        # working-tree target at its live path would let a concurrent edit
        # diverge from the bytes whose hash is attached to its evidence.
        physical = _safe_snapshot_destination(snapshot_root, index, record.logical_path)
        if physical is None:
            skips.append(comment_slop.FileSkip(record.logical_path, "snapshot_path_invalid", "source snapshot path is invalid", target_id))
            continue
        try:
            physical.parent.mkdir(parents=True, exist_ok=True)
            physical.write_bytes(record.data)
        except OSError as error:
            skips.append(comment_slop.FileSkip(record.logical_path, "snapshot_write_failure", str(error), target_id))
            continue
        target_contents[physical.as_posix()] = record.data
        source_layer = record.source_kind
        revision = record.revision or "WORKTREE"
        manifest_entry = next(
            (
                item for item in source_entries
                if item.reviewed_path == record.logical_path
                and item.source_kind == record.source_kind
                and (item.commit_revision or "") == record.revision
            ),
            None,
        )
        # An unchanged package manifest is normally absent from a diff entry.
        # Resolve it from the target's own layer anyway, otherwise an index or
        # commit target silently falls back to generic rules merely because the
        # manifest itself was not changed.
        manifest_entry = manifest_entry or DiffEntry(
            "M",
            record.logical_path,
            record.logical_path,
            True,
            record.source_kind,
            record.revision,
        )
        try:
            manifest_path, manifest_source_layer, manifest_sha256, has_effect = _snapshot_manifest_metadata(
                root, manifest_entry, record.logical_path, source_limit, manifest_cache,
                budget=snapshot_budget,
            )
        except AnalysisBudgetExceeded as error:
            skips.append(comment_slop.FileSkip(
                record.logical_path,
                error.reason_code,
                error.detail,
                target_id,
            ))
            manifest_path, manifest_source_layer, manifest_sha256, has_effect = "", "", "", False
        digest = hashlib.sha256(record.data).hexdigest()
        changed_ranges = tuple(sorted(record.changed_ranges)) if record.has_range_evidence else None
        if record.logical_path in anti_language_by_path:
            config_variant = "unavailable" if manifest_path and not manifest_sha256 else "effect" if has_effect else "generic"
            anti_targets.append(AnalysisTarget(
                record.logical_path, physical, anti_language_by_path[record.logical_path],
                source_layer, revision, digest, changed_ranges, record.data,
                config_variant, manifest_path,
                manifest_source_layer, manifest_sha256, True,
            ))
        spec = language_for_path(record.logical_path)
        if spec is not None and spec.comment_style is not None:
            comment_targets.append(AnalysisTarget(
                record.logical_path, physical, spec.language_id,
                source_layer, revision, digest, changed_ranges, record.data,
                "", "", "", "", True,
            ))
    return anti_targets, comment_targets, target_contents


def _collect_optional_records(
    root: Path,
    source_entries: list[DiffEntry],
    scope_set: set[str],
    relevant: tuple[str, ...],
    committed_paths: set[str],
    base: str,
    *,
    source_limit: int,
    snapshot_limit: int,
    snapshot_budget: AnalysisBudget,
    use_fallback_ranges: bool,
) -> tuple[dict[tuple[str, str, str], _SnapshotRecord], dict[tuple[str, str, str, str], tuple[str, str, str, bool] | None], list[comment_slop.FileSkip]]:
    records: dict[tuple[str, str, str], _SnapshotRecord] = {}
    manifest_cache: dict[tuple[str, str, str, str], tuple[str, str, str, bool] | None] = {}
    skips: list[comment_slop.FileSkip] = []
    current_cache: dict[tuple[str, str], tuple[bytes | None, str | None]] = {}
    source_cache: dict[tuple[str, str, str, str, int | None], tuple[bytes | None, str | None, int | None]] = {}
    record_bytes = 0
    def remaining_sources(start: int) -> int:
        count = 0
        for later in source_entries[start + 1:]:
            later_path = Path(later.reviewed_path).as_posix()
            if later_path not in scope_set or later_path not in relevant:
                continue
            if not later.exists_in_worktree and (later.source_kind not in {"commit", "index"} or later.status.startswith("D")):
                continue
            if later.source_kind == "commit" and (not base or later_path not in committed_paths):
                continue
            later_blob = _safe_relative_path(later.blob_path or later_path)
            if later_blob is None:
                continue
            later_key = (later_path, later.source_kind, later.commit_revision or "", later_blob, later.index_stage)
            if later_key not in source_cache:
                count += 1
        return count

    for entry_index, entry in enumerate(source_entries):
        logical = Path(entry.reviewed_path).as_posix()
        source_target_id = comment_slop._target_id(logical, entry.source_kind, "")
        try:
            snapshot_budget.check_deadline()
        except AnalysisBudgetExceeded as error:
            skips.append(comment_slop.FileSkip(
                logical, error.reason_code, error.detail, source_target_id,
                1 + remaining_sources(entry_index),
            ))
            break
        if logical not in scope_set or logical not in relevant:
            continue
        if not entry.exists_in_worktree and (entry.source_kind not in {"commit", "index"} or entry.status.startswith("D")):
            continue
        if entry.source_kind == "commit" and (not base or logical not in committed_paths):
            continue
        blob_path = _safe_relative_path(entry.blob_path or logical)
        if blob_path is None:
            skips.append(comment_slop.FileSkip(logical, "snapshot_path_invalid", "source snapshot path is invalid", source_target_id))
            continue
        if blob_path != logical and not entry.status.startswith(("R", "C")):
            skips.append(comment_slop.FileSkip(logical, "snapshot_path_invalid", "source snapshot path is inconsistent", source_target_id))
            continue
        source_key = (logical, entry.source_kind, entry.commit_revision or "", blob_path, entry.index_stage)
        unique_source = source_key not in source_cache
        if not unique_source:
            cached_source = source_cache[source_key]
            if cached_source[0] is None and cached_source[1] is not None:
                continue
        if unique_source:
            try:
                snapshot_budget.claim_file()
            except AnalysisBudgetExceeded as error:
                skips.append(comment_slop.FileSkip(logical, error.reason_code, error.detail, source_target_id))
                if error.reason_code in {"total_timeout", "max_files", "max_total_bytes"}:
                    if skips:
                        skips[-1] = comment_slop.FileSkip(
                            skips[-1].path,
                            skips[-1].reason_code,
                            skips[-1].detail,
                            skips[-1].target_id,
                            1 + remaining_sources(entry_index),
                        )
                    break
                continue
        cached_source = source_cache.get(source_key)
        try:
            source_size = cached_source[2] if cached_source is not None else _snapshot_source_size(root, entry)
            snapshot_budget.check_deadline()
        except AnalysisBudgetExceeded as error:
            skips.append(comment_slop.FileSkip(
                logical, error.reason_code, error.detail, source_target_id,
                1 + remaining_sources(entry_index),
            ))
            break
        if unique_source and source_size is None:
            # A bounded read cannot be budgeted safely without a trusted size.
            # Keep the snapshot incomplete instead of reading first and
            # claiming bytes afterwards.
            skips.append(comment_slop.FileSkip(logical, "snapshot_size_unavailable", "source size could not be established before reading", source_target_id))
            continue
        if unique_source and source_size is not None:
            if source_size > source_limit:
                source_cache[source_key] = (None, "max_file_bytes: source snapshot file exceeds its limit", source_size)
                skips.append(comment_slop.FileSkip(logical, "max_file_bytes", "source snapshot file exceeds its limit", source_target_id))
                continue
            try:
                snapshot_budget.claim_bytes(source_size)
            except AnalysisBudgetExceeded as error:
                skips.append(comment_slop.FileSkip(logical, error.reason_code, error.detail, source_target_id))
                if error.reason_code in {"total_timeout", "max_files", "max_total_bytes"}:
                    if skips:
                        skips[-1] = comment_slop.FileSkip(
                            skips[-1].path,
                            skips[-1].reason_code,
                            skips[-1].detail,
                            skips[-1].target_id,
                            1 + remaining_sources(entry_index),
                        )
                    break
                continue
        if cached_source is not None:
            data, error, _cached_size = cached_source
        elif entry.source_kind in {"working-tree", "untracked"} and (entry.source_kind, logical) in current_cache:
            data, error = current_cache[(entry.source_kind, logical)]
        else:
            try:
                snapshot_budget.check_deadline()
                data, error = _snapshot_source_bytes(root, entry, source_limit)
                snapshot_budget.check_deadline()
            except AnalysisBudgetExceeded as budget_error:
                skips.append(comment_slop.FileSkip(
                    logical, budget_error.reason_code, budget_error.detail,
                    source_target_id, 1 + remaining_sources(entry_index),
                ))
                break
            if entry.source_kind in {"working-tree", "untracked"}:
                current_cache[(entry.source_kind, logical)] = (data, error)
        source_cache[source_key] = (data, error, source_size)
        if data is None or error is not None:
            reason_code = "read_failure" if (error or "").startswith("read_failure:") else "snapshot_unavailable"
            if error and "max_file_bytes" in error:
                reason_code = "max_file_bytes"
            skips.append(comment_slop.FileSkip(logical, reason_code, error or "source snapshot unavailable", source_target_id))
            continue
        if source_size is not None and len(data) != source_size:
            skips.append(comment_slop.FileSkip(logical, "read_failure", "source changed during bounded snapshot read", source_target_id))
            continue
        if b"\0" in data[:4096]:
            skips.append(comment_slop.FileSkip(logical, "binary_source", "NUL byte in bounded source prefix", source_target_id))
            continue
        ranges = changed_line_ranges(root, logical, [], base, "") if use_fallback_ranges and entry.source_kind == "working-tree" else _ranges_for_snapshot(root, entry, base, data)
        digest = hashlib.sha256(data).hexdigest()
        key = (logical, entry.source_kind, digest)
        record = records.get(key)
        if record is None:
            if record_bytes + len(data) > snapshot_limit:
                skips.append(comment_slop.FileSkip(logical, "max_total_bytes", "source snapshot byte budget exhausted", source_target_id))
                continue
            record_bytes += len(data)
            record = _SnapshotRecord(logical, data, entry.source_kind, entry.commit_revision or "", set())
            records[key] = record
        if ranges is not None:
            record.has_range_evidence = True
            record.changed_ranges.update(ranges)
    return records, manifest_cache, skips


def _bounded_file_bytes(path: Path, limit: int) -> tuple[bytes | None, str | None]:
    """Read a current source file at most one byte past its configured limit."""
    try:
        initial_size = path.stat().st_size
        if initial_size > limit:
            with path.open("rb") as source_file:
                value = source_file.read(limit + 1)
            if path.stat().st_size != initial_size:
                return value, "read_failure: source changed during bounded read"
            return value, "max_file_bytes"
        spec = language_for_path(path)
        if spec is not None and spec.language_id == "python":
            # Python source may declare an encoding other than UTF-8.  Keep
            # the bytes intact so the AST and comment tokenisers can honour it.
            with path.open("rb") as source_file:
                value = source_file.read(limit)
        else:
            try:
                with path.open("rb") as source_file:
                    value = source_file.read(limit)
            except OSError as error:
                raise SourceReadError(str(error)) from error
    except (OSError, SourceReadError, UnicodeError) as error:
        return None, f"read_failure: {error}"
    if isinstance(value, str):
        value = value.encode("utf-8")
    try:
        if path.stat().st_size != initial_size:
            return value, "read_failure: source changed during bounded read"
    except OSError as error:
        return None, f"read_failure: {error}"
    if len(value) > limit:
        return value[:limit + 1], "max_file_bytes"
    return value, None


def _safe_bounded_file_bytes(root: Path, logical_path: str, limit: int) -> tuple[bytes | None, str | None]:
    path = root / logical_path
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return None, "snapshot_path_invalid: source path escapes review root"
    return _bounded_file_bytes(path, limit)


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
        return _safe_bounded_file_bytes(root, logical, limit)
    blob_path = _safe_relative_path(entry.blob_path or logical)
    if blob_path is None:
        return None, "snapshot_path_invalid: blob path is not repository-relative"
    if entry.source_kind == "index":
        stage = entry.index_stage if entry.index_stage is not None else 0
        return _bounded_git_blob(root, f":{stage}:{blob_path}", limit)
    revision = entry.commit_revision or "HEAD"
    return _bounded_git_blob(root, f"{revision}:{blob_path}", limit)


def _snapshot_source_size(root: Path, entry: DiffEntry) -> int | None:
    """Return source size from metadata without reading the source bytes."""
    logical = _safe_relative_path(entry.reviewed_path)
    if logical is None:
        return None
    if entry.source_kind in {"working-tree", "untracked"}:
        try:
            physical = (root / logical).resolve()
            physical.relative_to(root.resolve())
            return physical.stat().st_size
        except (OSError, ValueError):
            return None
    blob_path = _safe_relative_path(entry.blob_path or logical)
    if blob_path is None:
        return None
    if entry.source_kind == "index":
        stage = entry.index_stage if entry.index_stage is not None else 0
        reference = f":{stage}:{blob_path}"
    else:
        reference = f"{entry.commit_revision or 'HEAD'}:{blob_path}"
    try:
        result = subprocess.run(
            ["git", "cat-file", "-s", reference],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout.strip())
    except ValueError:
        return None


def _git_blob_size(root: Path, reference: str) -> int | None:
    """Read Git blob size metadata without loading the blob."""
    if not reference or reference.startswith("-"):
        return None
    try:
        result = subprocess.run(
            ["git", "cat-file", "-s", reference],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout.strip())
    except ValueError:
        return None


def _effect_manifest(data: bytes) -> bool:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError):
        return False
    if not isinstance(value, dict):
        return False
    return any(
        isinstance(value.get(section), dict)
        and any(
            str(name).lower() == "effect" or str(name).lower().startswith("@effect/")
            for name in value[section]
        )
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
    )


def _snapshot_manifest_metadata(
    root: Path,
    entry: DiffEntry,
    logical_path: str,
    limit: int,
    cache: dict[tuple[str, str, str, str], tuple[str, str, str, bool] | None],
    *,
    budget: AnalysisBudget | None = None,
) -> tuple[str, str, str, bool]:
    """Resolve the nearest package manifest from the target's source layer."""
    directory = Path(logical_path).parent
    revision = entry.commit_revision or "HEAD"
    layer_key = (entry.source_kind, str(entry.index_stage or 0), revision)
    while True:
        manifest_path = (directory / "package.json").as_posix()
        cache_key = (*layer_key, manifest_path)
        if cache_key not in cache:
            if entry.source_kind in {"working-tree", "untracked"}:
                try:
                    physical = (root / manifest_path).resolve()
                    physical.relative_to(root.resolve())
                    size = physical.stat().st_size
                except (OSError, ValueError):
                    size = None
                if size is None:
                    data, error = None, "snapshot_unavailable"
                elif size > limit:
                    cache[cache_key] = (manifest_path, entry.source_kind, "", False)
                    return cache[cache_key]
                else:
                    if budget is not None:
                        budget.claim_source(size)
                    data, error = _safe_bounded_file_bytes(root, manifest_path, limit)
            elif entry.source_kind == "index":
                stage = entry.index_stage if entry.index_stage is not None else 0
                reference = f":{stage}:{manifest_path}"
                size = _git_blob_size(root, reference)
                if size is None:
                    data, error = None, "snapshot_unavailable"
                elif size > limit:
                    cache[cache_key] = (manifest_path, entry.source_kind, "", False)
                    return cache[cache_key]
                else:
                    if budget is not None:
                        budget.claim_source(size)
                    data, error = _bounded_git_blob(root, reference, limit)
            else:
                reference = f"{revision}:{manifest_path}"
                size = _git_blob_size(root, reference)
                if size is None:
                    data, error = None, "snapshot_unavailable"
                elif size > limit:
                    cache[cache_key] = (manifest_path, entry.source_kind, "", False)
                    return cache[cache_key]
                else:
                    if budget is not None:
                        budget.claim_source(size)
                    data, error = _bounded_git_blob(root, reference, limit)
            if data is None or error is not None:
                # A known manifest which could not be read is still the
                # nearest applicable configuration. Do not silently inherit a
                # parent package's variant.
                if size is not None:
                    cache[cache_key] = (manifest_path, entry.source_kind, "", False)
                    return cache[cache_key]
                cache[cache_key] = None
            else:
                digest = hashlib.sha256(data).hexdigest()
                try:
                    parsed = json.loads(data.decode("utf-8"))
                except (UnicodeError, ValueError):
                    # The nearest manifest remains the applicable manifest.
                    # Its invalid contents must not be replaced by a parent
                    # package's configuration.
                    cache[cache_key] = (
                        manifest_path,
                        entry.source_kind,
                        digest,
                        False,
                    )
                    return cache[cache_key]
                if not isinstance(parsed, dict):
                    cache[cache_key] = (
                        manifest_path,
                        entry.source_kind,
                        digest,
                        False,
                    )
                    return cache[cache_key]
                cache[cache_key] = (
                    manifest_path,
                    entry.source_kind,
                    digest,
                    _effect_manifest(data),
                )
        metadata = cache[cache_key]
        if metadata is not None:
            return metadata
        if directory == Path("."):
            break
        directory = directory.parent
    return "", "", "", False


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
        left = (base.split("...", 1)[0] if "..." in base else base) or "HEAD^"
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
        revision_range = base if "..." in base else f"{base}...HEAD"
        result = subprocess.run(
            ["git", "diff", "--name-only", "-z", "-M", revision_range],
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
    snapshot_budget = AnalysisBudget(
        float(max(
            int(limits["anti_slop_timeout_seconds"]) if need_anti else 0,
            int(limits["comment_slop_timeout_seconds"]) if need_comments else 0,
            1,
        )),
        snapshot_file_limit,
        snapshot_limit,
        None,
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
    records, manifest_cache, skips = _collect_optional_records(
        root,
        source_entries,
        scope_set,
        relevant,
        committed_paths,
        base,
        source_limit=source_limit,
        snapshot_limit=snapshot_limit,
        snapshot_budget=snapshot_budget,
        use_fallback_ranges=not entries,
    )

    with tempfile.TemporaryDirectory(prefix="dissect-analysis-") as directory:
        anti_targets, comment_targets, target_contents = _materialise_optional_records(
            root,
            records.values(),
            source_entries,
            anti_language_by_path,
            manifest_cache,
            Path(directory),
            source_limit=source_limit,
            snapshot_limit=snapshot_limit,
            snapshot_file_limit=snapshot_file_limit,
            snapshot_budget=snapshot_budget,
            skips=skips,
        )
        yield _OptionalTargets(
            tuple(sorted(anti_targets, key=lambda item: (item.logical_path, item.source_kind, item.content_sha256))),
            tuple(sorted(comment_targets, key=lambda item: (item.logical_path, item.source_kind, item.content_sha256))),
            target_contents,
            tuple(skips),
            tuple(sorted(ambiguous_header_paths(relevant))),
        )


def _anti_backend_records(anti: dict[str, Any]) -> dict[str, Any]:
    records: dict[str, Any] = {}
    for backend_id, record in sorted((anti.get("backends") or {}).items()):
        status = str(record.get("status", "failed"))
        state = "Checked" if status == "complete" else "Not applicable" if status == "not_applicable" else "Not verified"
        records[backend_id] = {
            "state": state,
            "level": record.get("level", "structural"),
            "languages": list(record.get("languages", [])),
            "applicable_files": max(0, int(record.get("applicable_files", 0))),
            "checked_files": max(0, int(record.get("checked_files", 0))),
            "skipped_files": max(0, int(record.get("skipped_files", 0))),
            "reason": record.get("reason") or record.get("reason_code") or "Completed.",
        }
    return records


def _anti_slop_evidence(
    root: Path,
    source_scope: list[str],
    config: dict[str, Any],
    snapshot: _OptionalTargets | None,
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any], list[dict[str, Any]]]:
    if not analyser_enabled(config, "anti_slop"):
        reason = "anti-slop disabled by review_options"
        applicable = bool(
            (
                snapshot is not None
                and (
                    bool(snapshot.anti_targets)
                    or any(
                        Path(item.path).suffix.lower() == ".h"
                        or (
                            language_for_path(item.path) is not None
                            and language_for_path(item.path).anti_slop_backend is not None
                        )
                        for item in snapshot.snapshot_skips
                    )
                )
            )
            or paths_for_anti_slop(source_scope)
        )
        state = "Not verified" if applicable else "Not applicable"
        limitations = [reason] if applicable else []
        return [], limitations, {"anti-slop": {"state": state, "reason": reason if applicable else "No applicable structural anti-slop files."}}, [{"name": "anti-slop", "executed": False, "complete": False, "reason": reason}]
    try:
        anti = (
            anti_slop_orchestrator.analyse(root, targets=snapshot.anti_targets, config=config, ambiguous_paths=snapshot.ambiguous_paths)
            if snapshot is not None else
            anti_slop_orchestrator.analyse(
                root,
                [path for path in source_scope if not is_generated_path(root, root / path, config)],
                config=config,
            )
        )
    except Exception as error:
        anti = {
            "tool": "anti-slop", "status": "failed", "state": "Not verified",
            "reason": str(error), "files_scanned": 0, "candidates": [], "backends": {},
        }
    values = list(anti.get("candidates", []))
    backend_records = _anti_backend_records(anti)
    ambiguous = anti.get("ambiguous_header_paths") or []
    if snapshot is not None:
        for item in snapshot.snapshot_skips:
            spec = language_for_path(item.path)
            backend_id = spec.anti_slop_backend if spec is not None else None
            if backend_id is None and Path(item.path).suffix.lower() == ".h":
                backend_id = "ast-grep-c"
            record = backend_records.get(backend_id) if backend_id else None
            if record is None:
                continue
            record["applicable_files"] += item.count
            record["skipped_files"] += item.count
            record["state"] = "Not verified"
            record["reason"] = item.reason_code
    for backend_id in ("ast-grep-c", "ast-grep-cpp"):
        record = backend_records.get(backend_id)
        if record is not None and record["state"] == "Not applicable" and ambiguous:
            record.update({
                "state": "Not verified",
                "applicable_files": len(ambiguous),
                "skipped_files": len(ambiguous),
                "reason": "ambiguous_header_language",
            })
    state = anti.get("state", "Not verified")
    reason = anti.get("reason", "Anti-slop analysis did not complete.")
    limitations: list[str] = []
    if snapshot is not None:
        snapshot_skips = [
            item for item in snapshot.snapshot_skips
            if (language_for_path(item.path) is not None and language_for_path(item.path).anti_slop_backend is not None)
            or Path(item.path).suffix.lower() == ".h"
        ]
        if snapshot_skips and state in {"Checked", "Not applicable"}:
            reason = "Not verified — anti-slop source snapshot was incomplete"
            state = "Not verified"
            limitations.append(reason)
    if state == "Not verified":
        reasons = [
            str(record.get("reason_code"))
            for record in (anti.get("backends") or {}).values()
            if isinstance(record, dict) and record.get("reason_code")
        ]
        reason = reason if reason.startswith("Not verified") else f"Not verified — anti-slop pass unavailable ({reasons[0] if reasons else 'analysis_incomplete'})"
        limitations.append(reason)
    coverage = {"anti-slop": {"state": state, "reason": reason, "backends": backend_records}}
    commands = [{"name": "anti-slop", "executed": True, "complete": state in {"Checked", "Not applicable"}, "status": anti.get("status"), "state": state}]
    return values, limitations, coverage, commands


def _comment_scope(
    root: Path,
    source_scope: list[str],
    config: dict[str, Any],
    snapshot: _OptionalTargets | None,
) -> tuple[tuple[AnalysisTarget, ...] | None, list[str]]:
    if snapshot is not None:
        return snapshot.comment_targets, sorted({target.logical_path for target in snapshot.comment_targets})
    paths = [
        path for path in source_scope
        if path in set(paths_for_comment_analysis(source_scope))
        and not is_generated_path(root, root / path, config)
    ]
    return None, paths


def _comment_skip_limitations(skips: Iterable[comment_slop.FileSkip]) -> tuple[list[str], set[str], set[str]]:
    grouped: dict[str, list[comment_slop.FileSkip]] = {}
    skipped_paths: set[str] = set()
    skipped_target_ids: set[str] = set()
    for item in skips:
        grouped.setdefault(item.reason_code, []).append(item)
        if item.target_id:
            skipped_target_ids.add(item.target_id)
        else:
            skipped_paths.add(item.path)
    limitations: list[str] = []
    for reason_code, paths in sorted(grouped.items()):
        for item in paths[:3]:
            path = item.path
            if reason_code == "max_file_bytes":
                limitations.append(redact_sensitive_text(f"comment-slop: file too large for comment analysis {path}"))
            elif reason_code == "read_failure":
                limitations.append(redact_sensitive_text(f"comment-slop: source unreadable for comment analysis {path}"))
            else:
                limitations.append(redact_sensitive_text(f"comment-slop: {reason_code} for {path}"))
        total = sum(item.count for item in paths)
        if total > 3:
            limitations.append(f"comment-slop: {reason_code} affected {total} file(s)")
    return limitations, skipped_paths, skipped_target_ids


def _comment_slop_evidence(
    root: Path,
    mode: str,
    source_scope: list[str],
    config: dict[str, Any],
    snapshot: _OptionalTargets | None,
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any], list[dict[str, Any]]]:
    if not analyser_enabled(config, "comment_slop"):
        reason = "comment-slop disabled by review_options"
        applicable = bool(
            (
                snapshot is not None
                and (
                    bool(snapshot.comment_targets)
                    or any(
                        language_for_path(item.path) is not None
                        and language_for_path(item.path).comment_style is not None
                        for item in snapshot.snapshot_skips
                    )
                )
            )
            or paths_for_comment_analysis(source_scope)
        )
        state = "Not verified" if applicable else "Not applicable"
        limitations = [reason] if applicable else []
        return [], limitations, {"comment-slop": {"state": state, "reason": reason if applicable else "No applicable comment-bearing source files."}}, [{"name": "comment-slop", "executed": False, "complete": False, "reason": reason}]
    limits = analysis_limits(config)
    target_values, comment_scope = _comment_scope(root, source_scope, config, snapshot)
    budget = AnalysisBudget(
        float(limits["comment_slop_timeout_seconds"]),
        int(limits["comment_slop_max_files"]),
        int(limits["comment_slop_max_total_bytes"]),
        int(limits["comment_slop_max_candidates"]),
    )
    try:
        result = (
            comment_slop.scan_comment_targets(
                root, (), mode=mode, diff_density=0.0, budget=budget,
                max_file_bytes=int(limits["comment_slop_max_file_bytes"]),
                per_file_timeout=float(limits["comment_slop_per_file_timeout_seconds"]),
                targets=target_values, target_contents=snapshot.target_contents,
            )
            if snapshot is not None else
            comment_slop.scan_comment_targets(
                root, comment_scope, mode=mode, changed_ranges=None,
                diff_density=0.0, budget=budget,
                max_file_bytes=int(limits["comment_slop_max_file_bytes"]),
                per_file_timeout=float(limits["comment_slop_per_file_timeout_seconds"]),
                source_reader=lambda path, limit: _safe_bounded_file_bytes(root, path, limit),
            )
        )
    except Exception as error:
        reason = redact_sensitive_text(f"Not verified — comment-slop pass unavailable (runner_error: {error})")
        return [], [reason], {"comment-slop": {"state": "Not verified", "reason": reason}}, [{"name": "comment-slop", "executed": True, "complete": False, "reason": reason}]
    skips = list(result.skipped_files)
    snapshot_comment_skips: list[comment_slop.FileSkip] = []
    if snapshot is not None:
        snapshot_comment_skips = [
            item for item in snapshot.snapshot_skips
            if language_for_path(item.path) is not None
            and language_for_path(item.path).comment_style is not None
        ]
        skips.extend(snapshot_comment_skips)
    limitations, skipped_paths, skipped_target_ids = _comment_skip_limitations(skips)
    unevidenced = sorted({
        target.target_id for target in snapshot.comment_targets
        if target.changed_ranges is None
        and target.target_id not in skipped_target_ids
        and target.logical_path not in skipped_paths
    }) if snapshot is not None else []
    limitations.extend(redact_sensitive_text(f"comment-slop: no diff-line evidence for {target_id}") for target_id in unevidenced[:3])
    skipped_count = int(result.skipped_file_count or 0) + sum(item.count for item in snapshot_comment_skips)
    incomplete = bool(skipped_count or unevidenced or result.status != "complete")
    record = {
        "applicable_files": result.applicable_files + sum(item.count for item in snapshot_comment_skips),
        "checked_files": result.checked_files,
        "skipped_files": skipped_count,
        "bytes_scanned": result.bytes_scanned,
        "changed_line_count": result.changed_line_count,
        "changed_comment_count": result.changed_comment_count,
        "comment_density": result.comment_density,
    }
    state = "Not applicable" if result.status == "not_applicable" and not incomplete else "Not verified" if incomplete else "Checked"
    reason = "No applicable comment-bearing source files." if state == "Not applicable" else f"Comment analysis skipped {skipped_count + len(unevidenced)} applicable file(s)." if incomplete else "Comment candidates are scoped to the selected source and remain subject to semantic verification."
    coverage = {"comment-slop": {"state": state, "reason": reason, **record}}
    commands = [{"name": "comment-slop", "executed": True, "complete": state in {"Checked", "Not applicable"}, "status": result.status}]
    return list(result.candidates), limitations, coverage, commands


def _optional_analyser_evidence_impl(
    root: Path,
    mode: str,
    source_scope: list[str],
    entries: list[DiffEntry],
    base: str,
    config: dict[str, Any],
    snapshot: _OptionalTargets | None = None,
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any], list[dict[str, Any]]]:
    """Compose independent anti-slop and comment-slop evidence passes."""
    anti_values, anti_limits, anti_coverage, anti_commands = _anti_slop_evidence(
        root, source_scope, config, snapshot,
    )
    comment_values, comment_limits, comment_coverage, comment_commands = _comment_slop_evidence(
        root, mode, source_scope, config, snapshot,
    )
    return (
        [*anti_values, *comment_values],
        [*anti_limits, *comment_limits],
        {**anti_coverage, **comment_coverage},
        [*anti_commands, *comment_commands],
    )


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
    root = root.resolve()
    config = local_config(root)
    analysis_limits(config)
    review_intent = intent(root, intent_file)
    entries = changed_entries(root, mode, file_list, base)
    primary_paths = source_paths(root, entries, mode)
    semantic_context_paths, scope_reasons = expanded_paths(root, primary_paths, mode)
    candidate_values, coverage_errors = candidates(root, entries, semantic_context_paths)
    optional_values, analyser_limitations, analyser_coverage, analyser_commands = optional_analyser_evidence(
        root, mode, primary_paths, entries, base, config,
    )
    candidate_values.extend(optional_values)
    if mode == "diff" and "..." in base:
        source_base_revision, requested_head = base.split("...", 1)
        head_revision = requested_head or "HEAD"
    else:
        head_revision = git(root, "rev-parse", "HEAD") or "HEAD"
        source_base_revision = base if mode == "diff" else ""
    test_integrity_paths = sorted({
        *semantic_context_paths,
        *(
            entry.reviewed_path
            for entry in entries
            if _safe_relative_path(entry.reviewed_path) is not None
        ),
        *(
            path for path in all_text_paths(root)
            if Path(path).name in {
                "package.json", "pyproject.toml", "go.mod", "Cargo.toml",
                "pom.xml", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
            }
            or path.startswith(".github/workflows/")
            or path == ".gitlab-ci.yml"
        ),
    })
    base_contents, head_contents = test_integrity_orchestrator.source_maps(
        root,
        entries,
        test_integrity_paths,
        base_revision=source_base_revision,
        head_revision=head_revision,
        assume_base_equals_head=mode == "full",
    )
    changed_paths = tuple(sorted({entry.reviewed_path for entry in entries if entry.reviewed_path}))
    changed_ranges = {
        path: changed_line_ranges(root, path, entries, base, head_contents.get(path, ""))
        for path in changed_paths
        if not Path(path).is_absolute()
    } if mode == "diff" else None
    test_integrity = test_integrity_orchestrator.analyse(
        root,
        test_integrity_paths,
        entries=entries,
        config=config,
        mode=mode,
        base_contents=base_contents,
        head_contents=head_contents,
        base_revision=source_base_revision,
        head_revision=head_revision,
        changed_ranges=changed_ranges,
        intent_text=review_intent.get("summary", ""),
    )
    complexity = complexity_orchestrator.analyse(
        root,
        semantic_context_paths,
        mode=mode,
        config=config,
        base_contents=base_contents,
        head_contents=head_contents,
        changed_ranges=changed_ranges,
        source_kind=_head_source_layer(mode, entries),
        source_kind_by_path=(
            test_integrity_orchestrator._head_source_kinds(
                entries, semantic_context_paths, source_base_revision, root=root,
            )
            if mode == "diff" else None
        ),
    ) if analyser_enabled(config, "complexity") else complexity_orchestrator.ComplexityResult("partial", (), (), {"disabled": True}, 0, 0, 0, "disabled")
    test_evidence = test_integrity.as_dict()
    complexity_evidence = complexity.as_dict()
    candidate_values.extend(test_evidence.get("static_candidates", []))
    candidate_values.extend(test_evidence.get("dynamic_candidates", []))
    candidate_values.extend(_complexity_candidates(complexity_evidence))
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
    test_backends = {
        "static-test-analysis": {
            "state": "Checked" if test_integrity.static.status == "complete" else "Not applicable" if test_integrity.static.status == "not_applicable" else "Not verified",
            "level": "structural",
            "languages": ["python", "javascript", "typescript", "go", "rust", "c", "cpp", "java", "csharp"],
            "applicable_files": test_integrity.static.applicable_files,
            "checked_files": test_integrity.static.checked_files,
            "skipped_files": test_integrity.static.skipped_files,
            "reason": test_integrity.static.reason_code or "Static test-integrity analysis completed.",
            "status": test_integrity.static.status,
        },
    }
    if test_integrity.matrix is not None:
        test_backends["dynamic-test-matrix"] = {
            "state": "Checked" if test_integrity.matrix.status == "complete" else "Not applicable" if test_integrity.matrix.status == "not_applicable" else "Not verified",
            "level": "structural", "languages": [], "applicable_files": len(test_integrity.matrix.scenarios),
            "checked_files": sum(1 for item in test_integrity.matrix.scenarios if item.result.completed),
            "skipped_files": sum(1 for item in test_integrity.matrix.scenarios if not item.result.completed),
            "reason": test_integrity.matrix.reason_code or "Dynamic test matrix completed.",
            "status": test_integrity.matrix.status,
        }
    if test_integrity.mutations is not None:
        test_backends["targeted-mutation"] = {
            "state": "Checked" if test_integrity.mutations.status == "complete" else "Not applicable" if test_integrity.mutations.status == "not_applicable" else "Not verified",
            "level": "structural", "languages": [], "applicable_files": len(test_integrity.mutations.results),
            "checked_files": sum(1 for item in test_integrity.mutations.results if item.build_valid is not None),
            "skipped_files": sum(1 for item in test_integrity.mutations.results if item.build_valid is None),
            "reason": test_integrity.mutations.reason_code or "Targeted mutation analysis completed.",
            "status": test_integrity.mutations.status,
        }
    coverage["test-integrity"] = {
        "state": test_evidence["state"],
        "reason": test_evidence.get("reason_code") or "Static test-integrity analysis completed; dynamic evidence remains approval-bound.",
        "backends": test_backends,
    }
    complexity_state = "Checked" if complexity.status == "complete" else "Not applicable" if complexity.status == "not_applicable" else "Not verified"
    coverage["complexity"] = {
        "state": complexity_state,
        "reason": complexity.reason_code or "Complexity is a review signal and requires contextual confirmation.",
        "backends": {
            complexity.backend_id: {
                "state": complexity_state, "level": "structural", "languages": sorted(complexity.policy.get("languages", {}).keys()),
                "applicable_files": complexity.applicable_files, "checked_files": complexity.checked_files,
                "skipped_files": complexity.skipped_files, "reason": complexity.reason_code or "Completed.", "status": complexity.status,
            },
        },
    }
    commands = [
        {"name": "git evidence collection", "executed": True, "complete": True},
        {"name": "architecture detection", "executed": True, "complete": bool(arch)},
        {"name": "deterministic scanner", "executed": True, "complete": not coverage_errors},
        *analyser_commands,
        {"name": "test-integrity static analysis", "executed": True, "complete": test_integrity.static.status == "complete"},
        {"name": "test-integrity dynamic matrix", "executed": False, "complete": False, "reason": "approval required"},
        {"name": "complexity analysis", "executed": True, "complete": complexity.status == "complete"},
    ]
    test_integrity.close()
    payload = {
        "schema_version": "1.2", "mode": mode,
        "scope": {"root": str(root), "base": base, "branch": git(root, "branch", "--show-current"), "head": git(root, "rev-parse", "HEAD"), "merge_base": git(root, "merge-base", base, "HEAD") if base else "", "files": semantic_context_paths, "entries": [asdict(entry) for entry in entries]},
        "intent": review_intent,
        "repository": {"instructions": instructions, "languages": languages, "frameworks": list(dict.fromkeys([*(arch.get("key_libraries") or {}).get("framework", []), *requested_frameworks])), "framework_packs": loaded_framework_packs(root, arch, semantic_context_paths, requested_frameworks), "package_managers": detected.get("package_managers", []), "test_commands": detected.get("commands", {}), "architecture": arch, "manifests": manifests, "touchpoints": touchpoints},
        "behavioural_units": behavioural_units(root, semantic_context_paths, entries, scope_reasons), "candidates": candidate_values,
        "test_evidence": test_evidence,
        "complexity": complexity_evidence,
        "commands": commands,
        "coverage": coverage,
        "limitations": coverage_errors + analyser_limitations + ["Semantic confirmation, falsification, and runtime evidence are performed by the reviewer."],
    }
    return redact_payload(payload)


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
    worker_delay = getattr(args, "worker_delay", 0.0)
    if worker_delay:
        values.extend(["--worker-delay", str(worker_delay)])
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
        try:
            process = subprocess.Popen(
                _worker_arguments(args, temporary),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
        except OSError as error:
            print(f"could not start context worker: {redact_sensitive_text(str(error))}", file=sys.stderr)
            return 1
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
        if not isinstance(payload, dict) or payload.get("schema_version") != "1.2":
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
    parser.add_argument("--worker-delay", type=float, default=0.0, help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.timeout is None:
        try:
            args.timeout = float(analysis_limits(local_config(args.root.resolve()))["context_timeout_seconds"])
        except ValueError as error:
            parser.error(str(error))
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if not math.isfinite(args.worker_delay) or args.worker_delay < 0:
        parser.error("--worker-delay must be finite and non-negative")
    if args.worker:
        try:
            if args.worker_delay:
                time.sleep(args.worker_delay)
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
    return _run_supervisor(args)


if __name__ == "__main__":
    raise SystemExit(main())
