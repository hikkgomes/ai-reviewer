#!/usr/bin/env python3
"""Collect review evidence into a context file outside the reviewed checkout.

This collector deliberately prepares context and scanner candidates without
turning syntactic matches into semantic findings.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from diff_file_list import DiffEntry, read_diff_entries  # noqa: E402
from dissect_checks.engine import ScanOptions, scan_report  # noqa: E402
from dissect_checks import comment_slop  # noqa: E402
from dissect_checks.redaction import redact_sensitive_text  # noqa: E402
import run_anti_slop  # noqa: E402
from file_paths import is_ignored_path, iter_files  # noqa: E402


EXTENSIONS = {
    ".ts": "typescript", ".tsx": "typescript", ".js": "javascript", ".jsx": "javascript",
    ".mjs": "javascript", ".cjs": "javascript", ".py": "python", ".sql": "sql",
    ".java": "java", ".cs": "csharp", ".go": "go", ".rs": "rust", ".php": "php",
    ".rb": "ruby", ".tf": "terraform", ".yml": "yaml", ".yaml": "yaml",
}
INSTRUCTION_NAMES = {"AGENTS.md", "CLAUDE.md", "CONTRIBUTING.md", "README.md"}
INTENT_NAMES = {"TASK.md", "task.md", "PR.md", "pull-request.md", "DESIGN.md", "design.md", "ISSUE.md", "issue.md", "intent.md", "intent.txt", "requirements.md"}
TEXT_SUFFIXES = set(EXTENSIONS) | {".json", ".toml", ".md", ".txt", ".yaml", ".yml"}
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


def _comment_analysis_too_large(path: Path) -> bool:
    try:
        return path.stat().st_size > COMMENT_ANALYSIS_MAX_BYTES
    except OSError:
        return False


class SourceReadError(Exception):
    """Comment-analysis source could not be read; treat as missing evidence."""


def read_full(path: Path) -> str:
    """Read a comment-analysis source file without the context-read cap."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        raise SourceReadError(str(error)) from error


def rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
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
        entry.reviewed_path
        for entry in entries
        if entry.exists_in_worktree
        and entry.reviewed_path
        and not is_ignored_path(root, entry.reviewed_path)
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
    text_by_path: dict[str, str],
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
    options = ScanOptions(root=root, file_list=tuple(paths))
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


def optional_analyser_evidence(
    root: Path,
    mode: str,
    source_scope: list[str],
    entries: list[DiffEntry],
    base: str,
    config: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str], dict[str, dict[str, str]], list[dict[str, Any]]]:
    """Run optional analysers without allowing their runtime to break context collection."""
    values: list[dict[str, Any]] = []
    limitations: list[str] = []
    coverage: dict[str, dict[str, str]] = {}
    commands: list[dict[str, Any]] = []

    if not analyser_enabled(config, "anti_slop"):
        limitation = "anti-slop disabled by review_options"
        limitations.append(limitation)
        coverage["anti-slop"] = {"state": "Not verified", "reason": limitation}
        commands.append({"name": "anti-slop", "executed": False, "complete": False, "reason": limitation})
    else:
        try:
            anti = run_anti_slop.analyse(root, source_scope)
        except Exception as error:  # optional tooling must remain non-fatal
            anti = {
                "tool": "anti-slop", "status": "skipped", "skip_reason": "runner_error",
                "config_variant": "generic", "files_scanned": 0, "candidates": [],
                "detail": str(error),
            }
        values.extend(anti.get("candidates", []))
        commands.append({
            "name": "anti-slop", "executed": True,
            "complete": anti.get("status") == "ok",
            "status": anti.get("status"), "skip_reason": anti.get("skip_reason"),
        })
        if anti.get("status") == "skipped":
            reason = str(anti.get("skip_reason") or "unknown")
            limitation = f"Not verified — anti-slop pass unavailable ({reason})"
            limitations.append(limitation)
            coverage["anti-slop"] = {"state": "Not verified", "reason": limitation}
        else:
            coverage["anti-slop"] = {
                "state": "Checked",
                "reason": f"Skill-local anti-slop pass scanned {anti.get('files_scanned', 0)} file(s); matches remain candidates.",
            }

    if not analyser_enabled(config, "comment_slop"):
        limitation = "comment-slop disabled by review_options"
        limitations.append(limitation)
        coverage["comment-slop"] = {"state": "Not verified", "reason": limitation}
        commands.append({"name": "comment-slop", "executed": False, "complete": False, "reason": limitation})
        return values, limitations, coverage, commands

    ranges_by_path: dict[str, list[tuple[int, int]] | None] = {}
    text_by_path: dict[str, str] = {}
    unreadable_paths: set[str] = set()
    oversized_paths = {
        path for path in source_scope if _comment_analysis_too_large(root / path)
    }
    for path in sorted(oversized_paths):
        limitations.append(redact_sensitive_text(f"comment-slop: file too large for comment analysis {path}"))
    for path in source_scope:
        if path in oversized_paths:
            if mode == "diff":
                ranges_by_path[path] = None
            continue
        try:
            text_by_path[path] = read_full(root / path)
        except SourceReadError:
            unreadable_paths.add(path)
            limitations.append(redact_sensitive_text(f"comment-slop: source unreadable for comment analysis {path}"))
            if mode == "diff":
                ranges_by_path[path] = None
            continue
        if mode == "diff":
            ranges = changed_line_ranges(root, path, entries, base, text_by_path[path])
            ranges_by_path[path] = ranges
            if ranges is None:
                limitations.append(redact_sensitive_text(f"comment-slop: no diff-line evidence for {path}"))
    density = _comment_density(source_scope, ranges_by_path, text_by_path) if mode == "diff" else 0.0
    try:
        for path in source_scope:
            text = text_by_path.get(path)
            if text is None:
                continue
            ranges = ranges_by_path.get(path) if mode == "diff" else None
            values.extend(comment_slop.scan_comments(path, text, ranges, mode, density))
    except Exception as error:  # optional tooling must remain non-fatal
        limitation = redact_sensitive_text(f"Not verified — comment-slop pass unavailable (runner_error: {error})")
        limitations.append(limitation)
        coverage["comment-slop"] = {"state": "Not verified", "reason": limitation}
        commands.append({"name": "comment-slop", "executed": True, "complete": False, "reason": redact_sensitive_text(str(error))})
    else:
        unevidenced = sorted({
            path for path, ranges in ranges_by_path.items() if ranges is None
        } | oversized_paths | unreadable_paths)
        if unevidenced:
            preview = ", ".join(unevidenced[:3])
            reason = redact_sensitive_text(
                f"comment-slop: incomplete source or diff evidence for {len(unevidenced)} file(s): {preview}"
            )
            coverage["comment-slop"] = {"state": "Not verified", "reason": reason}
            commands.append({"name": "comment-slop", "executed": True, "complete": False})
        else:
            coverage["comment-slop"] = {
                "state": "Checked",
                "reason": "Comment candidates are scoped to changed lines in diff mode and remain subject to semantic verification.",
            }
            commands.append({"name": "comment-slop", "executed": True, "complete": True})
    return values, limitations, coverage, commands


def build(root: Path, mode: str, base: str, file_list: Path | None, intent_file: Path | None = None, requested_frameworks: tuple[str, ...] = ()) -> dict[str, Any]:
    config = local_config(root)
    entries = changed_entries(root, mode, file_list, base)
    changed = source_paths(root, entries, mode)
    paths, scope_reasons = expanded_paths(root, changed, mode)
    candidate_values, coverage_errors = candidates(root, entries, paths)
    optional_values, analyser_limitations, analyser_coverage, analyser_commands = optional_analyser_evidence(
        root, mode, changed, entries, base, config,
    )
    candidate_values.extend(optional_values)
    instructions = [rel(path, root) for path in iter_files(root) if path.name in INSTRUCTION_NAMES]
    manifests = [path for path in paths if Path(path).name in {"package.json", "pyproject.toml", "go.mod", "Cargo.toml", "composer.json", "pom.xml", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}]
    languages = sorted({EXTENSIONS[Path(path).suffix.lower()] for path in paths if Path(path).suffix.lower() in EXTENSIONS})
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
        touchpoints[category] = [{"path": path, "reason": "path or source token matched"} for path in paths if any(token in path.lower() or token in read(root / path).lower() for token in tokens)][:80]
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
        "schema_version": "1.0", "mode": mode,
        "scope": {"root": str(root), "base": base, "branch": git(root, "branch", "--show-current"), "head": git(root, "rev-parse", "HEAD"), "merge_base": git(root, "merge-base", base, "HEAD") if base else "", "files": paths, "entries": [asdict(entry) for entry in entries]},
        "intent": intent(root, intent_file),
        "repository": {"instructions": instructions, "languages": languages, "frameworks": list(dict.fromkeys([*(arch.get("key_libraries") or {}).get("framework", []), *requested_frameworks])), "framework_packs": loaded_framework_packs(root, arch, paths, requested_frameworks), "package_managers": detected.get("package_managers", []), "test_commands": detected.get("commands", {}), "architecture": arch, "manifests": manifests, "touchpoints": touchpoints},
        "behavioural_units": behavioural_units(root, paths, entries, scope_reasons), "candidates": candidate_values,
        "commands": commands,
        "coverage": coverage,
        "limitations": coverage_errors + analyser_limitations + ["Semantic confirmation, falsification, and runtime evidence are performed by the reviewer."],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--mode", choices=("diff", "full"), required=True)
    parser.add_argument("--base", default="")
    parser.add_argument("--file-list", type=Path)
    parser.add_argument("--intent-file", type=Path)
    parser.add_argument("--framework", action="append", default=[])
    parser.add_argument("--timeout", type=int, default=DEFAULT_CONTEXT_TIMEOUT_SECONDS)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    def timeout_handler(_signum: int, _frame: Any) -> None:
        raise TimeoutError(f"review context construction exceeded {args.timeout} seconds")

    previous_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(args.timeout)
    try:
        payload = build(args.root.resolve(), args.mode, args.base, args.file_list, args.intent_file, tuple(args.framework))
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_handler)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(str(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
