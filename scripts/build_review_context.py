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
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from diff_file_list import DiffEntry, read_diff_entries  # noqa: E402
from dissect_checks.engine import ScanOptions, scan_report  # noqa: E402
from file_paths import iter_files  # noqa: E402


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


def git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def read(path: Path, limit: int = 12000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


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
    return sorted({entry.reviewed_path for entry in entries if entry.exists_in_worktree and entry.reviewed_path})


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


def evidence_lines(text: str, patterns: tuple[str, ...]) -> list[str]:
    return [line.strip() for line in text.splitlines() if any(re.search(pattern, line, re.I) for pattern in patterns)][:20]


def all_text_paths(root: Path) -> list[str]:
    return sorted(rel(path, root) for path in iter_files(root) if path.suffix.lower() in TEXT_SUFFIXES)


def expanded_paths(root: Path, changed: list[str], mode: str) -> tuple[list[str], dict[str, list[dict[str, str]]]]:
    if mode == "full":
        return all_text_paths(root), {}
    candidates = all_text_paths(root)
    changed_symbols = [name for path in changed for name in symbols(read(root / path))]
    selected = set(changed)
    reasons: dict[str, list[dict[str, str]]] = {path: [{"reason": "changed scope"}] for path in changed}
    for path in candidates:
        if path in selected:
            continue
        text = read(root / path)
        referenced = [name for name in changed_symbols if re.search(rf"\b{re.escape(name)}\b", text)]
        companion = any(token in path.lower() for token in ("middleware", "schema", "model", "migration", "config", "test", "spec", "route", "handler"))
        if referenced or companion and any(Path(item).stem in path for item in changed):
            selected.add(path)
            reasons[path] = [{"reason": "direct symbol reference" if referenced else "credible companion path", "symbols": ", ".join(referenced)}]
    return sorted(selected), reasons


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
            content = read(root / member)
            changed_symbols.extend(f"{member}:{symbol}" for symbol in symbols(content))
            if "/test" in f"/{member}" or "/tests" in f"/{member}" or ".spec." in member or ".test." in member:
                tests.append(member)
            if any(token in member.lower() for token in ("config", ".env", "workflow", "docker", "terraform")):
                configuration.append(member)
        unit_text = "\n".join(read(root / member) for member in members)
        declarations = [item for member in members for item in symbols_with_lines(read(root / member), member)]
        names = [item["name"] for item in declarations]
        callers = []
        for candidate in paths:
            if candidate in members:
                continue
            candidate_text = read(root / candidate)
            referenced = [name for name in names if re.search(rf"\b{re.escape(name)}\b", candidate_text)]
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


def build(root: Path, mode: str, base: str, file_list: Path | None, intent_file: Path | None = None, requested_frameworks: tuple[str, ...] = ()) -> dict[str, Any]:
    entries = changed_entries(root, mode, file_list, base)
    changed = source_paths(root, entries, mode)
    paths, scope_reasons = expanded_paths(root, changed, mode)
    candidate_values, coverage_errors = candidates(root, entries, paths)
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
    return {
        "schema_version": "1.0", "mode": mode,
        "scope": {"root": str(root), "base": base, "branch": git(root, "branch", "--show-current"), "head": git(root, "rev-parse", "HEAD"), "merge_base": git(root, "merge-base", base, "HEAD") if base else "", "files": paths, "entries": [asdict(entry) for entry in entries]},
        "intent": intent(root, intent_file),
        "repository": {"instructions": instructions, "languages": languages, "frameworks": list(dict.fromkeys([*(arch.get("key_libraries") or {}).get("framework", []), *requested_frameworks])), "framework_packs": loaded_framework_packs(root, arch, paths, requested_frameworks), "package_managers": detected.get("package_managers", []), "test_commands": detected.get("commands", {}), "architecture": arch, "manifests": manifests, "touchpoints": touchpoints},
        "behavioural_units": behavioural_units(root, paths, entries, scope_reasons), "candidates": candidate_values,
        "commands": [{"name": "git evidence collection", "executed": True, "complete": True}, {"name": "architecture detection", "executed": True, "complete": bool(arch)}, {"name": "deterministic scanner", "executed": True, "complete": not coverage_errors}],
        "coverage": coverage, "limitations": coverage_errors + (["Semantic confirmation, falsification, and runtime evidence are performed by the reviewer."] if True else []),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--mode", choices=("diff", "full"), required=True)
    parser.add_argument("--base", default="")
    parser.add_argument("--file-list", type=Path)
    parser.add_argument("--intent-file", type=Path)
    parser.add_argument("--framework", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = build(args.root.resolve(), args.mode, args.base, args.file_list, args.intent_file, tuple(args.framework))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(str(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
