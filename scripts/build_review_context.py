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


EXTENSIONS = {
    ".ts": "typescript", ".tsx": "typescript", ".js": "javascript", ".jsx": "javascript",
    ".mjs": "javascript", ".cjs": "javascript", ".py": "python", ".sql": "sql",
    ".java": "java", ".cs": "csharp", ".go": "go", ".rs": "rust", ".php": "php",
    ".rb": "ruby", ".tf": "terraform", ".yml": "yaml", ".yaml": "yaml",
}
INSTRUCTION_NAMES = {"AGENTS.md", "CLAUDE.md", "CONTRIBUTING.md", "README.md"}
INTENT_NAMES = {"TASK.md", "task.md", "PR.md", "pull-request.md", "DESIGN.md", "design.md", "ISSUE.md", "issue.md"}
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
            return [DiffEntry("M", rel(path, root), rel(path, root), True, "working-tree") for path in root.rglob("*") if path.is_file()]
    return [DiffEntry("M", rel(path, root), rel(path, root), True, "working-tree") for path in root.rglob("*") if path.is_file() and ".git" not in path.parts]


def source_paths(root: Path, entries: list[DiffEntry], mode: str) -> list[str]:
    if mode == "full":
        return sorted({rel(path, root) for path in root.rglob("*") if path.is_file() and ".git" not in path.parts and path.parts[-1] not in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}})
    return sorted({entry.reviewed_path for entry in entries if entry.exists_in_worktree and entry.reviewed_path})


def intent(root: Path) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name not in INTENT_NAMES:
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


def behavioural_units(root: Path, paths: list[str], entries: list[DiffEntry]) -> list[dict[str, Any]]:
    groups: dict[str, list[str]] = {}
    for path in paths:
        groups.setdefault(classify(path), []).append(path)
    units = []
    for index, (kind, members) in enumerate(sorted(groups.items()), 1):
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
        units.append({
            "id": f"unit-{index}", "kind": kind, "entry_points": members,
            "changed_symbols": list(dict.fromkeys(changed_symbols)), "inputs": [], "outputs": [],
            "state_read": [], "state_modified": [], "external_side_effects": [], "error_paths": [],
            "callers": [], "downstream_consumers": [], "configuration": configuration,
            "tests": tests, "before": "Not collected by the evidence collector; compare the base or prior contract.",
            "after": "Review changed symbols and their reachable callers/callees in the semantic phase.",
        })
    return units


def candidates(root: Path, entries: list[DiffEntry], paths: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    options = ScanOptions(root=root, file_list=tuple(paths), diff_entries=tuple(
        (entry.status, entry.old_path, entry.new_path, entry.exists_in_worktree, entry.source_kind, entry.commit_revision, entry.index_stage, entry.blob_path)
        for entry in entries
    ))
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


def build(root: Path, mode: str, base: str, file_list: Path | None) -> dict[str, Any]:
    entries = changed_entries(root, mode, file_list, base)
    paths = source_paths(root, entries, mode)
    candidate_values, coverage_errors = candidates(root, entries, paths)
    instructions = [rel(path, root) for path in root.rglob("*") if path.is_file() and path.name in INSTRUCTION_NAMES]
    manifests = [path for path in paths if Path(path).name in {"package.json", "pyproject.toml", "go.mod", "Cargo.toml", "composer.json", "pom.xml", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}]
    languages = sorted({EXTENSIONS[Path(path).suffix.lower()] for path in paths if Path(path).suffix.lower() in EXTENSIONS})
    arch = architecture(root)
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
        "intent": intent(root),
        "repository": {"instructions": instructions, "languages": languages, "frameworks": (arch.get("key_libraries") or {}).get("framework", []), "package_managers": [], "test_commands": [], "architecture": arch, "manifests": manifests, "touchpoints": {"auth": [], "payments": [], "persistence": [], "routes": [], "infrastructure": []}},
        "behavioural_units": behavioural_units(root, paths, entries), "candidates": candidate_values,
        "commands": [{"name": "git evidence collection", "executed": True, "complete": True}, {"name": "deterministic scanner", "executed": True, "complete": not coverage_errors}],
        "coverage": coverage, "limitations": coverage_errors + (["Semantic confirmation, falsification, and runtime evidence are performed by the reviewer."] if True else []),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--mode", choices=("diff", "full"), required=True)
    parser.add_argument("--base", default="")
    parser.add_argument("--file-list", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = build(args.root.resolve(), args.mode, args.base, args.file_list)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(str(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
