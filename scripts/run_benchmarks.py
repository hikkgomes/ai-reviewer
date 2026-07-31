#!/usr/bin/env python3
"""Run representative benchmarks through an installed Dissect skill.

The runner is intentionally explicit about provenance. It never substitutes a
hand-authored result when the agent is unavailable; it records a not-run
artifact instead. This keeps offline CI useful without inflating quality data.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_review_context import build  # noqa: E402
from review_ledger import validate_ledger  # noqa: E402
from install import install_codex_skill  # noqa: E402
from score_review_results import score  # noqa: E402
from validate_review_result import validate  # noqa: E402


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def installed_skill(skill_root: Path) -> Path:
    agents_base = skill_root
    install_codex_skill("dissect-full", agents_base)
    destination = agents_base / "skills" / "dissect-full"
    return destination


def prompt(skill: Path, benchmark: dict[str, Any], context_path: Path) -> str:
    return f"""You are running the installed Dissect skill at {skill}.

Review the proposed benchmark application at {benchmark['_root'] / benchmark['proposed']} against the intent in {benchmark['_root'] / 'intent.md'}.
Use the context at {context_path}. Read the relevant files, trace cross-file callers and controls, and follow reference/review-workflow.md.

Return JSON matching the review-result schema. Include a `provenance` object, a `candidates` array, and a `ledger` array. Every candidate must have status candidate, verified, disproved, not_verifiable, or duplicate, with falsification_attempts and verification_attempts. Every final finding must contain `candidate_id` equal to a ledger candidate whose status is verified. Do not guess expected IDs; use precise locations and evidence. For a clean case, return no findings and preserve Not verified areas.
"""


def run_one(manifest_path: Path, output_dir: Path, skill: Path, codex: str | None) -> dict[str, Any]:
    case = manifest(manifest_path)
    case["_root"] = manifest_path.parent
    proposed = manifest_path.parent / case["proposed"]
    context_path = output_dir / f"context-{case['id']}.json"
    context = build(proposed, "full", "", None, manifest_path.parent / "intent.md", tuple(case.get("frameworks", [])))
    context_path.write_text(json.dumps(context, indent=2, sort_keys=True), encoding="utf-8")
    raw_path = output_dir / f"raw-{case['id']}.jsonl"
    final_path = output_dir / f"agent-{case['id']}.json"
    metadata = {
        "schema_version": "1.0", "benchmark_id": case["id"], "generator": "not-run",
        "skill_path": str(skill), "skill_sha256": sha256(skill / "SKILL.md"),
        "invocation": [], "started_at": datetime.now(timezone.utc).isoformat(),
        "commit_under_review": git(ROOT, "rev-parse", "HEAD"), "context_path": str(context_path),
        "raw_output_path": str(raw_path), "final_output_path": str(final_path),
    }
    if not codex:
        raw_path.write_text("", encoding="utf-8")
        final = {"schema_version": "1.0", "mode": "full", "status": "not_run", "provenance": metadata, "candidates": [], "ledger": [], "findings": [], "open_questions": [], "not_verified": ["agent unavailable"], "coverage": {}}
        final_path.write_text(json.dumps(final, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return final
    schema = ROOT / "reference" / "review-result-schema.json"
    command = [codex, "exec", "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only", "--json", "--output-schema", str(schema), "-o", str(final_path), "-C", str(proposed), prompt(skill, case, context_path)]
    metadata["generator"] = "codex-cli"
    metadata["invocation"] = command
    codex_home = Path(tempfile.mkdtemp(prefix="codex-home-"))
    environment = {**os.environ, "CODEX_HOME": str(codex_home)}
    completed = subprocess.run(command, cwd=proposed, env=environment, text=True, capture_output=True, check=False)
    raw_path.write_text(completed.stdout + completed.stderr, encoding="utf-8")
    metadata["exit_code"] = completed.returncode
    metadata["completed_at"] = datetime.now(timezone.utc).isoformat()
    if final_path.exists():
        try:
            final = json.loads(final_path.read_text(encoding="utf-8"))
        except ValueError:
            final = {"schema_version": "1.0", "mode": "full", "status": "invalid_agent_output", "provenance": metadata, "candidates": [], "ledger": [], "findings": [], "open_questions": ["Agent output was not valid JSON"], "not_verified": ["agent output"], "coverage": {}}
    else:
        final = {"schema_version": "1.0", "mode": "full", "status": "agent_failed", "provenance": metadata, "candidates": [], "ledger": [], "findings": [], "open_questions": ["Agent did not produce a final result"], "not_verified": ["agent output"], "coverage": {}}
    final["provenance"] = {**metadata, **(final.get("provenance") or {})}
    validation_errors = validate(final)
    if validation_errors:
        final["status"] = "invalid_result"
        final["validation_errors"] = validation_errors
    final_path.write_text(json.dumps(final, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return final


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT / "benchmarks")
    parser.add_argument("--output", type=Path, default=ROOT / "benchmarks" / "results")
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--codex", default=shutil.which("codex"), help="Codex executable; omit to record a deterministic not-run artifact.")
    parser.add_argument("--no-agent", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    # Keep the installed skill outside the benchmark checkout; provenance
    # records its path and hash without turning generated copies into fixtures.
    skill = installed_skill(Path(tempfile.mkdtemp(prefix="dissect-installed-")))
    manifests = sorted(args.root.glob("**/benchmark.json"))
    if args.case:
        manifests = [path for path in manifests if manifest(path).get("id") in set(args.case)]
    outputs = []
    scores = []
    for path in manifests:
        result = run_one(path, args.output, skill, None if args.no_agent else args.codex)
        outputs.append(result)
        scores.append(score(manifest(path), result))
        (args.output / f"score-{manifest(path)['id']}.json").write_text(json.dumps(scores[-1], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = {
        "schema_version": "1.0", "runner": "scripts/run_benchmarks.py",
        "skill_path": str(skill), "skill_sha256": sha256(skill / "SKILL.md"),
        "agent_requested": not args.no_agent, "results": [{"benchmark_id": item.get("provenance", {}).get("benchmark_id"), "status": item.get("status", "complete"), "generator": item.get("provenance", {}).get("generator")} for item in outputs],
        "scores": scores,
    }
    (args.output / "run-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if all(item.get("status") not in {"invalid_agent_output", "agent_failed"} for item in outputs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
