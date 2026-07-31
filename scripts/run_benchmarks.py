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
import tomllib
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


def tree_manifest(path: Path) -> dict[str, Any]:
    """Return a deterministic, content-addressed manifest for a file tree."""
    files = []
    for item in sorted(path.rglob("*")):
        if not item.is_file():
            continue
        relative = item.relative_to(path).as_posix()
        files.append({"path": relative, "sha256": sha256(item), "size": item.stat().st_size})
    encoded = "".join(
        f"{item['path']}\t{item['sha256']}\t{item['size']}\n" for item in files
    ).encode("utf-8")
    return {"sha256": hashlib.sha256(encoded).hexdigest(), "files": files}


def codex_version(codex: str) -> str:
    result = subprocess.run([codex, "--version"], text=True, capture_output=True, check=False)
    return (result.stdout or result.stderr).strip()


def configured_model(codex_home: Path) -> str | None:
    """Return the configured model when Codex exposes one locally."""
    config = codex_home / "config.toml"
    try:
        value = tomllib.loads(config.read_text(encoding="utf-8")).get("model")
    except (OSError, tomllib.TOMLDecodeError):
        return None
    return str(value) if value else None


def prepare_codex_environment(skill_name: str = "dissect-full") -> tuple[Path, Path, dict[str, str]]:
    """Create the only skill-discovery root visible to a spawned Codex process.

    Codex's supported skill location is ``$CODEX_HOME/skills``. The isolated
    HOME prevents discovery through a user's global ``.agents`` tree while
    copying only the top-level Codex files needed for authentication/config.
    No global skills, caches, sessions, or plugins are copied.
    """
    codex_home = Path(tempfile.mkdtemp(prefix="codex-home-"))
    skill = installed_skill(codex_home, skill_name)
    source_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    for filename in ("auth.json", "config.toml"):
        source = source_home / filename
        if source.is_file():
            shutil.copy2(source, codex_home / filename)
    isolated_home = codex_home / "home"
    isolated_home.mkdir()
    environment = {**os.environ}
    environment.update({
        "CODEX_HOME": str(codex_home),
        "HOME": str(isolated_home),
        "USERPROFILE": str(isolated_home),
        "XDG_CONFIG_HOME": str(isolated_home / ".config"),
    })
    return codex_home, skill, environment


def installed_skill(skill_root: Path, skill_name: str = "dissect-full") -> Path:
    """Install and return a skill under the supplied Codex discovery root."""
    install_codex_skill(skill_name, skill_root)
    return skill_root / "skills" / skill_name


def git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def prompt(skill: Path, benchmark: dict[str, Any], context_path: Path) -> str:
    workflow = skill / "reference" / "review-workflow.md"
    return f"""You are running the installed Dissect skill at {skill}.
The benchmark runner installed this exact entrypoint in the active Codex skill
discovery root. Read {skill / 'SKILL.md'} and the canonical workflow at
{workflow} before reviewing. Do not use any other Dissect installation.

Review the proposed benchmark application at {benchmark['_root'] / benchmark['proposed']} against the intent in {benchmark['_root'] / 'intent.md'}.
Use the context at {context_path}. Read the relevant files, trace cross-file callers and controls, and follow reference/review-workflow.md.

Return JSON matching the review-result schema. Include a `provenance` object, a `candidates` array, and a `ledger` array. Every candidate must have status candidate, verified, disproved, not_verifiable, or duplicate, with falsification_attempts and verification_attempts. Every final finding must contain `candidate_id` equal to a ledger candidate whose status is verified. Do not guess expected IDs; use precise locations and evidence. For a clean case, return no findings and preserve Not verified areas.
"""


def run_one(
    manifest_path: Path,
    output_dir: Path,
    skill: Path,
    codex: str | None,
    environment: dict[str, str] | None = None,
    agent_options: tuple[str, ...] = (),
) -> dict[str, Any]:
    case = manifest(manifest_path)
    case["_root"] = manifest_path.parent
    proposed = manifest_path.parent / case["proposed"]
    context_path = output_dir / f"context-{case['id']}.json"
    context = build(proposed, "full", "", None, manifest_path.parent / "intent.md", tuple(case.get("frameworks", [])))
    context_path.write_text(json.dumps(context, indent=2, sort_keys=True), encoding="utf-8")
    raw_path = output_dir / f"raw-{case['id']}.jsonl"
    stderr_path = output_dir / f"stderr-{case['id']}.log"
    final_path = output_dir / f"agent-{case['id']}.json"
    fixture_manifest = tree_manifest(proposed)
    benchmark_manifest_digest = sha256(manifest_path)
    intent_path = manifest_path.parent / "intent.md"
    reviewer_commit = git(ROOT, "rev-parse", "HEAD")
    reviewer_dirty = bool(git(ROOT, "status", "--porcelain"))
    skill_manifest = tree_manifest(skill)
    codex_home = skill.parents[1]
    workflow_path = skill / "reference" / "review-workflow.md"
    entrypoint_path = skill / "SKILL.md"
    metadata = {
        "schema_version": "1.0", "benchmark_id": case["id"], "generator": "not-run",
        "skill_path": str(skill), "skill_sha256": sha256(entrypoint_path),
        "installed_skill_tree_sha256": skill_manifest["sha256"],
        "installed_skill_manifest": skill_manifest["files"],
        "skill_discovery": {
            "method": "CODEX_HOME/skills",
            "codex_home": str(skill.parents[1]),
            "skill_path": str(skill),
            "entrypoint": "dissect-full",
            "entrypoint_path": str(entrypoint_path),
            "entrypoint_sha256": sha256(entrypoint_path),
            "canonical_workflow_path": str(workflow_path),
            "canonical_workflow_sha256": sha256(workflow_path),
            "isolated_home": True,
            "prompt_load_instruction": True,
        },
        "invocation": [], "started_at": datetime.now(timezone.utc).isoformat(),
        "reviewer_source_commit": reviewer_commit, "reviewer_source_dirty": reviewer_dirty,
        "benchmark_manifest_sha256": benchmark_manifest_digest,
        "benchmark_fixture_sha256": fixture_manifest["sha256"],
        "benchmark_fixture_manifest": fixture_manifest["files"],
        "intent_sha256": sha256(intent_path),
        "codex_executable": "", "codex_version": "", "model_identifier": configured_model(codex_home),
        "context_path": str(context_path), "raw_output_path": str(raw_path),
        "stderr_output_path": str(stderr_path), "final_output_path": str(final_path),
    }
    if not codex:
        metadata["completed_at"] = datetime.now(timezone.utc).isoformat()
        raw_path.write_text("", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        final = {"schema_version": "1.0", "mode": "full", "status": "not_run", "provenance": metadata, "candidates": [], "ledger": [], "findings": [], "open_questions": [], "not_verified": ["agent unavailable"], "coverage": {}}
        final_path.write_text(json.dumps(final, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return final
    schema = ROOT / "reference" / "review-result-schema.json"
    command = [codex, "exec", *agent_options, "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only", "--json", "--output-schema", str(schema), "-o", str(final_path), "-C", str(proposed), prompt(skill, case, context_path)]
    # Never interpret an artifact from an earlier invocation as this run's
    # reviewer output, especially if the new agent fails before writing JSON.
    if final_path.exists():
        final_path.unlink()
    metadata["generator"] = "codex-cli"
    metadata["invocation"] = command
    metadata["codex_executable"] = str(Path(codex).resolve())
    metadata["codex_version"] = codex_version(codex)
    environment = {**(environment or os.environ)}
    codex_home = Path(skill.parents[1])
    environment.update({
        "CODEX_HOME": str(codex_home),
        "HOME": str(codex_home / "home"),
        "USERPROFILE": str(codex_home / "home"),
        "XDG_CONFIG_HOME": str(codex_home / "home" / ".config"),
    })
    completed = subprocess.run(command, cwd=proposed, env=environment, text=True, capture_output=True, check=False)
    raw_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    metadata["exit_code"] = completed.returncode
    metadata["completed_at"] = datetime.now(timezone.utc).isoformat()
    if final_path.exists():
        try:
            final = json.loads(final_path.read_text(encoding="utf-8"))
        except ValueError:
            final = {"schema_version": "1.0", "mode": "full", "status": "invalid_agent_output", "provenance": metadata, "candidates": [], "ledger": [], "findings": [], "open_questions": ["Agent output was not valid JSON"], "not_verified": ["agent output"], "coverage": {}}
    else:
        final = {"schema_version": "1.0", "mode": "full", "status": "agent_failed", "provenance": metadata, "candidates": [], "ledger": [], "findings": [], "open_questions": ["Agent did not produce a final result"], "not_verified": ["agent output"], "coverage": {}}
    agent_provenance = final.get("provenance") or {}
    if agent_provenance.get("model_identifier"):
        metadata["model_identifier"] = agent_provenance["model_identifier"]
    agent_provenance = {
        key: value for key, value in agent_provenance.items()
        if key != "commit_under_review"
    }
    final["provenance"] = {**agent_provenance, **metadata}
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
    parser.add_argument("--oss", action="store_true", help="Use Codex's configured open-source provider.")
    parser.add_argument("--local-provider", choices=("lmstudio", "ollama"), help="Local OSS provider to use; implies --oss.")
    args = parser.parse_args()
    if args.local_provider:
        args.oss = True
    args.output.mkdir(parents=True, exist_ok=True)
    # Install into the actual Codex skill-discovery root used by the spawned
    # process, keeping that root isolated from the benchmark checkout.
    _codex_home, skill, environment = prepare_codex_environment()
    manifests = sorted(args.root.glob("**/benchmark.json"))
    if args.case:
        manifests = [path for path in manifests if manifest(path).get("id") in set(args.case)]
    outputs = []
    scores = []
    agent_options = (("--oss",) if args.oss else ()) + (("--local-provider", args.local_provider) if args.local_provider else ())
    for path in manifests:
        result = run_one(path, args.output, skill, None if args.no_agent else args.codex, environment, agent_options)
        outputs.append(result)
        scores.append(score(manifest(path), result))
        (args.output / f"score-{manifest(path)['id']}.json").write_text(json.dumps(scores[-1], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = {
        "schema_version": "1.0", "runner": "scripts/run_benchmarks.py",
        "skill_path": str(skill), "skill_sha256": sha256(skill / "SKILL.md"),
        "installed_skill_tree_sha256": tree_manifest(skill)["sha256"],
        "agent_requested": not args.no_agent, "results": [{"benchmark_id": item.get("provenance", {}).get("benchmark_id"), "status": item.get("status", "complete"), "generator": item.get("provenance", {}).get("generator")} for item in outputs],
        "scores": scores,
    }
    (args.output / "run-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if all(item.get("status") not in {"invalid_agent_output", "agent_failed"} for item in outputs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
