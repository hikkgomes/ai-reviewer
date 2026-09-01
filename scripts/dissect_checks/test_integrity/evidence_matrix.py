"""Approval-bound base/head test evidence matrix."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tarfile
import time
from typing import Any, Iterable, Mapping

from dissect_checks.execution_plan import ExecutionPlan, build_execution_plan, execute_approved_plan
from dissect_checks.redaction import redact_sensitive_text
from review_ledger import blank_candidate, validate_candidate
from .change_analysis import ChangePartition
from .model import REACHABILITY_STATES, SCENARIO_IDS, TestRunResult, bounded_fingerprint, canonical_json, digest_payload, sha256_bytes


MAX_SOURCE_FILE_BYTES = 5 * 1024 * 1024
MAX_SOURCE_ARCHIVE_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class MatrixScenario:
    scenario_id: str
    production_state: str
    test_state: str
    source_hashes: Mapping[str, Any]
    selected_tests: tuple[str, ...]
    plan: ExecutionPlan | None
    result: TestRunResult
    repeated_runs: tuple[TestRunResult, ...] = ()
    focal_subjects: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "production_state": self.production_state,
            "test_state": self.test_state,
            "source_hashes": dict(sorted(self.source_hashes.items())),
            "selected_tests": list(self.selected_tests),
            "reachability": self.result.reachability,
            "reached_subjects": list(self.result.reached_subjects),
            "plan": self.plan.redacted_payload() if self.plan is not None else None,
            "result": self.result.as_dict(),
            "repeated_runs": [item.as_dict() for item in self.repeated_runs],
            "focal_subjects": list(self.focal_subjects),
            "flakiness": flakiness_evidence(self.repeated_runs) if self.repeated_runs else {
                "run_count": 0,
                "pass_count": 0,
                "fail_count": 0,
                "seeds": [],
                "order_settings": [],
                "output_fingerprints": [],
                "first_difference": None,
                "stable": False,
                "status": "not_verified",
            },
        }


@dataclass
class EvidenceMatrix:
    scenarios: tuple[MatrixScenario, ...]
    status: str
    reason_code: str | None = None
    _temporary: tempfile.TemporaryDirectory[str] | None = None
    ambiguous_configuration: bool = False
    dynamic_candidates: tuple[Mapping[str, Any], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason_code": self.reason_code,
            "ambiguous_configuration": self.ambiguous_configuration,
            "interpretation": interpret_matrix(self.scenarios),
            "scenarios": [scenario.as_dict() for scenario in self.scenarios],
            "candidates": [dict(item) for item in self.dynamic_candidates],
        }

    def close(self) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()
            self._temporary = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __enter__(self) -> "EvidenceMatrix":
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.close()


def interpret_matrix(scenarios: Iterable[MatrixScenario]) -> dict[str, Any]:
    """Interpret the four outcomes without reducing them to one score."""
    values = tuple(scenarios)
    by_id = {item.scenario_id: item.result for item in values}
    if len(values) != len(SCENARIO_IDS) or set(by_id) != set(SCENARIO_IDS):
        return {"outcome": "not_verified", "reason_code": "incomplete_scenarios"}
    if any(not by_id[item].completed or by_id[item].passed is None for item in SCENARIO_IDS):
        return {"outcome": "not_verified", "reason_code": "scenario_not_verified"}
    values = tuple(by_id[item].passed for item in SCENARIO_IDS)
    if values[0] is False:
        return {"outcome": "inconclusive", "reason_code": "baseline_failed"}
    if values[3] is False:
        return {"outcome": "not_verified", "reason_code": "head_failed"}
    if values == (True, False, True, True):
        return {"outcome": "distinguishes_base_and_head", "reason_code": "changed_test_detects_head_behaviour"}
    if values == (True, True, True, True):
        return {"outcome": "stable_contract", "reason_code": "new_tests_do_not_distinguish_sources"}
    if values == (True, False, False, True):
        return {"outcome": "contract_changed", "reason_code": "intent_required"}
    if values == (True, True, False, True):
        return {"outcome": "regression_candidate", "reason_code": "head_code_fails_base_tests"}
    return {"outcome": "material_difference", "reason_code": "review_required"}


def flakiness_evidence(
    runs: Iterable[TestRunResult],
    *,
    seeds: Iterable[str] = (),
    order_settings: Iterable[str] = (),
) -> dict[str, Any]:
    """Summarise repeated identical runs without collapsing them to a score."""
    values = tuple(runs)
    passes = sum(1 for item in values if item.passed is True)
    failures = sum(1 for item in values if item.passed is False)
    fingerprints = tuple(sorted({item.output_fingerprint for item in values if item.output_fingerprint}))
    verified = bool(values) and all(item.completed and item.passed is not None for item in values)
    stable = verified and len({item.passed for item in values}) <= 1 and len(fingerprints) <= 1
    first_difference: dict[str, Any] | None = None
    if values:
        first = values[0]
        for index, item in enumerate(values[1:], 1):
            if item.passed != first.passed or item.output_fingerprint != first.output_fingerprint:
                first_difference = {
                    "run_index": index,
                    "first_passed": first.passed,
                    "different_passed": item.passed,
                    "first_output_fingerprint": first.output_fingerprint,
                    "different_output_fingerprint": item.output_fingerprint,
                    "reason_code": item.reason_code,
                }
                break
    return {
        "run_count": len(values),
        "pass_count": passes,
        "fail_count": failures,
        "seeds": list(seeds),
        "order_settings": list(order_settings),
        "output_fingerprints": list(fingerprints),
        "first_difference": first_difference,
        "stable": stable,
        "status": "stable" if stable else "flaky" if verified else "not_verified",
    }


def _flakiness_candidates(scenarios: Iterable[MatrixScenario]) -> tuple[Mapping[str, Any], ...]:
    """Create candidate evidence only after repeated approved runs disagree."""
    candidates: list[Mapping[str, Any]] = []
    for scenario in scenarios:
        if not scenario.repeated_runs:
            continue
        evidence = flakiness_evidence(scenario.repeated_runs)
        if evidence["status"] != "flaky":
            continue
        identity = digest_payload({
            "scenario_id": scenario.scenario_id,
            "source_hashes": dict(scenario.source_hashes),
            "flakiness": evidence,
        })
        candidate = blank_candidate(
            f"candidate-test-integrity-{identity[:24]}",
            source="GOV-TESTS-009",
            claim=f"Approved test scenario {scenario.scenario_id} produced inconsistent repeated results.",
            contract="The same source, command, environment, and approved plan should produce stable test evidence.",
        )
        candidate["trigger_path"] = list(scenario.selected_tests[:3])
        candidate["supporting_evidence"] = [{
            "kind": "test_flakiness",
            "rule_id": "GOV-TESTS-009",
            "scenario_id": scenario.scenario_id,
            "source_layer": "private-snapshot",
            "source_hashes": dict(scenario.source_hashes),
            "run_count": evidence["run_count"],
            "pass_count": evidence["pass_count"],
            "fail_count": evidence["fail_count"],
            "seeds": evidence["seeds"],
            "order_settings": evidence["order_settings"],
            "output_fingerprints": evidence["output_fingerprints"],
            "first_difference": evidence["first_difference"],
            "does_not_prove": ["root cause", "unsafe production behaviour", "test removal"],
        }]
        errors = validate_candidate(candidate)
        if errors:
            raise ValueError("invalid flakiness candidate: " + "; ".join(errors))
        candidates.append(candidate)
    return tuple(candidates)


def _reachability_candidates(scenarios: Iterable[MatrixScenario]) -> tuple[Mapping[str, Any], ...]:
    """Create candidates only from explicit dynamic reachability evidence."""
    candidates: list[Mapping[str, Any]] = []
    for scenario in scenarios:
        if scenario.result.reachability != "not_reached" or not scenario.focal_subjects:
            continue
        identity = digest_payload({
            "scenario_id": scenario.scenario_id,
            "source_hashes": dict(scenario.source_hashes),
            "selected_tests": scenario.selected_tests,
            "focal_subjects": scenario.focal_subjects,
        })
        candidate = blank_candidate(
            f"candidate-test-integrity-{identity[:24]}",
            source="GOV-TESTS-008",
            claim=f"Approved test scenario {scenario.scenario_id} did not reach its mapped focal subject.",
            contract="The selected test must execute the focal subject claimed by its contract.",
        )
        candidate["trigger_path"] = list(scenario.selected_tests[:3])
        candidate["supporting_evidence"] = [{
            "kind": "test_reachability",
            "rule_id": "GOV-TESTS-008",
            "scenario_id": scenario.scenario_id,
            "source_layer": "private-snapshot",
            "source_hashes": dict(scenario.source_hashes),
            "focal_subjects": list(scenario.focal_subjects),
            "reached_subjects": list(scenario.result.reached_subjects),
            "reachability": scenario.result.reachability,
            "does_not_prove": ["root cause", "unsafe production behaviour", "test removal"],
        }]
        errors = validate_candidate(candidate)
        if errors:
            raise ValueError("invalid reachability candidate: " + "; ".join(errors))
        candidates.append(candidate)
    return tuple(candidates)


reachability_candidates = _reachability_candidates


def _matrix_candidates(scenarios: Iterable[MatrixScenario]) -> tuple[Mapping[str, Any], ...]:
    """Create candidates for matrix patterns which need contract review."""
    values = tuple(scenarios)
    interpretation = interpret_matrix(values)
    outcome = interpretation.get("outcome")
    if outcome not in {"contract_changed", "regression_candidate"}:
        return ()
    by_id = {item.scenario_id: item.result for item in values}
    identity = digest_payload({
        "outcome": outcome,
        "scenarios": {
            key: {
                "passed": by_id[key].passed,
                "source_hashes": by_id[key].production_patch_sha256 + by_id[key].test_patch_sha256,
            }
            for key in SCENARIO_IDS
        },
    })
    candidate = blank_candidate(
        f"candidate-test-integrity-{identity[:24]}",
        source="GOV-TESTS",
        claim=(
            "The changed tests may hide a production regression from the base test contract."
            if outcome == "regression_candidate"
            else "The production and test changes may represent an unreviewed contract change."
        ),
        contract="The four matrix outcomes must agree with an explicit, independently sourced contract.",
    )
    candidate["trigger_path"] = sorted({
        test for scenario in values for test in scenario.selected_tests[:3]
    })[:3]
    candidate["supporting_evidence"] = [{
        "kind": "dynamic_test_matrix",
        "scenario_outcome": outcome,
        "reason_code": interpretation.get("reason_code"),
        "scenarios": {
            scenario_id: {
                "passed": by_id[scenario_id].passed,
                "completed": by_id[scenario_id].completed,
                "source_hashes": dict(next(item.source_hashes for item in values if item.scenario_id == scenario_id)),
                "command_plan_digest": by_id[scenario_id].command_plan_digest,
            }
            for scenario_id in SCENARIO_IDS
        },
        "does_not_prove": ["intent", "independent oracle", "root cause", "test removal"],
    }]
    errors = validate_candidate(candidate)
    if errors:
        raise ValueError("invalid matrix candidate: " + "; ".join(errors))
    return (candidate,)


def _file_digest(values: Mapping[str, bytes | str]) -> str:
    payload = "\n".join(
        f"{path}\0{sha256_bytes(value if isinstance(value, bytes) else value.encode('utf-8', errors='surrogatepass'))}"
        for path, value in sorted(values.items())
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _read_tree(
    root: Path,
    paths: Iterable[str],
    *,
    max_file_bytes: int = MAX_SOURCE_FILE_BYTES,
) -> dict[str, bytes]:
    output: dict[str, bytes] = {}
    for path in sorted(set(paths)):
        path_object = Path(path)
        if path_object.is_absolute() or ".." in path_object.parts:
            continue
        try:
            physical = (root / path_object).resolve()
            physical.relative_to(root.resolve())
            size = physical.stat().st_size
            if size > max_file_bytes:
                continue
            with physical.open("rb") as handle:
                data = handle.read(size)
            if len(data) == size and physical.stat().st_size == size:
                output[path] = data
        except (OSError, ValueError):
            continue
    return output


def _git_blob_size(root: Path, ref: str) -> int | None:
    try:
        size_result = subprocess.run(
            ["git", "cat-file", "-s", ref],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        size = int(size_result.stdout.strip()) if size_result.returncode == 0 else -1
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return size if 0 <= size <= MAX_SOURCE_FILE_BYTES else None


def _read_git_blob(root: Path, ref: str, size: int) -> bytes | None:
    try:
        process = subprocess.Popen(
            ["git", "show", "--format=", ref],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError:
        return None
    try:
        data = process.stdout.read(size + 1) if process.stdout is not None else b""
        if len(data) > size:
            process.kill()
            process.wait(timeout=1)
            return None
        process.wait(timeout=1)
        return data if process.returncode == 0 and len(data) == size else None
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            pass
        return None
    finally:
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass


def _git_file(root: Path, reference: str, path: str) -> bytes | None:
    path_object = Path(path)
    if not reference or reference.startswith("-") or path_object.is_absolute() or not path_object.parts or ".." in path_object.parts:
        return None
    ref = f"{reference}:{path_object.as_posix()}"
    size = _git_blob_size(root, ref)
    return _read_git_blob(root, ref, size) if size is not None else None


def _git_path_changed(root: Path, staged: bool, path: str) -> bool | None:
    path_object = Path(path)
    if path_object.is_absolute() or not path_object.parts or ".." in path_object.parts:
        return None
    arguments = (
        ["git", "diff", "--cached", "--no-ext-diff", "--name-only", "-z", "--", path]
        if staged else
        ["git", "diff", "--no-ext-diff", "--name-only", "-z", "--", path]
    )
    try:
        result = subprocess.run(
            arguments,
            cwd=root,
            capture_output=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return bool(result.stdout)


def _git_tracked(root: Path, path: str) -> bool | None:
    path_object = Path(path)
    if path_object.is_absolute() or not path_object.parts or ".." in path_object.parts:
        return None
    try:
        result = subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", path],
            cwd=root,
            capture_output=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    return None


def _local_path_values(root: Path, path: str) -> tuple[bytes | None, bytes | None] | None:
    tracked = _git_tracked(root, path)
    unstaged = _git_path_changed(root, False, path)
    staged = _git_path_changed(root, True, path)
    if tracked is None or unstaged is None or staged is None:
        return None
    current = _read_tree(root, [path]).get(path)
    if not tracked:
        return None, current
    if unstaged:
        indexed = _git_file(root, ":0", path)
        if indexed is None:
            indexed = _git_file(root, "HEAD", path)
        return indexed, current
    if staged:
        return _git_file(root, "HEAD", path), _git_file(root, ":0", path)
    # Full-mode callers may select clean files. Keep their current bytes so a
    # dirty but otherwise unmodified checkout is not silently converted into
    # an empty matrix scope.
    return current, current


def _local_snapshot_values(root: Path, paths: Iterable[str]) -> tuple[dict[str, bytes], dict[str, bytes]] | None:
    """Build changed local states when callers did not supply source maps."""
    try:
        probe = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if probe.returncode != 0:
        return None
    base: dict[str, bytes] = {}
    head: dict[str, bytes] = {}
    for path in sorted(set(paths)):
        values = _local_path_values(root, path)
        if values is None:
            return None
        before, after = values
        if before is not None:
            base[path] = before
        if after is not None:
            head[path] = after
    return base, head


def _materialise(source_root: Path, destination: Path, overrides: Mapping[str, bytes], removed: Iterable[str] = ()) -> None:
    base_ignore = shutil.ignore_patterns(
        ".git", "node_modules", "__pycache__", "*.pyc", ".venv", "target",
        ".env", ".env.*", "*.pem", "*.key", "credentials.json", "secrets.json",
    )
    def ignore(directory: str, names: list[str]) -> set[str]:
        ignored = set(base_ignore(directory, names))
        ignored.update(name for name in names if (Path(directory) / name).is_symlink())
        return ignored
    shutil.copytree(source_root, destination, ignore=ignore, dirs_exist_ok=True)
    for path in removed:
        if Path(path).is_absolute() or ".." in Path(path).parts:
            continue
        target = destination / path
        try:
            target.unlink()
        except FileNotFoundError:
            pass
    for path, data in overrides.items():
        if Path(path).is_absolute() or ".." in Path(path).parts:
            continue
        target = destination / path
        if target.is_symlink():
            target.unlink()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def _extract_archive(bundle: tarfile.TarFile, destination: Path) -> None:
    root_resolved = destination.resolve()
    members = bundle.getmembers()

    def safe_target(name: str) -> Path:
        relative = Path(name)
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise tarfile.TarError("archive member has an unsafe path")
        current = destination
        for part in relative.parts[:-1]:
            current = current / part
            if current.is_symlink():
                raise tarfile.TarError("archive member follows a symlink")
        target = destination / relative
        if not target.resolve().is_relative_to(root_resolved):
            raise tarfile.TarError("archive member escapes destination")
        return target

    for member in members:
        safe_target(member.name)
        if member.islnk() or member.issym():
            link = Path(member.linkname)
            link_path = (destination / Path(member.name).parent / link).resolve()
            if link.is_absolute() or not link_path.is_relative_to(root_resolved):
                raise tarfile.TarError("archive link escapes destination")
        if member.islnk():
            raise tarfile.TarError("archive hardlinks are not supported")
    for member in members:
        target = safe_target(member.name)
        if target.exists() or target.is_symlink():
            raise tarfile.TarError("archive member collides with an existing path")
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if member.isfile():
            target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                raise tarfile.TarError("archive member could not be read")
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            os.chmod(target, member.mode & 0o777)
            continue
        if member.issym():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(member.linkname)
            continue
        raise tarfile.TarError("archive member type is unsupported")


def _archive_revision(
    root: Path,
    revision: str,
    destination: Path,
    *,
    timeout_seconds: float = 30,
    max_bytes: int = MAX_SOURCE_ARCHIVE_BYTES,
) -> bool:
    """Materialise a Git revision with bounded output and extraction time."""
    if not revision or revision.startswith("-"):
        return False
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max archive bytes must be greater than zero")
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination.parent / f"{destination.name}.tar"
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            ["git", "archive", "--format=tar", revision],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + timeout_seconds
        total = 0
        with archive.open("wb") as handle:
            while process.stdout is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(process.args, timeout_seconds)
                chunk = process.stdout.read(min(1024 * 1024, max_bytes + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError("source archive exceeds its configured limit")
                handle.write(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, timeout_seconds)
        process.wait(timeout=remaining)
        if process.returncode != 0:
            return False
        with tarfile.open(archive, mode="r:") as bundle:
            _extract_archive(bundle, destination)
        return True
    except (OSError, subprocess.SubprocessError, tarfile.TarError, ValueError):
        if process is not None and process.poll() is None:
            process.kill()
        if process is not None:
            try:
                process.communicate(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                pass
        shutil.rmtree(destination, ignore_errors=True)
        return False
    finally:
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
        try:
            archive.unlink()
        except FileNotFoundError:
            pass


def _command_from_config(
    root: Path,
    config: Mapping[str, Any],
    *,
    snapshot_texts: Mapping[str, bytes | str] | None = None,
) -> tuple[str, str] | None:
    options = config.get("review_options") if isinstance(config.get("review_options"), Mapping) else {}
    commands = config.get("commands") if isinstance(config.get("commands"), Mapping) else {}
    explicit = commands.get("test") or options.get("test_command")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip(), "review configuration"
    workflow_command = _repository_ci_test_command(root, snapshot_texts=snapshot_texts)
    if workflow_command is not None:
        return workflow_command, "repository CI configuration snapshot"
    if snapshot_texts is not None:
        for path, value in sorted(snapshot_texts.items()):
            if Path(path).name != "package.json":
                continue
            try:
                package = json.loads(value.decode("utf-8") if isinstance(value, bytes) else value)
            except (UnicodeError, ValueError):
                continue
            scripts = package.get("scripts") if isinstance(package, dict) else None
            test_script = scripts.get("test") if isinstance(scripts, Mapping) else None
            if isinstance(test_script, str) and test_script.strip():
                return "npm test", f"snapshot package manifest: {path}"
        # Once an exact snapshot was supplied, do not fall back to command
        # discovery in the mutable checkout. Missing snapshot configuration is
        # an evidence gap, not permission to run a different command.
        return None
    try:
        result = subprocess.run(
            [os.environ.get("PYTHON", "python3"), str(Path(__file__).resolve().parents[2] / "detect_commands.py")],
            cwd=root, capture_output=True, text=True, check=False, timeout=5,
        )
        if result.returncode == 0:
            import json
            payload = json.loads(result.stdout)
            detected = payload.get("commands", {}).get("test") if isinstance(payload, dict) else None
            if isinstance(detected, str) and detected.strip():
                return detected.strip(), "repository detection"
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return None


def _repository_ci_test_command(
    root: Path,
    *,
    snapshot_texts: Mapping[str, bytes | str] | None = None,
) -> str | None:
    """Find an existing plain test command without inventing framework flags."""
    workflow_root = root / ".github" / "workflows"
    if snapshot_texts is None:
        try:
            workflow_values = [
                (path.as_posix(), path.read_text(encoding="utf-8", errors="replace"))
                for path in sorted(workflow_root.glob("*.y*ml"))
            ]
        except OSError:
            return None
    else:
        workflow_values = [
            (path, value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value)
            for path, value in sorted(snapshot_texts.items())
            if path.startswith(".github/workflows/") or path == ".gitlab-ci.yml"
        ]
    patterns = (
        re.compile(r"^python(?:3)?\s+-m\s+unittest\b[^\r\n]*$"),
        re.compile(r"^(?:python(?:3)?\s+-m\s+pytest|pytest)\b[^\r\n]*$"),
        re.compile(r"^(?:npm|pnpm|yarn)\s+(?:run\s+)?test\b[^\r\n]*$"),
        re.compile(r"^go\s+test\b[^\r\n]*$"),
        re.compile(r"^cargo\s+test\b[^\r\n]*$"),
    )
    for _path, text in workflow_values:
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line.startswith("run:"):
                line = line[4:].strip().strip('"\'')
            if line.startswith("- "):
                line = line[2:].strip()
            if any(pattern.fullmatch(line) for pattern in patterns):
                return line
    return None


def _command_argv(command: str) -> list[str] | None:
    try:
        values = shlex.split(command)
    except ValueError:
        return None
    return values if values and all(value for value in values) else None


def _selected_tests(partition: ChangePartition) -> tuple[str, ...]:
    return tuple(sorted(set(partition.tests + partition.test_support)))


def _scenario_mapping(scenario_id: str) -> tuple[str, str]:
    return {
        "base-code-base-tests": ("base", "base"),
        "base-code-head-tests": ("base", "head"),
        "head-code-base-tests": ("head", "base"),
        "head-code-head-tests": ("head", "head"),
    }[scenario_id]


def _scenario_hashes(
    production: Mapping[str, bytes],
    tests: Mapping[str, bytes],
    config: Mapping[str, bytes],
    *,
    all_values: Mapping[str, bytes] | None = None,
) -> dict[str, Any]:
    files = dict(all_values) if all_values is not None else {**production, **tests, **config}
    return {
        "production_patch_sha256": _file_digest(production),
        "test_patch_sha256": _file_digest(tests),
        "shared_config_patch_sha256": _file_digest(config),
        "source_files_sha256": {path: sha256_bytes(value) for path, value in sorted(files.items())},
        "source_files_present": sorted(files),
    }


def _relative_private_path(root: Path, raw_path: Any) -> Path | None:
    if not isinstance(raw_path, str):
        return None
    path = Path(raw_path)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        return None
    try:
        physical = (root / path).resolve()
        physical.relative_to(root)
    except (OSError, ValueError):
        return None
    return physical


def _verify_expected_file(root: Path, raw_path: Any, expected_digest: Any) -> tuple[str, str] | str:
    path = _relative_private_path(root, raw_path)
    if path is None or not isinstance(expected_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        return "source_snapshot_invalid"
    try:
        size = path.stat().st_size
        if size > MAX_SOURCE_FILE_BYTES:
            return "source_snapshot_changed"
        with path.open("rb") as handle:
            data = handle.read(size)
        if len(data) != size or path.stat().st_size != size:
            return "source_snapshot_changed"
    except (OSError, ValueError):
        return "source_snapshot_changed"
    return str(raw_path), sha256_bytes(data)


def _verify_absent_files(root: Path, values: Any) -> str | None:
    if not isinstance(values, list):
        return "source_snapshot_invalid"
    paths = [_relative_private_path(root, item) for item in values]
    if any(path is None for path in paths):
        return "source_snapshot_invalid"
    return "source_snapshot_changed" if any(path.exists() for path in paths if path is not None) else None


def _verify_materialised_sources(
    plan: ExecutionPlan,
    source_hashes: Mapping[str, Any],
) -> str | None:
    """Revalidate the private scenario tree before an approved test run."""
    required = {"source_files_sha256", "source_files_present", "source_files_absent"}
    if not required <= set(source_hashes):
        return "source_snapshot_missing"
    expected = source_hashes.get("source_files_sha256")
    if not isinstance(expected, Mapping):
        return "source_snapshot_missing"
    if any(not isinstance(path, str) or not isinstance(digest, str) for path, digest in expected.items()):
        return "source_snapshot_invalid"
    root = Path(plan.working_directory).resolve()
    observed: dict[str, str] = {}
    for raw_path, digest in sorted(expected.items()):
        verified = _verify_expected_file(root, raw_path, digest)
        if isinstance(verified, str):
            return verified
        path, actual_digest = verified
        observed[path] = actual_digest
    if observed != dict(sorted(expected.items())):
        return "source_snapshot_changed"
    present = source_hashes.get("source_files_present")
    if present is not None and (
        not isinstance(present, list)
        or any(not isinstance(item, str) or _relative_private_path(root, item) is None for item in present)
        or present != sorted(expected)
    ):
        return "source_snapshot_invalid"
    absent_error = _verify_absent_files(root, source_hashes.get("source_files_absent", []))
    if absent_error is not None:
        return absent_error
    expected_digest = source_hashes.get("scenario_source_sha256")
    if expected_digest is not None and not isinstance(expected_digest, str):
        return "source_snapshot_invalid"
    if isinstance(expected_digest, str):
        if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
            return "source_snapshot_invalid"
        payload = "\n".join(f"{path}\0{digest}" for path, digest in sorted(observed.items())).encode("utf-8")
        if hashlib.sha256(payload).hexdigest() != expected_digest:
            return "source_snapshot_changed"
    return None


def _plan_matches_source_hashes(plan: ExecutionPlan, source_hashes: Mapping[str, Any]) -> bool:
    """Ensure approval bindings still describe the scenario being executed."""
    if not {"source_files_sha256", "source_files_present", "source_files_absent"} <= set(source_hashes):
        return False
    bindings = dict(plan.bindings)
    for key, value in source_hashes.items():
        expected = digest_payload(value) if key in {
            "source_files_sha256", "source_files_present", "source_files_absent"
        } else canonical_json(value)
        if bindings.get(key) != expected:
            return False
    return True


def _plan_matches_scenario(
    plan: ExecutionPlan,
    scenario_id: str,
    selected_tests: Iterable[str] = (),
    focal_subjects: Iterable[str] = (),
) -> bool:
    bindings = dict(plan.bindings)
    if bindings.get("scenario_id") != scenario_id:
        return False
    if selected_tests and bindings.get("selected_tests") != "\0".join(sorted(set(selected_tests))):
        return False
    if focal_subjects and bindings.get("focal_subjects") != "\0".join(sorted(set(focal_subjects))):
        return False
    return True


def _scenario_environment(
    config: Mapping[str, Any],
    temporary_root: Path,
    scenario_id: str,
) -> dict[str, str]:
    """Build a minimal child environment with an isolated home and temp dir."""
    options = config.get("review_options") if isinstance(config.get("review_options"), Mapping) else {}
    configured = options.get("execution_environment") if isinstance(options, Mapping) else {}
    environment = dict(configured) if isinstance(configured, Mapping) else {}
    environment.setdefault("PATH", os.environ.get("PATH", os.defpath))
    home = temporary_root / "homes" / scenario_id
    temp = temporary_root / "tmp" / scenario_id
    home.mkdir(parents=True, exist_ok=True)
    temp.mkdir(parents=True, exist_ok=True)
    # Repository tests must not observe the caller's credentials or home
    # directory, even when review configuration contains other explicit vars.
    environment["HOME"] = str(home)
    environment["TMPDIR"] = str(temp)
    return environment


def _plan_bindings(
    scenario_id: str,
    source_hashes: Mapping[str, Any],
    *,
    base_revision: str,
    head_revision: str,
    selected_tests: Iterable[str] = (),
    focal_subjects: Iterable[str] = (),
    repository_id: str = "",
) -> tuple[tuple[str, str], ...]:
    bound_hashes = {
        key: digest_payload(value)
        if key in {"source_files_sha256", "source_files_present", "source_files_absent"}
        else canonical_json(value)
        for key, value in source_hashes.items()
    }
    values = {
        "scenario_id": scenario_id,
        "base_revision": base_revision,
        "head_revision": head_revision,
        "selected_tests": "\0".join(sorted(set(selected_tests))),
        "focal_subjects": "\0".join(sorted(set(focal_subjects))),
        "selection_mode": "command_scope_unfiltered",
        "repository_id": repository_id,
    }
    # The source-state fields are already part of the canonical source hash
    # map. Updating a dictionary avoids duplicate binding names while keeping
    # every source fact digest-bound.
    values.update(bound_hashes)
    return tuple(sorted(values.items()))


def _repeat_matrix_runs(
    first: TestRunResult,
    plan: ExecutionPlan,
    approval: str,
    source_hashes: Mapping[str, Any],
    selected: tuple[str, ...],
    repetitions: int,
    output_limit: int,
) -> tuple[TestRunResult, ...]:
    if repetitions <= 1 or not first.completed:
        return ()
    runs = [first]
    for _ in range(1, repetitions):
        error = (
            "source_snapshot_invalid"
            if not _plan_matches_source_hashes(plan, source_hashes)
            else _verify_materialised_sources(plan, source_hashes)
        )
        if error is not None:
            runs.append(TestRunResult(
                first.scenario_id, plan.approval_digest, None, False, None, None,
                selected, "", error,
                first.production_patch_sha256,
                first.test_patch_sha256,
                first.shared_config_patch_sha256,
                first.reachability,
                first.reached_subjects,
            ))
            continue
        completed, execution_error = _execute_plan(plan, approval)
        if completed is None:
            runs.append(TestRunResult(
                first.scenario_id, plan.approval_digest, None, False, None, None,
                selected, "", execution_error or "execution_failed",
                first.production_patch_sha256,
                first.test_patch_sha256,
                first.shared_config_patch_sha256,
                first.reachability,
                first.reached_subjects,
            ))
            continue
        output = redact_sensitive_text(
            (completed.stdout or "")[:output_limit]
            + (completed.stderr or "")[:output_limit]
        )
        collected_tests = _collect_count(output)
        completed_flag, passed, reason_code = _test_outcome(
            completed.returncode,
            collected_tests,
            selected_tests_present=set(selected) <= set(
                source_hashes.get("source_files_present", ())
            ),
        )
        runs.append(TestRunResult(
            first.scenario_id, plan.approval_digest, completed.returncode,
            completed_flag,
            passed,
            collected_tests, selected,
            bounded_fingerprint(output),
            reason_code,
            first.production_patch_sha256,
            first.test_patch_sha256,
            first.shared_config_patch_sha256,
            first.reachability,
            first.reached_subjects,
        ))
    return tuple(runs)


def _repository_id(root: Path) -> str:
    """Bind a plan to the repository identity without retaining raw metadata."""
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        git_dir = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        identity = f"{top.stdout.strip()}\0{git_dir.stdout.strip()}"
        if top.returncode == 0 and git_dir.returncode == 0 and identity != "\0":
            return hashlib.sha256(identity.encode("utf-8", errors="surrogatepass")).hexdigest()
    except (OSError, subprocess.SubprocessError):
        pass
    return hashlib.sha256(root.resolve().as_posix().encode("utf-8", errors="surrogatepass")).hexdigest()


def _is_git_repository(root: Path) -> bool:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and result.stdout.strip() == "true"


def _resolved_revision(root: Path, revision: str) -> str:
    value = revision or "HEAD"
    if value not in {"HEAD", "INDEX", "WORKTREE"}:
        return value
    try:
        result = subprocess.run(
            ["git", "rev-parse", value],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return value
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else value


def _collect_count(output: str) -> int | None:
    patterns = (
        r"(?:collected|Collected)\s+(\d+)\s+items?",
        r"\bRan\s+(\d+)\s+tests?\b",
        r"\bTests?\s*:\s*(\d+)\s+(?:passed|failed|total)\b",
        r"\b(\d+)\s+(?:tests?|specs?)\s+(?:passed|failed|total)\b",
        r"\b(?:test suites?|tests?)\s*[:=]\s*(\d+)\b",
        r"\b(\d+)\s+(?:passed|failed)\b",
    )
    matches = [match for pattern in patterns for match in re.findall(pattern, output)]
    return int(matches[-1]) if matches else None


def _test_outcome(
    return_code: int,
    collected_tests: int | None,
    *,
    selected_tests_present: bool = True,
) -> tuple[bool, bool | None, str | None]:
    """Map a bounded test process result without accepting zero-test success."""
    if return_code == 124:
        return False, None, "test_timeout"
    if not selected_tests_present:
        return True, False, "selected_tests_missing"
    if return_code != 0:
        return True, False, "test_failure"
    if collected_tests == 0:
        return True, False, "zero_tests"
    return True, True, None


def _execute_plan(plan: ExecutionPlan, approval: str) -> tuple[subprocess.CompletedProcess[str] | None, str | None]:
    return execute_approved_plan(plan, approval)


def build_matrix(
    root: Path,
    partition: ChangePartition,
    *,
    config: Mapping[str, Any] | None = None,
    base_contents: Mapping[str, bytes | str] | None = None,
    head_contents: Mapping[str, bytes | str] | None = None,
    base_revision: str = "",
    head_revision: str = "",
    approved_digests: Mapping[str, str] | None = None,
    timeout_seconds: float = 600,
    output_limit: int = 64 * 1024,
    create_plans: bool = True,
    flaky_repetitions: int = 1,
    reachability_by_scenario: Mapping[str, str] | None = None,
    reached_subjects_by_scenario: Mapping[str, Iterable[str]] | None = None,
    focal_subjects_by_scenario: Mapping[str, Iterable[str]] | None = None,
) -> EvidenceMatrix:
    """Build four exact source scenarios; execute only matching approvals."""
    root = root.resolve()
    config = config or {}
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not math.isfinite(float(timeout_seconds)) or timeout_seconds <= 0:
        raise ValueError("matrix timeout must be a finite number greater than zero")
    matrix_deadline = time.monotonic() + float(timeout_seconds)
    if approved_digests is not None:
        unknown_approvals = sorted(set(approved_digests) - set(SCENARIO_IDS))
        if unknown_approvals:
            raise ValueError(f"unknown matrix approval scenario(s): {', '.join(unknown_approvals)}")
    if isinstance(flaky_repetitions, bool) or not isinstance(flaky_repetitions, int) or flaky_repetitions < 1:
        raise ValueError("flaky_repetitions must be a positive integer")
    reachability = dict(reachability_by_scenario or {})
    if any(
        key not in SCENARIO_IDS or value not in REACHABILITY_STATES
        for key, value in reachability.items()
    ):
        raise ValueError("reachability_by_scenario contains an invalid scenario or state")
    reached_subjects = {
        key: tuple(sorted(set(values)))
        for key, values in (reached_subjects_by_scenario or {}).items()
    }
    focal_subjects = {
        key: tuple(sorted(set(values)))
        for key, values in (focal_subjects_by_scenario or {}).items()
    }
    if any(key not in SCENARIO_IDS for key in (*reached_subjects, *focal_subjects)):
        raise ValueError("reachability subject evidence contains an invalid scenario")
    if any(
        any(not isinstance(value, str) or not value for value in values)
        for values in (*reached_subjects.values(), *focal_subjects.values())
    ):
        raise ValueError("reachability subject IDs must be non-empty strings")
    if any(
        not set(reached_subjects.get(key, ())) <= set(focal_subjects.get(key, ()))
        for key in reached_subjects
        if focal_subjects.get(key)
    ):
        raise ValueError("reached subject IDs must be mapped focal subjects")
    if any(
        state == "confirmed" and not reached_subjects.get(key)
        or state == "not_reached" and reached_subjects.get(key)
        for key, state in reachability.items()
    ):
        raise ValueError("reachability state does not match reached subject evidence")
    if any(values and not focal_subjects.get(key) for key, values in reached_subjects.items()):
        raise ValueError("reached subject evidence requires mapped focal subjects")
    selected = _selected_tests(partition)
    if not selected:
        return EvidenceMatrix((), "not_applicable", "no_test_artifacts")
    partition_sets = (
        set(partition.production), set(partition.tests), set(partition.test_support),
        set(partition.shared_configuration), set(partition.documentation_or_generated),
    )
    overlapping_paths = {
        path
        for index, current in enumerate(partition_sets)
        for other in partition_sets[index + 1:]
        for path in current & other
    }
    # A shared configuration file is a first-class snapshot input. It is only
    # ambiguous when partitioning could not decide which semantic side owns a
    # path, or when one path was assigned to multiple partitions.
    configuration_ambiguous = bool(partition.uncertain or overlapping_paths)
    all_paths = tuple(sorted(set(partition.all_paths)))
    production_paths = set(partition.production)
    test_paths = set(partition.tests + partition.test_support + partition.shared_configuration)
    inferred_base: Mapping[str, bytes] = {}
    inferred_head: Mapping[str, bytes] = {}
    if base_contents is None or head_contents is None:
        if base_revision:
            inferred_base = {
                path: value
                for path in all_paths
                if (value := _git_file(root, base_revision, path)) is not None
            }
            inferred_head = {
                path: value
                for path in all_paths
                if (value := _git_file(root, head_revision or "HEAD", path)) is not None
            }
        else:
            local_values = _local_snapshot_values(root, all_paths)
            if local_values is not None:
                inferred_base, inferred_head = local_values
            else:
                inferred_base = inferred_head = _read_tree(root, all_paths)
    base_values = dict(inferred_base if base_contents is None else base_contents)
    head_values = dict(inferred_head if head_contents is None else head_contents)
    base_command_source = _command_from_config(root, config, snapshot_texts=base_values)
    head_command_source = _command_from_config(root, config, snapshot_texts=head_values)
    temporary = tempfile.TemporaryDirectory(prefix="dissect-test-evidence-") if create_plans else None
    temporary_root = Path(temporary.name) if temporary is not None else None
    repository_id = _repository_id(root)
    binding_base_revision = _resolved_revision(root, base_revision)
    binding_head_revision = _resolved_revision(root, head_revision)
    base_source = root
    head_source = root
    source_materialisation_error: str | None = None
    if create_plans and temporary_root is not None:
        if _is_git_repository(root):
            base_source = temporary_root / ".base-source"
            head_source = temporary_root / ".head-source"
            base_is_archived = _archive_revision(root, base_revision or "HEAD", base_source)
            if not base_is_archived:
                source_materialisation_error = "source_snapshot_unavailable"
        # Start every private scenario from an immutable Git tree. Changed
        # files are overlaid below from the exact base/head maps. Copying the
        # live checkout here would leak unrelated worktree files into the
        # matrix and would make an approval depend on mutable state.
        if source_materialisation_error is None and _is_git_repository(root):
            head_is_archived = _archive_revision(root, head_revision or "HEAD", head_source)
            if not head_is_archived:
                source_materialisation_error = "source_snapshot_unavailable"
    scenarios: list[MatrixScenario] = []
    for scenario_id in SCENARIO_IDS:
        production_state, test_state = _scenario_mapping(scenario_id)
        values: dict[str, bytes] = {}
        removed: list[str] = []
        for path in all_paths:
            value = (
                base_values if path in production_paths and production_state == "base"
                else head_values if path in production_paths
                else base_values if path in test_paths and test_state == "base"
                else head_values
            ).get(path)
            if value is None:
                removed.append(path)
            else:
                values[path] = value if isinstance(value, bytes) else value.encode("utf-8", errors="surrogatepass")
        source_hashes = _scenario_hashes(
            {path: values[path] for path in partition.production if path in values},
            {path: values[path] for path in partition.tests + partition.test_support if path in values},
            {path: values[path] for path in partition.shared_configuration if path in values},
            all_values=values,
        )
        source_hashes["base_source_sha256"] = _file_digest(base_values)
        source_hashes["head_source_sha256"] = _file_digest(head_values)
        source_hashes["scenario_source_sha256"] = _file_digest(values)
        source_hashes["source_files_present"] = sorted(values)
        source_hashes["source_files_absent"] = sorted(set(all_paths) - set(values))
        source_hashes["production_source_state"] = production_state
        source_hashes["test_source_state"] = test_state
        command_source = base_command_source if test_state == "base" else head_command_source
        repeated_runs: tuple[TestRunResult, ...] = ()
        if not create_plans or configuration_ambiguous:
            no_plan_reason = (
                "shared_configuration_ambiguous"
                if configuration_ambiguous
                else "command_not_configured" if command_source is None else "not_approved"
            )
            result = TestRunResult(
                scenario_id,
                "",
                None,
                False,
                None,
                None,
                selected,
                "",
                no_plan_reason,
                source_hashes["production_patch_sha256"],
                source_hashes["test_patch_sha256"],
                source_hashes["shared_config_patch_sha256"],
                reachability.get(scenario_id, "unverified"),
                reached_subjects.get(scenario_id, ()),
            )
            scenarios.append(MatrixScenario(
                scenario_id, production_state, test_state, source_hashes, selected,
                None, result, (), focal_subjects.get(scenario_id, ()),
            ))
            continue
        if temporary_root is None:
            raise RuntimeError("matrix planning requires a private temporary root")
        tree = temporary_root / scenario_id
        if source_materialisation_error is not None:
            plan = None
            result = TestRunResult(
                scenario_id, "", None, False, None, None, selected, "",
                source_materialisation_error,
                source_hashes["production_patch_sha256"],
                source_hashes["test_patch_sha256"],
                source_hashes["shared_config_patch_sha256"],
                reachability.get(scenario_id, "unverified"),
                reached_subjects.get(scenario_id, ()),
            )
            scenarios.append(MatrixScenario(
                scenario_id, production_state, test_state, source_hashes, selected,
                plan, result, (), focal_subjects.get(scenario_id, ()),
            ))
            continue
        source_root = base_source if production_state == "base" and test_state == "base" else head_source if production_state == "head" and test_state == "head" else base_source if production_state == "base" else head_source
        _materialise(source_root, tree, values, removed)
        if command_source is None:
            plan = None
            result = TestRunResult(
                scenario_id, "", None, False, None, None, selected, "", "command_not_configured",
                source_hashes["production_patch_sha256"], source_hashes["test_patch_sha256"], source_hashes["shared_config_patch_sha256"],
                reachability.get(scenario_id, "unverified"),
                reached_subjects.get(scenario_id, ()),
            )
        else:
            command, source = command_source
            argv = _command_argv(command)
            bindings = _plan_bindings(
                scenario_id,
                source_hashes,
                base_revision=binding_base_revision,
                head_revision=binding_head_revision,
                selected_tests=selected,
                focal_subjects=focal_subjects.get(scenario_id, ()),
                repository_id=repository_id,
            )
            if argv is None:
                plan = None
                result = TestRunResult(
                    scenario_id, "", None, False, None, None, selected, "", "invalid_test_command",
                    source_hashes["production_patch_sha256"], source_hashes["test_patch_sha256"], source_hashes["shared_config_patch_sha256"],
                    reachability.get(scenario_id, "unverified"),
                    reached_subjects.get(scenario_id, ()),
                )
            else:
                plan, error = build_execution_plan(
                    kind="test-evidence",
                    name=f"{source}:{scenario_id}",
                    argv=argv,
                    working_directory=tree,
                    environment=_scenario_environment(config, temporary_root, scenario_id),
                    timeout_seconds=min(
                        float(timeout_seconds),
                        max(0.001, matrix_deadline - time.monotonic()),
                    ),
                    output_limit=output_limit,
                    bindings=bindings,
                )
                if plan is None:
                    result = TestRunResult(
                        scenario_id, "", None, False, None, None, selected, "", "plan_unavailable",
                        source_hashes["production_patch_sha256"], source_hashes["test_patch_sha256"], source_hashes["shared_config_patch_sha256"],
                        reachability.get(scenario_id, "unverified"),
                        reached_subjects.get(scenario_id, ()),
                    )
                else:
                    approval = (approved_digests or {}).get(scenario_id)
                    if approval is None:
                        result = TestRunResult(
                            scenario_id, plan.approval_digest, None, False, None, None, selected,
                            "", "not_approved",
                            source_hashes["production_patch_sha256"], source_hashes["test_patch_sha256"], source_hashes["shared_config_patch_sha256"],
                            reachability.get(scenario_id, "unverified"),
                            reached_subjects.get(scenario_id, ()),
                        )
                    else:
                        source_error = (
                            "source_snapshot_invalid"
                            if not _plan_matches_source_hashes(plan, source_hashes)
                            else _verify_materialised_sources(plan, source_hashes)
                        )
                        if source_error is not None:
                            result = TestRunResult(
                                scenario_id, plan.approval_digest, None, False, None, None, selected,
                                "", source_error,
                                source_hashes["production_patch_sha256"],
                                source_hashes["test_patch_sha256"],
                                source_hashes["shared_config_patch_sha256"],
                                reachability.get(scenario_id, "unverified"),
                                reached_subjects.get(scenario_id, ()),
                            )
                            scenarios.append(MatrixScenario(
                                scenario_id, production_state, test_state, source_hashes, selected,
                                plan, result, (), focal_subjects.get(scenario_id, ()),
                            ))
                            continue
                        completed, execution_error = _execute_plan(plan, approval)
                        if completed is None:
                            result = TestRunResult(
                                scenario_id, plan.approval_digest, None, False, None, None, selected,
                                "", execution_error or "execution_failed",
                                source_hashes["production_patch_sha256"], source_hashes["test_patch_sha256"], source_hashes["shared_config_patch_sha256"],
                                reachability.get(scenario_id, "unverified"),
                                reached_subjects.get(scenario_id, ()),
                            )
                        else:
                            output = redact_sensitive_text((completed.stdout or "")[:output_limit] + (completed.stderr or "")[:output_limit])
                            collected_tests = _collect_count(output)
                            completed_flag, passed, reason_code = _test_outcome(
                                completed.returncode,
                                collected_tests,
                                selected_tests_present=set(selected) <= set(values),
                            )
                            result = TestRunResult(
                                scenario_id, plan.approval_digest, completed.returncode,
                                completed_flag,
                                passed,
                                collected_tests, selected,
                                bounded_fingerprint(output),
                                reason_code,
                                source_hashes["production_patch_sha256"], source_hashes["test_patch_sha256"], source_hashes["shared_config_patch_sha256"],
                                reachability.get(scenario_id, "unverified"),
                                reached_subjects.get(scenario_id, ()),
                            )
                            repeated_runs = _repeat_matrix_runs(
                                result, plan, approval, source_hashes, selected,
                                flaky_repetitions, output_limit,
                            )
        scenarios.append(MatrixScenario(
            scenario_id, production_state, test_state, source_hashes, selected,
            plan, result, repeated_runs, focal_subjects.get(scenario_id, ()),
        ))
    has_test_evidence_scope = bool(selected)
    applicable = any(item.result.reason_code not in {"command_not_configured", "plan_unavailable"} for item in scenarios)
    complete = all(item.result.completed for item in scenarios) if applicable else False
    baseline = next((item.result for item in scenarios if item.scenario_id == "base-code-base-tests"), None)
    head = next((item.result for item in scenarios if item.scenario_id == "head-code-head-tests"), None)
    flaky = complete and any(
        scenario.repeated_runs
        and flakiness_evidence(scenario.repeated_runs)["status"] != "stable"
        for scenario in scenarios
    )
    dynamic_candidates = (
        *_matrix_candidates(scenarios),
        *_flakiness_candidates(scenarios),
        *_reachability_candidates(scenarios),
    )
    if configuration_ambiguous:
        status, reason = "partial", "shared_configuration_ambiguous"
    elif flaky:
        status, reason = "partial", "flaky_test_evidence"
    elif complete and baseline is not None and baseline.passed is False:
        status, reason = "partial", "baseline_failed"
    elif complete and head is not None and head.passed is False:
        status, reason = "partial", "head_failed"
    elif complete:
        status, reason = "complete", None
    elif applicable:
        source_reasons = {
            "source_snapshot_changed", "source_snapshot_invalid", "source_snapshot_unavailable"
        }
        source_reason = next(
            (item.result.reason_code for item in scenarios if item.result.reason_code in source_reasons),
            None,
        )
        unapproved = any(item.result.reason_code == "not_approved" for item in scenarios)
        status, reason = (
            ("partial", source_reason)
            if source_reason is not None else
            ("planned", "not_approved") if unapproved else
            ("partial", "scenario_not_verified")
        )
    elif has_test_evidence_scope:
        status, reason = "unavailable", "command_not_configured"
    else:
        status, reason = "not_applicable", "command_not_configured"
    return EvidenceMatrix(tuple(scenarios), status, reason, temporary, configuration_ambiguous, dynamic_candidates)


def execute_approved_matrix(
    matrix: EvidenceMatrix,
    approved_digests: Mapping[str, str],
    *,
    output_limit: int = 64 * 1024,
    flaky_repetitions: int = 1,
    reachability_by_scenario: Mapping[str, str] | None = None,
    reached_subjects_by_scenario: Mapping[str, Iterable[str]] | None = None,
) -> EvidenceMatrix:
    """Execute plans already returned by :func:`build_matrix`.

    Keeping planning and execution separate lets a trusted caller inspect the
    exact redacted plans before approving them without rebuilding temporary
    trees and changing their approval digests.
    """
    if isinstance(flaky_repetitions, bool) or not isinstance(flaky_repetitions, int) or flaky_repetitions < 1:
        raise ValueError("flaky_repetitions must be a positive integer")
    reachability = dict(reachability_by_scenario or {})
    reached_subjects = {
        key: tuple(sorted(set(values)))
        for key, values in (reached_subjects_by_scenario or {}).items()
    }
    if any(
        key not in SCENARIO_IDS or value not in REACHABILITY_STATES
        for key, value in reachability.items()
    ) or any(key not in SCENARIO_IDS for key in reached_subjects):
        raise ValueError("reachability evidence contains an invalid scenario or state")
    if any(
        any(not isinstance(value, str) or not value for value in values)
        for values in reached_subjects.values()
    ):
        raise ValueError("reached subject IDs must be non-empty strings")
    for scenario in matrix.scenarios:
        if reached_subjects.get(scenario.scenario_id) and not scenario.focal_subjects:
            raise ValueError("reached subject evidence requires mapped focal subjects")
        if scenario.scenario_id in reached_subjects and scenario.focal_subjects and not set(
            reached_subjects[scenario.scenario_id]
        ) <= set(scenario.focal_subjects):
            raise ValueError("reached subject IDs must be mapped focal subjects")
        if scenario.scenario_id in reachability:
            state = reachability[scenario.scenario_id]
            reached = reached_subjects.get(scenario.scenario_id, scenario.result.reached_subjects)
            if state == "confirmed" and not reached or state == "not_reached" and reached:
                raise ValueError("reachability state does not match reached subject evidence")
    unknown_approvals = sorted(set(approved_digests) - set(SCENARIO_IDS))
    if unknown_approvals:
        raise ValueError(f"unknown matrix approval scenario(s): {', '.join(unknown_approvals)}")
    scenarios: list[MatrixScenario] = []
    for scenario in matrix.scenarios:
        plan = scenario.plan
        result = scenario.result
        if matrix.ambiguous_configuration:
            scenarios.append(MatrixScenario(
                scenario.scenario_id,
                scenario.production_state,
                scenario.test_state,
                scenario.source_hashes,
                scenario.selected_tests,
                None,
                TestRunResult(
                    scenario.scenario_id,
                    result.command_plan_digest,
                    None,
                    False,
                    None,
                    None,
                    scenario.selected_tests,
                    "",
                    "shared_configuration_ambiguous",
                    result.production_patch_sha256,
                    result.test_patch_sha256,
                    result.shared_config_patch_sha256,
                    "unverified",
                    (),
                ),
                (),
                scenario.focal_subjects,
            ))
            continue
        if plan is None:
            scenarios.append(scenario)
            continue
        approval = approved_digests.get(scenario.scenario_id)
        if approval is None:
            result = TestRunResult(
                scenario.scenario_id,
                plan.approval_digest,
                None,
                False,
                None,
                None,
                scenario.selected_tests,
                "",
                "not_approved",
                result.production_patch_sha256,
                result.test_patch_sha256,
                result.shared_config_patch_sha256,
                result.reachability,
                result.reached_subjects,
            )
        else:
            source_error = (
                "scenario_plan_mismatch"
                if plan.kind != "test-evidence"
                or result.command_plan_digest not in {"", plan.approval_digest}
                or not _plan_matches_scenario(
                    plan,
                    scenario.scenario_id,
                    scenario.selected_tests,
                    scenario.focal_subjects,
                )
                else "source_snapshot_invalid"
                if not _plan_matches_source_hashes(plan, scenario.source_hashes)
                else _verify_materialised_sources(plan, scenario.source_hashes)
            )
            if source_error is not None:
                completed, error = None, source_error
            else:
                completed, error = execute_approved_plan(plan, approval)
            if completed is None:
                result = TestRunResult(
                    scenario.scenario_id,
                    plan.approval_digest,
                    None,
                    False,
                    None,
                    None,
                    scenario.selected_tests,
                    "",
                    error or "execution_failed",
                    result.production_patch_sha256,
                    result.test_patch_sha256,
                    result.shared_config_patch_sha256,
                    result.reachability,
                    result.reached_subjects,
                )
            else:
                output = redact_sensitive_text(
                    ((completed.stdout or "") + (completed.stderr or ""))[:output_limit]
                )
                collected_tests = _collect_count(output)
                completed_flag, passed, reason_code = _test_outcome(
                    completed.returncode,
                    collected_tests,
                    selected_tests_present=set(scenario.selected_tests) <= set(
                        scenario.source_hashes.get("source_files_present", ())
                    ),
                )
                result = TestRunResult(
                    scenario.scenario_id,
                    plan.approval_digest,
                    completed.returncode,
                    completed_flag,
                    passed,
                    collected_tests,
                    scenario.selected_tests,
                    bounded_fingerprint(output),
                    reason_code,
                    result.production_patch_sha256,
                    result.test_patch_sha256,
                    result.shared_config_patch_sha256,
                    reachability.get(scenario.scenario_id, result.reachability),
                    reached_subjects.get(scenario.scenario_id, result.reached_subjects),
                )
        repeated_runs = scenario.repeated_runs
        if result.completed and plan is not None and approval is not None:
            repeated_runs = _repeat_matrix_runs(
                result,
                plan,
                approval,
                scenario.source_hashes,
                scenario.selected_tests,
                flaky_repetitions,
                output_limit,
            )
        scenarios.append(MatrixScenario(
            scenario.scenario_id,
            scenario.production_state,
            scenario.test_state,
            scenario.source_hashes,
            scenario.selected_tests,
            plan,
            result,
            repeated_runs,
            scenario.focal_subjects,
        ))
    matrix.scenarios = tuple(scenarios)
    if not scenarios:
        matrix.status, matrix.reason_code = "not_applicable", "no_test_artifacts"
    elif any(item.result.reason_code == "scenario_plan_mismatch" for item in scenarios):
        matrix.status, matrix.reason_code = "partial", "scenario_plan_mismatch"
    elif any(item.result.reason_code in {"source_snapshot_changed", "source_snapshot_invalid"} for item in scenarios):
        matrix.status, matrix.reason_code = "partial", "source_snapshot_changed"
    elif any(item.result.reason_code == "source_snapshot_unavailable" for item in scenarios):
        matrix.status = "partial"
        matrix.reason_code = next(
            item.result.reason_code for item in scenarios
            if item.result.reason_code == "source_snapshot_unavailable"
        )
    elif matrix.ambiguous_configuration:
        matrix.status, matrix.reason_code = "partial", "shared_configuration_ambiguous"
    elif not all(item.result.completed for item in scenarios):
        matrix.status, matrix.reason_code = "planned", "not_approved"
    elif any(item.scenario_id == "base-code-base-tests" and item.result.passed is False for item in scenarios):
        matrix.status, matrix.reason_code = "partial", "baseline_failed"
    elif any(item.scenario_id == "head-code-head-tests" and item.result.passed is False for item in scenarios):
        matrix.status, matrix.reason_code = "partial", "head_failed"
    else:
        matrix.status, matrix.reason_code = "complete", None
    matrix.dynamic_candidates = (
        *_matrix_candidates(scenarios),
        *_flakiness_candidates(scenarios),
        *_reachability_candidates(scenarios),
    )
    return matrix


build_evidence_matrix = build_matrix
run_approved_matrix = execute_approved_matrix
