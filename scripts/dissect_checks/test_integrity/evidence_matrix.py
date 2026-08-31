"""Approval-bound base/head test evidence matrix."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tarfile
from typing import Any, Iterable, Mapping

from dissect_checks.execution_plan import ExecutionPlan, build_execution_plan, execute_approved_plan
from dissect_checks.redaction import redact_sensitive_text
from .change_analysis import ChangePartition
from .model import SCENARIO_IDS, TestRunResult, bounded_fingerprint, canonical_json, sha256_bytes


MAX_SOURCE_FILE_BYTES = 5 * 1024 * 1024


@dataclass(frozen=True)
class MatrixScenario:
    scenario_id: str
    production_state: str
    test_state: str
    source_hashes: Mapping[str, Any]
    selected_tests: tuple[str, ...]
    plan: ExecutionPlan | None
    result: TestRunResult

    def as_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "production_state": self.production_state,
            "test_state": self.test_state,
            "source_hashes": dict(sorted(self.source_hashes.items())),
            "selected_tests": list(self.selected_tests),
            "plan": self.plan.redacted_payload() if self.plan is not None else None,
            "result": self.result.as_dict(),
        }


@dataclass
class EvidenceMatrix:
    scenarios: tuple[MatrixScenario, ...]
    status: str
    reason_code: str | None = None
    _temporary: tempfile.TemporaryDirectory[str] | None = None
    ambiguous_configuration: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason_code": self.reason_code,
            "ambiguous_configuration": self.ambiguous_configuration,
            "interpretation": interpret_matrix(self.scenarios),
            "scenarios": [scenario.as_dict() for scenario in self.scenarios],
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
    by_id = {item.scenario_id: item.result for item in scenarios}
    if set(by_id) != set(SCENARIO_IDS):
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
    return {
        "run_count": len(values),
        "pass_count": passes,
        "fail_count": failures,
        "seeds": list(seeds),
        "order_settings": list(order_settings),
        "output_fingerprints": list(fingerprints),
        "stable": stable,
        "status": "stable" if stable else "flaky" if verified else "not_verified",
    }


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


def _materialise(source_root: Path, destination: Path, overrides: Mapping[str, bytes], removed: Iterable[str] = ()) -> None:
    ignore = shutil.ignore_patterns(
        ".git", "node_modules", "__pycache__", "*.pyc", ".venv", "target",
        ".env", ".env.*", "*.pem", "*.key", "credentials.json", "secrets.json",
    )
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
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def _archive_revision(root: Path, revision: str, destination: Path) -> bool:
    """Materialise a Git revision without capturing an unbounded tar stream."""
    if not revision:
        return False
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination.parent / f"{destination.name}.tar"
    try:
        with archive.open("wb") as handle:
            result = subprocess.run(
                ["git", "archive", "--format=tar", revision],
                cwd=root,
                stdout=handle,
                stderr=subprocess.PIPE,
                check=False,
            )
        if result.returncode != 0:
            return False
        with tarfile.open(archive, mode="r:") as bundle:
            root_resolved = destination.resolve()
            for member in bundle.getmembers():
                member_path = (destination / member.name).resolve()
                if not member_path.is_relative_to(root_resolved):
                    return False
            if sys.version_info >= (3, 12):
                bundle.extractall(destination, filter="data")
            else:
                bundle.extractall(destination)
        return True
    except (OSError, tarfile.TarError):
        return False
    finally:
        try:
            archive.unlink()
        except FileNotFoundError:
            pass


def _command_from_config(root: Path, config: Mapping[str, Any]) -> tuple[str, str] | None:
    options = config.get("review_options") if isinstance(config.get("review_options"), Mapping) else {}
    commands = config.get("commands") if isinstance(config.get("commands"), Mapping) else {}
    explicit = commands.get("test") or options.get("test_command")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip(), "review configuration"
    workflow_command = _repository_ci_test_command(root)
    if workflow_command is not None:
        return workflow_command, "repository CI configuration"
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


def _repository_ci_test_command(root: Path) -> str | None:
    """Find an existing plain test command without inventing framework flags."""
    workflow_root = root / ".github" / "workflows"
    try:
        workflow_paths = sorted(workflow_root.glob("*.y*ml"))
    except OSError:
        return None
    patterns = (
        re.compile(r"^python(?:3)?\s+-m\s+unittest\b[^\r\n]*$"),
        re.compile(r"^(?:python(?:3)?\s+-m\s+pytest|pytest)\b[^\r\n]*$"),
        re.compile(r"^(?:npm|pnpm|yarn)\s+(?:run\s+)?test\b[^\r\n]*$"),
        re.compile(r"^go\s+test\b[^\r\n]*$"),
        re.compile(r"^cargo\s+test\b[^\r\n]*$"),
    )
    for path in workflow_paths:
        try:
            if path.stat().st_size > 1024 * 1024:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
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


def _scenario_hashes(production: Mapping[str, bytes], tests: Mapping[str, bytes], config: Mapping[str, bytes]) -> dict[str, Any]:
    files = {**production, **tests, **config}
    return {
        "production_patch_sha256": _file_digest(production),
        "test_patch_sha256": _file_digest(tests),
        "shared_config_patch_sha256": _file_digest(config),
        "source_files_sha256": {path: sha256_bytes(value) for path, value in sorted(files.items())},
    }


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
    repository_id: str = "",
) -> tuple[tuple[str, str], ...]:
    bound_hashes = {
        key: canonical_json(value) if isinstance(value, Mapping) else str(value)
        for key, value in source_hashes.items()
    }
    return tuple(sorted({
        ("scenario_id", scenario_id),
        ("base_revision", base_revision),
        ("head_revision", head_revision),
        ("selected_tests", "\0".join(sorted(set(selected_tests)))),
        ("selection_mode", "command_scope_unfiltered"),
        ("repository_id", repository_id),
        ("production_source_state", source_hashes.get("production_source_state", "")),
        ("test_source_state", source_hashes.get("test_source_state", "")),
        *bound_hashes.items(),
    }))


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


def _collect_count(output: str) -> int | None:
    matches = re.findall(r"(?:collected|Collected)\s+(\d+)\s+items?", output)
    return int(matches[-1]) if matches else None


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
) -> EvidenceMatrix:
    """Build four exact source scenarios; execute only matching approvals."""
    root = root.resolve()
    config = config or {}
    command_source = _command_from_config(root, config)
    selected = _selected_tests(partition)
    if not selected:
        return EvidenceMatrix((), "not_applicable", "no_test_artifacts")
    all_paths = tuple(sorted(set(partition.all_paths)))
    production_paths = set(partition.production)
    test_paths = set(partition.tests + partition.test_support + partition.shared_configuration)
    base_values = dict(_read_tree(root, all_paths) if base_contents is None else base_contents)
    head_values = dict(_read_tree(root, all_paths) if head_contents is None else head_contents)
    if base_contents is None and not base_values:
        base_values = dict(head_values)
    temporary = tempfile.TemporaryDirectory(prefix="dissect-test-evidence-") if create_plans else None
    temporary_root = Path(temporary.name) if temporary is not None else None
    repository_id = _repository_id(root)
    base_source = root
    head_source = root
    if create_plans and temporary_root is not None:
        base_source = temporary_root / ".base-source"
        head_source = temporary_root / ".head-source"
        base_is_archived = _archive_revision(root, base_revision or "HEAD", base_source)
        if not base_is_archived:
            base_source = root
        if base_revision:
            head_is_archived = _archive_revision(root, head_revision or "HEAD", head_source)
            if not head_is_archived:
                head_source = root
        else:
            head_source = root
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
        )
        source_hashes["base_source_sha256"] = _file_digest(base_values)
        source_hashes["head_source_sha256"] = _file_digest(head_values)
        source_hashes["scenario_source_sha256"] = _file_digest(values)
        source_hashes["production_source_state"] = production_state
        source_hashes["test_source_state"] = test_state
        if not create_plans:
            result = TestRunResult(
                scenario_id,
                "",
                None,
                False,
                None,
                None,
                selected,
                "",
                "command_not_configured" if command_source is None else "not_approved",
                source_hashes["production_patch_sha256"],
                source_hashes["test_patch_sha256"],
                source_hashes["shared_config_patch_sha256"],
            )
            scenarios.append(MatrixScenario(scenario_id, production_state, test_state, source_hashes, selected, None, result))
            continue
        if temporary_root is None:
            raise RuntimeError("matrix planning requires a private temporary root")
        tree = temporary_root / scenario_id
        source_root = base_source if production_state == "base" and test_state == "base" else head_source if production_state == "head" and test_state == "head" else base_source if production_state == "base" else head_source
        _materialise(source_root, tree, values, removed)
        if command_source is None:
            plan = None
            result = TestRunResult(
                scenario_id, "", None, False, None, None, selected, "", "command_not_configured",
                source_hashes["production_patch_sha256"], source_hashes["test_patch_sha256"], source_hashes["shared_config_patch_sha256"],
            )
        else:
            command, source = command_source
            argv = _command_argv(command)
            bindings = _plan_bindings(
                scenario_id,
                source_hashes,
                base_revision=base_revision,
                head_revision=head_revision,
                selected_tests=selected,
                repository_id=repository_id,
            )
            if argv is None:
                plan = None
                result = TestRunResult(
                    scenario_id, "", None, False, None, None, selected, "", "invalid_test_command",
                    source_hashes["production_patch_sha256"], source_hashes["test_patch_sha256"], source_hashes["shared_config_patch_sha256"],
                )
            else:
                plan, error = build_execution_plan(
                    kind="test-evidence",
                    name=f"{source}:{scenario_id}",
                    argv=argv,
                    working_directory=tree,
                    environment=_scenario_environment(config, temporary_root, scenario_id),
                    timeout_seconds=timeout_seconds,
                    output_limit=output_limit,
                    bindings=bindings,
                )
                if plan is None:
                    result = TestRunResult(
                        scenario_id, "", None, False, None, None, selected, "", "plan_unavailable",
                        source_hashes["production_patch_sha256"], source_hashes["test_patch_sha256"], source_hashes["shared_config_patch_sha256"],
                    )
                else:
                    approval = (approved_digests or {}).get(scenario_id)
                    if approval is None:
                        result = TestRunResult(
                            scenario_id, plan.approval_digest, None, False, None, None, selected,
                            "", "not_approved",
                            source_hashes["production_patch_sha256"], source_hashes["test_patch_sha256"], source_hashes["shared_config_patch_sha256"],
                        )
                    else:
                        completed, execution_error = _execute_plan(plan, approval)
                        if completed is None:
                            result = TestRunResult(
                                scenario_id, plan.approval_digest, None, False, None, None, selected,
                                "", execution_error or "execution_failed",
                                source_hashes["production_patch_sha256"], source_hashes["test_patch_sha256"], source_hashes["shared_config_patch_sha256"],
                            )
                        else:
                            output = redact_sensitive_text((completed.stdout or "")[:output_limit] + (completed.stderr or "")[:output_limit])
                            result = TestRunResult(
                                scenario_id, plan.approval_digest, completed.returncode, True,
                                completed.returncode == 0, _collect_count(output), selected,
                                bounded_fingerprint(output), None if completed.returncode == 0 else "test_failure",
                                source_hashes["production_patch_sha256"], source_hashes["test_patch_sha256"], source_hashes["shared_config_patch_sha256"],
                            )
        scenarios.append(MatrixScenario(scenario_id, production_state, test_state, source_hashes, selected, plan, result))
    has_test_evidence_scope = bool(selected)
    applicable = any(item.result.reason_code not in {"command_not_configured", "plan_unavailable"} for item in scenarios)
    complete = all(item.result.completed for item in scenarios) if applicable else False
    baseline = next((item.result for item in scenarios if item.scenario_id == "base-code-base-tests"), None)
    head = next((item.result for item in scenarios if item.scenario_id == "head-code-head-tests"), None)
    if partition.shared_configuration:
        status, reason = "partial", "shared_configuration_ambiguous"
    elif complete and baseline is not None and baseline.passed is False:
        status, reason = "partial", "baseline_failed"
    elif complete and head is not None and head.passed is False:
        status, reason = "partial", "head_failed"
    elif complete:
        status, reason = "complete", None
    elif applicable:
        unapproved = any(item.result.reason_code == "not_approved" for item in scenarios)
        status, reason = ("planned", "not_approved") if unapproved else ("partial", "scenario_not_verified")
    elif has_test_evidence_scope:
        status, reason = "unavailable", "command_not_configured"
    else:
        status, reason = "not_applicable", "command_not_configured"
    return EvidenceMatrix(tuple(scenarios), status, reason, temporary, bool(partition.shared_configuration))


def execute_approved_matrix(
    matrix: EvidenceMatrix,
    approved_digests: Mapping[str, str],
    *,
    output_limit: int = 64 * 1024,
) -> EvidenceMatrix:
    """Execute plans already returned by :func:`build_matrix`.

    Keeping planning and execution separate lets a trusted caller inspect the
    exact redacted plans before approving them without rebuilding temporary
    trees and changing their approval digests.
    """
    scenarios: list[MatrixScenario] = []
    for scenario in matrix.scenarios:
        plan = scenario.plan
        result = scenario.result
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
            )
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
                )
            else:
                output = redact_sensitive_text(
                    ((completed.stdout or "") + (completed.stderr or ""))[:output_limit]
                )
                result = TestRunResult(
                    scenario.scenario_id,
                    plan.approval_digest,
                    completed.returncode,
                    True,
                    completed.returncode == 0,
                    _collect_count(output),
                    scenario.selected_tests,
                    bounded_fingerprint(output),
                    None if completed.returncode == 0 else "test_failure",
                    result.production_patch_sha256,
                    result.test_patch_sha256,
                    result.shared_config_patch_sha256,
                )
        scenarios.append(MatrixScenario(
            scenario.scenario_id,
            scenario.production_state,
            scenario.test_state,
            scenario.source_hashes,
            scenario.selected_tests,
            plan,
            result,
        ))
    matrix.scenarios = tuple(scenarios)
    if not scenarios:
        matrix.status, matrix.reason_code = "not_applicable", "no_test_artifacts"
    elif not all(item.result.completed for item in scenarios):
        matrix.status, matrix.reason_code = "planned", "not_approved"
    elif matrix.ambiguous_configuration:
        matrix.status, matrix.reason_code = "partial", "shared_configuration_ambiguous"
    elif any(item.scenario_id == "base-code-base-tests" and item.result.passed is False for item in scenarios):
        matrix.status, matrix.reason_code = "partial", "baseline_failed"
    elif any(item.scenario_id == "head-code-head-tests" and item.result.passed is False for item in scenarios):
        matrix.status, matrix.reason_code = "partial", "head_failed"
    else:
        matrix.status, matrix.reason_code = "complete", None
    return matrix


build_evidence_matrix = build_matrix
run_approved_matrix = execute_approved_matrix
