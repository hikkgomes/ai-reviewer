#!/usr/bin/env python3
"""Validate bounded test-integrity evidence records."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from review_ledger import validate_candidate
from dissect_checks.test_integrity.model import ARTIFACT_ROLES, SCENARIO_IDS, PUBLIC_STATES, INTERNAL_STATES

TEST_RULE_IDS = {f"GOV-TESTS-{index:03d}" for index in range(1, 11)}
ORACLE_KINDS = {"user_intent", "public_contract", "existing_invariant", "external_spec", "independent_reference"}


def _safe_relative_path(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    path = Path(value.replace("\\", "/"))
    return not path.is_absolute() and bool(path.parts) and ".." not in path.parts


def _forbidden_output(value: Any, path: str = "") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            name = str(key).lower()
            current = f"{path}.{key}" if path else str(key)
            if name in {"stdout", "stderr", "raw_output", "command_output", "raw_patch", "full_patch"}:
                errors.append(f"unbounded command or patch output is not allowed: {current}")
            errors.extend(_forbidden_output(child, current))
    elif isinstance(value, list):
        if path.lower() == "environment" or path.lower().endswith(".environment"):
            for item in value:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name", "")).lower()
                value_text = item.get("value")
                if any(token in name for token in ("token", "secret", "password", "private_key", "api_key", "access_key")) and not (
                    isinstance(value_text, str) and value_text.startswith("[REDACTED")
                ):
                    errors.append(f"raw secret-bearing environment value is not allowed: {path}")
        if path.lower() == "bindings" or path.lower().endswith(".bindings"):
            for item in value:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name", "")).lower()
                value_text = item.get("value")
                if (
                    any(token in name for token in ("token", "secret", "password", "private_key", "api_key", "access_key"))
                    and not (isinstance(value_text, str) and value_text.startswith("[REDACTED"))
                ):
                    errors.append(f"raw secret-bearing execution binding is not allowed: {path}")
        for index, child in enumerate(value):
            errors.extend(_forbidden_output(child, f"{path}[{index}]"))
    return errors


def _hash(value: Any, *, allow_empty: bool = False) -> bool:
    return (
        (allow_empty and value == "")
        or isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _count_record(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{name} must be an object")
        return
    values = {key: value.get(key) for key in ("applicable_files", "checked_files", "skipped_files")}
    for key, item in values.items():
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            errors.append(f"{name}.{key} must be a non-negative integer")
    if all(isinstance(item, int) and not isinstance(item, bool) and item >= 0 for item in values.values()):
        if values["checked_files"] > values["applicable_files"]:
            errors.append(f"{name}.checked_files exceeds applicable_files")
        if values["checked_files"] + values["skipped_files"] > values["applicable_files"]:
            errors.append(f"{name}.checked_files plus skipped_files exceeds applicable_files")


def _validate_run_result(value: Any, scenario_id: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"matrix scenario {scenario_id} requires a result")
        return
    if value.get("scenario_id") != scenario_id:
        errors.append(f"matrix scenario {scenario_id} result ID does not match")
    completed = value.get("completed")
    passed = value.get("passed")
    if not isinstance(completed, bool):
        errors.append(f"matrix scenario {scenario_id} completed must be boolean")
    elif completed and not isinstance(passed, bool):
        errors.append(f"matrix scenario {scenario_id} completed result needs boolean passed")
    elif not completed and passed is not None:
        errors.append(f"matrix scenario {scenario_id} incomplete result must not have passed")
    exit_code = value.get("exit_code")
    if exit_code is not None and (isinstance(exit_code, bool) or not isinstance(exit_code, int)):
        errors.append(f"matrix scenario {scenario_id} exit_code must be an integer or null")
    if completed and (isinstance(exit_code, bool) or not isinstance(exit_code, int)):
        errors.append(f"matrix scenario {scenario_id} completed result needs an integer exit_code")
    collected = value.get("collected_tests")
    if collected is not None and (isinstance(collected, bool) or not isinstance(collected, int) or collected < 0):
        errors.append(f"matrix scenario {scenario_id} collected_tests must be non-negative")
    selected = value.get("selected_tests")
    if not isinstance(selected, list) or not all(isinstance(item, str) and item for item in selected):
        errors.append(f"matrix scenario {scenario_id} selected_tests must contain non-empty strings")
    reachability = value.get("reachability", "unverified")
    if reachability not in {"confirmed", "not_reached", "unverified"}:
        errors.append(f"matrix scenario {scenario_id} reachability has an invalid state")
    reached = value.get("reached_subjects", [])
    if not isinstance(reached, list) or not all(isinstance(item, str) and item for item in reached):
        errors.append(f"matrix scenario {scenario_id} reached_subjects must be an array of non-empty strings")
    elif reachability == "confirmed" and not reached:
        errors.append(f"matrix scenario {scenario_id} confirmed reachability requires reached subjects")
    elif reachability == "not_reached" and reached:
        errors.append(f"matrix scenario {scenario_id} not_reached result cannot contain reached subjects")
    for key in ("command_plan_digest", "output_fingerprint", "production_patch_sha256", "test_patch_sha256", "shared_config_patch_sha256"):
        if key in value and not _hash(value[key], allow_empty=True):
            errors.append(f"matrix scenario {scenario_id} has an invalid {key}")
    if completed:
        if not _hash(value.get("command_plan_digest")):
            errors.append(f"matrix scenario {scenario_id} completed result requires an approval plan digest")
        if not _hash(value.get("output_fingerprint")):
            errors.append(f"matrix scenario {scenario_id} completed result requires an output fingerprint")


def _validate_mutation_record(
    mutation: Any,
    label: str,
    errors: list[str],
    subject_ids: set[str],
    mutation_ids: set[str],
    *,
    allow_existing_id: bool = False,
) -> None:
    if not isinstance(mutation, dict):
        errors.append(f"{label} must be an object")
        return
    identifier = mutation.get("mutation_id")
    if not isinstance(identifier, str) or not identifier:
        errors.append(f"{label} id is required")
    elif identifier in mutation_ids and not allow_existing_id:
        errors.append(f"duplicate mutation id: {identifier}")
    else:
        mutation_ids.add(identifier)
    if not isinstance(mutation.get("mutation_kind"), str) or not mutation.get("mutation_kind"):
        errors.append(f"{label} mutation_kind is required")
    if not _hash(mutation.get("patch_sha256")):
        errors.append(f"{label} has an invalid patch hash")
    for key in ("command_plan_digest", "build_command_plan_digest"):
        if key in mutation and not _hash(mutation.get(key), allow_empty=True):
            errors.append(f"{label} has an invalid {key}")
    subject = mutation.get("subject")
    if not isinstance(subject, dict):
        errors.append(f"{label} requires a subject")
    else:
        subject_id = subject.get("id")
        if not isinstance(subject_id, str) or not subject_id:
            errors.append(f"{label} subject requires an ID")
        elif subject_id not in subject_ids:
            errors.append(f"{label} references unknown test subject: {subject_id}")
        if not _safe_relative_path(subject.get("logical_path")):
            errors.append(f"{label} subject path must be repository-relative")
        if not _hash(subject.get("content_sha256")):
            errors.append(f"{label} subject has an invalid content hash")
    build_valid = mutation.get("build_valid")
    killed = mutation.get("killed")
    killing_tests = mutation.get("killing_tests")
    if build_valid is not None and not isinstance(build_valid, bool):
        errors.append(f"{label} build_valid must be boolean or null")
    if killed is not None and not isinstance(killed, bool):
        errors.append(f"{label} killed must be boolean or null")
    if build_valid is not True and killed is not None:
        errors.append(f"{label} has a killed result without a valid build")
    if not isinstance(killing_tests, list) or not all(isinstance(item, str) and item for item in killing_tests):
        errors.append(f"{label} killing_tests must be an array of non-empty strings")
    elif killed is not True and killing_tests:
        errors.append(f"{label} has killing tests without a killed result")
    if killed is not None and not _hash(mutation.get("command_plan_digest")):
        errors.append(f"{label} executed result requires a command plan digest")


def _validate_header(data: dict[str, Any], errors: list[str]) -> bool:
    if data.get("status") not in INTERNAL_STATES:
        errors.append("invalid internal test evidence status")
    if data.get("state") not in PUBLIC_STATES:
        errors.append("invalid public test evidence state")
    arrays = ("artifacts", "subjects", "relations", "changes", "static_candidates", "dynamic_candidates", "matrix", "mutations", "proof_tests")
    for key in arrays:
        if not isinstance(data.get(key), list):
            errors.append(f"{key} must be an array")
    artifacts = data.get("artifacts")
    test_artifacts_present = any(
        isinstance(item, dict) and item.get("role") in ARTIFACT_ROLES - {"production source", "test tooling", "shared build or manifest file", "documentation"}
        for item in artifacts
    ) if isinstance(artifacts, list) else False
    if data.get("status") == "not_applicable" and data.get("state") != "Not applicable":
        errors.append("not_applicable test evidence must use the Not applicable public state")
    if data.get("status") == "not_applicable" and (
        test_artifacts_present
        or any(data.get(key) for key in ("relations", "changes", "static_candidates", "matrix", "mutations", "proof_tests") if isinstance(data.get(key), list))
    ):
        errors.append("not_applicable test evidence cannot contain applicable records")
    if data.get("status") == "complete" and data.get("state") != "Checked":
        errors.append("complete test evidence must use the Checked public state")
    if data.get("status") in {"partial", "planned", "unavailable", "failed"} and data.get("state") != "Not verified":
        errors.append("incomplete test evidence must use the Not verified public state")
    return test_artifacts_present


def _validate_artifacts(data: dict[str, Any], errors: list[str]) -> set[str]:
    artifact_ids: set[str] = set()
    artifacts = data.get("artifacts", []) if isinstance(data.get("artifacts"), list) else []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            errors.append("test artefact must be an object")
            continue
        identifier = artifact.get("id")
        if not isinstance(identifier, str) or not identifier:
            errors.append("test artefact id is required")
        elif identifier in artifact_ids:
            errors.append(f"duplicate test artefact id: {identifier}")
        else:
            artifact_ids.add(identifier)
        for key in ("logical_path", "framework_id", "role", "source_kind"):
            if not isinstance(artifact.get(key), str) or not artifact[key]:
                errors.append(f"test artefact {identifier or '<missing>'} requires {key}")
        if artifact.get("role") not in ARTIFACT_ROLES:
            errors.append(f"test artefact {identifier or '<missing>'} has an unrecognised role")
        if not _hash(artifact.get("content_sha256", "")):
            errors.append(f"invalid test artefact hash: {identifier}")
        if not _safe_relative_path(artifact.get("logical_path")):
            errors.append(f"test artefact {identifier or '<missing>'} path must be repository-relative")
        classification = artifact.get("classification_evidence")
        if not isinstance(classification, list) or not classification or not all(isinstance(item, str) and item for item in classification):
            errors.append(f"test artefact {identifier or '<missing>'} classification evidence must be a non-empty array of strings")
    return artifact_ids


def _validate_subjects(data: dict[str, Any], errors: list[str]) -> set[str]:
    subject_ids: set[str] = set()
    subjects = data.get("subjects", []) if isinstance(data.get("subjects"), list) else []
    for subject in subjects:
        if not isinstance(subject, dict):
            errors.append("test subject must be an object")
            continue
        identifier = subject.get("id")
        if not isinstance(identifier, str) or not identifier:
            errors.append("test subject id is required")
        elif identifier in subject_ids:
            errors.append(f"duplicate test subject id: {identifier}")
        else:
            subject_ids.add(identifier)
        if not isinstance(subject.get("logical_path"), str) or not subject.get("logical_path"):
            errors.append(f"test subject {identifier or '<missing>'} requires a path")
        if not isinstance(subject.get("qualified_name"), str) or not subject.get("qualified_name"):
            errors.append(f"test subject {identifier or '<missing>'} requires a qualified name")
        start_line = subject.get("start_line")
        if isinstance(start_line, bool) or not isinstance(start_line, int) or start_line < 1:
            errors.append(f"test subject {identifier or '<missing>'} has an invalid start line")
        end_line = subject.get("end_line")
        if isinstance(end_line, bool) or not isinstance(end_line, int) or end_line < (start_line if isinstance(start_line, int) and not isinstance(start_line, bool) else 1):
            errors.append(f"test subject {identifier or '<missing>'} has an invalid end line")
        if not _hash(subject.get("content_sha256")):
            errors.append(f"invalid test subject hash: {identifier}")
        if not _safe_relative_path(subject.get("logical_path")):
            errors.append(f"test subject {identifier or '<missing>'} path must be repository-relative")
    return subject_ids


def _validate_mutations(data: dict[str, Any], errors: list[str], subject_ids: set[str]) -> tuple[set[str], dict[str, str]]:
    mutation_ids: set[str] = set()
    mutation_records: dict[str, str] = {}
    mutations = data.get("mutations", []) if isinstance(data.get("mutations"), list) else []
    for mutation in mutations:
        _validate_mutation_record(mutation, "mutation", errors, subject_ids, mutation_ids)
        if isinstance(mutation, dict) and isinstance(mutation.get("mutation_id"), str):
            mutation_records[mutation["mutation_id"]] = json.dumps(mutation, sort_keys=True, separators=(",", ":"))
    mutation_run = data.get("targeted_mutation")
    if mutation_run is None:
        return mutation_ids, mutation_records
    if not isinstance(mutation_run, dict):
        errors.append("targeted_mutation must be an object")
        return mutation_ids, mutation_records
    if mutation_run.get("status") not in INTERNAL_STATES:
        errors.append("targeted_mutation has an invalid status")
    run_results = mutation_run.get("results")
    if not isinstance(run_results, list):
        errors.append("targeted_mutation.results must be an array")
    else:
        for mutation in run_results:
            identifier = mutation.get("mutation_id") if isinstance(mutation, dict) else None
            _validate_mutation_record(
                mutation,
                "targeted_mutation result",
                errors,
                subject_ids,
                mutation_ids,
                allow_existing_id=isinstance(identifier, str) and identifier in mutation_ids,
            )
            if isinstance(mutation, dict) and isinstance(identifier, str) and identifier in mutation_records:
                current = json.dumps(mutation, sort_keys=True, separators=(",", ":"))
                if current != mutation_records[identifier]:
                    errors.append(f"targeted_mutation result does not match mutation record: {identifier}")
            elif isinstance(mutation, dict) and isinstance(identifier, str):
                mutation_records[identifier] = json.dumps(mutation, sort_keys=True, separators=(",", ":"))
    for key in ("kill_sets", "unique_kill_sets"):
        values = mutation_run.get(key)
        if not isinstance(values, dict):
            errors.append(f"targeted_mutation.{key} must be an object")
            continue
        for test_name, mutant_ids in values.items():
            if not isinstance(test_name, str) or not isinstance(mutant_ids, list) or not all(isinstance(item, str) for item in mutant_ids):
                errors.append(f"targeted_mutation.{key} contains an invalid entry")
            elif any(item not in mutation_ids for item in mutant_ids):
                errors.append(f"targeted_mutation.{key} references an unknown mutation")
    return mutation_ids, mutation_records


def _validate_changes(data: dict[str, Any], errors: list[str], artifact_ids: set[str], subject_ids: set[str]) -> set[str]:
    change_ids: set[str] = set()
    changes = data.get("changes", []) if isinstance(data.get("changes"), list) else []
    for change in changes:
        if not isinstance(change, dict):
            errors.append("test change must be an object")
            continue
        identifier = change.get("id")
        if not isinstance(identifier, str) or not identifier:
            errors.append("test change id is required")
        elif identifier in change_ids:
            errors.append(f"duplicate test change id: {identifier}")
        else:
            change_ids.add(identifier)
        test = change.get("test")
        if not isinstance(test, dict):
            errors.append(f"test change {identifier or '<missing>'} requires a test artefact")
        elif test.get("id") and test.get("id") not in artifact_ids:
            errors.append(f"test change references unknown test artefact: {test.get('id')}")
        kinds = change.get("change_kinds")
        if not isinstance(kinds, list) or not kinds or not all(isinstance(item, str) and item for item in kinds):
            errors.append(f"test change {identifier or '<missing>'} requires non-empty change_kinds")
        affected = change.get("affected_subjects")
        if not isinstance(affected, list):
            errors.append(f"test change {identifier or '<missing>'} affected_subjects must be an array")
        else:
            for subject in affected:
                if not isinstance(subject, dict) or subject.get("id") not in subject_ids:
                    errors.append(f"test change {identifier or '<missing>'} references an unknown subject")
        oracle = change.get("oracle_source")
        if not isinstance(oracle, dict) or not isinstance(oracle.get("kind"), str) or not oracle.get("kind") or not isinstance(oracle.get("reference"), str) or not oracle.get("reference"):
            errors.append(f"test change {identifier or '<missing>'} requires an oracle source record")
        elif data.get("status") == "complete" and oracle.get("kind") not in ORACLE_KINDS:
            errors.append(f"test change {identifier or '<missing>'} is complete without an independent oracle")
    return change_ids


def _validate_candidates(data: dict[str, Any], errors: list[str], artifact_ids: set[str], subject_ids: set[str]) -> set[str]:
    candidate_ids: set[str] = set()
    static_candidates = data.get("static_candidates", [])
    dynamic_candidates = data.get("dynamic_candidates", [])
    for candidate_list, label in ((static_candidates, "static"), (dynamic_candidates, "dynamic")):
        if not isinstance(candidate_list, list):
            continue
        for candidate in candidate_list:
            if not isinstance(candidate, dict):
                continue
            candidate_id = candidate.get("id")
            if not isinstance(candidate_id, str) or not candidate_id:
                errors.append(f"{label} candidate requires an ID")
            elif candidate_id in candidate_ids:
                errors.append(f"duplicate test-integrity candidate ID: {candidate_id}")
            else:
                candidate_ids.add(candidate_id)
            errors.extend(f"{label} candidate {candidate_id or '<missing>'}: {error}" for error in validate_candidate(candidate))
            for evidence in candidate.get("supporting_evidence", ()):
                if not isinstance(evidence, dict):
                    continue
                if evidence.get("rule_id") and evidence["rule_id"] not in TEST_RULE_IDS:
                    errors.append(f"{label} candidate {candidate_id or '<missing>'} has an unknown rule ID")
                if evidence.get("test_artifact_id") and evidence["test_artifact_id"] not in artifact_ids:
                    errors.append(f"candidate references unknown test artefact: {evidence['test_artifact_id']}")
                if evidence.get("focal_subject_id") and evidence["focal_subject_id"] not in subject_ids:
                    errors.append(f"candidate references unknown test subject: {evidence['focal_subject_id']}")
    return candidate_ids


def _validate_scenario(scenario: Any, errors: list[str]) -> None:
    if not isinstance(scenario, dict):
        errors.append("matrix scenario must be an object")
        return
    scenario_id = scenario.get("scenario_id")
    valid_id = scenario_id if isinstance(scenario_id, str) else None
    if valid_id not in SCENARIO_IDS:
        errors.append(f"matrix scenario has an invalid ID: {scenario_id}")
    if scenario.get("production_state") not in {"base", "head"}:
        errors.append(f"matrix scenario {scenario_id} has an invalid production state")
    if scenario.get("test_state") not in {"base", "head"}:
        errors.append(f"matrix scenario {scenario_id} has an invalid test state")
    expected_states = {
        "base-code-base-tests": ("base", "base"),
        "base-code-head-tests": ("base", "head"),
        "head-code-base-tests": ("head", "base"),
        "head-code-head-tests": ("head", "head"),
    }.get(valid_id)
    if expected_states is not None and (scenario.get("production_state"), scenario.get("test_state")) != expected_states:
        errors.append(f"matrix scenario {scenario_id} states do not match its ID")
    source_hashes = scenario.get("source_hashes")
    if not isinstance(source_hashes, dict):
        errors.append(f"matrix scenario {scenario_id} requires source hashes")
    else:
        for key in ("source_files_sha256", "source_files_present", "source_files_absent"):
            if key not in source_hashes:
                errors.append(f"matrix scenario {scenario_id} source hashes require {key}")
        present = source_hashes.get("source_files_present")
        absent = source_hashes.get("source_files_absent")
        if isinstance(present, list) and all(isinstance(item, str) for item in present) and len(present) != len(set(present)):
            errors.append(f"matrix scenario {scenario_id} has duplicate present source paths")
        if isinstance(absent, list) and all(isinstance(item, str) for item in absent) and len(absent) != len(set(absent)):
            errors.append(f"matrix scenario {scenario_id} has duplicate absent source paths")
        if isinstance(present, list) and isinstance(absent, list) and all(isinstance(item, str) for item in (*present, *absent)) and set(present) & set(absent):
            errors.append(f"matrix scenario {scenario_id} marks a source path both present and absent")
        if isinstance(source_hashes.get("source_files_sha256"), dict):
            values = source_hashes["source_files_sha256"]
            if any(not _hash(item) for item in values.values()) or any(not _safe_relative_path(path) for path in values):
                errors.append(f"matrix scenario {scenario_id} has an invalid source file hash")
            if isinstance(present, list) and sorted(present) != sorted(values):
                errors.append(f"matrix scenario {scenario_id} present paths do not match source file hashes")
        elif "source_files_sha256" in source_hashes:
            errors.append(f"matrix scenario {scenario_id} source_files_sha256 must be an object")
        for key, value in source_hashes.items():
            if key != "source_files_sha256" and key not in {"source_files_present", "source_files_absent"} and key.endswith("_sha256") and not _hash(value, allow_empty=True):
                errors.append(f"matrix scenario {scenario_id} has an invalid source hash: {key}")
        for key in ("source_files_present", "source_files_absent"):
            values = source_hashes.get(key)
            if not isinstance(values, list) or not all(isinstance(item, str) and item for item in values) or not all(_safe_relative_path(item) for item in values):
                errors.append(f"matrix scenario {scenario_id} contains an invalid source path list")
    selected = scenario.get("selected_tests")
    if not isinstance(selected, list) or not all(isinstance(item, str) and item for item in selected):
        errors.append(f"matrix scenario {scenario_id} selected_tests must be an array of strings")
    _validate_run_result(scenario.get("result"), str(scenario_id), errors)
    result = scenario.get("result")
    if not isinstance(result, dict):
        return
    if "reachability" in scenario and scenario.get("reachability") != result.get("reachability", "unverified"):
        errors.append(f"matrix scenario {scenario_id} reachability differs between scenario and result")
    if "reached_subjects" in scenario and scenario.get("reached_subjects") != result.get("reached_subjects", []):
        errors.append(f"matrix scenario {scenario_id} reached subjects differ between scenario and result")
    if isinstance(selected, list) and isinstance(result.get("selected_tests"), list) and selected != result["selected_tests"]:
        errors.append(f"matrix scenario {scenario_id} selected tests differ between plan and result")
    focal = scenario.get("focal_subjects", [])
    if not isinstance(focal, list) or not all(isinstance(item, str) and item for item in focal):
        errors.append(f"matrix scenario {scenario_id} focal_subjects must be an array of non-empty strings")
    repeated = scenario.get("repeated_runs", [])
    if not isinstance(repeated, list):
        errors.append(f"matrix scenario {scenario_id} repeated_runs must be an array")
    else:
        for repeat in repeated:
            if not isinstance(repeat, dict):
                errors.append(f"matrix scenario {scenario_id} repeated run must be an object")
            else:
                if repeat.get("scenario_id") != scenario_id:
                    errors.append(f"matrix scenario {scenario_id} repeated run ID does not match")
                _validate_run_result(repeat, str(scenario_id), errors)
        flakiness = scenario.get("flakiness")
        if flakiness is not None and not isinstance(flakiness, dict):
            errors.append(f"matrix scenario {scenario_id} flakiness must be an object")
        if isinstance(flakiness, dict):
            values = [flakiness.get(key) for key in ("run_count", "pass_count", "fail_count")]
            if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in values):
                errors.append(f"matrix scenario {scenario_id} flakiness counts must be non-negative integers")
            elif flakiness["pass_count"] + flakiness["fail_count"] > flakiness["run_count"]:
                errors.append(f"matrix scenario {scenario_id} flakiness counts exceed run_count")
            if flakiness.get("status") not in {"stable", "flaky", "not_verified"}:
                errors.append(f"matrix scenario {scenario_id} flakiness has an invalid status")
    for key in ("production_patch_sha256", "test_patch_sha256", "shared_config_patch_sha256"):
        if key in result and not _hash(result[key], allow_empty=True):
            errors.append(f"matrix scenario {scenario_id} has an invalid {key}")


def _validate_scenarios(data: dict[str, Any], errors: list[str], test_artifacts_present: bool) -> None:
    scenarios = data.get("matrix", [])
    scenario_ids = [item.get("scenario_id") for item in scenarios if isinstance(item, dict) and isinstance(item.get("scenario_id"), str)] if isinstance(scenarios, list) else []
    if scenarios and (len(scenario_ids) != len(SCENARIO_IDS) or set(scenario_ids) != set(SCENARIO_IDS)):
        errors.append("matrix must contain exactly the four test evidence scenarios")
    if len(scenario_ids) != len(set(scenario_ids)):
        errors.append("matrix scenario IDs must be unique")
    if data.get("status") == "complete" and test_artifacts_present and set(scenario_ids) != set(SCENARIO_IDS):
        errors.append("complete test evidence with test artefacts requires all four matrix scenarios")
    if data.get("status") == "complete" and isinstance(scenarios, list) and any(
        not isinstance(item, dict) or not isinstance(item.get("result"), dict) or item["result"].get("completed") is not True or not isinstance(item["result"].get("passed"), bool)
        for item in scenarios
    ):
        errors.append("complete test evidence requires completed matrix results")
    for scenario in scenarios if isinstance(scenarios, list) else []:
        _validate_scenario(scenario, errors)


def _validate_relations_proofs_and_static(data: dict[str, Any], errors: list[str], artifact_ids: set[str], subject_ids: set[str], candidate_ids: set[str]) -> None:
    for relation in data.get("relations", []) if isinstance(data.get("relations"), list) else []:
        if not isinstance(relation, dict):
            errors.append("test relation must be an object")
            continue
        if relation.get("test_artifact_id") and relation["test_artifact_id"] not in artifact_ids:
            errors.append(f"relation references unknown test artefact: {relation['test_artifact_id']}")
        if relation.get("subject_id") and relation["subject_id"] not in subject_ids:
            errors.append(f"relation references unknown test subject: {relation['subject_id']}")
    for proof in data.get("proof_tests", []) if isinstance(data.get("proof_tests"), list) else []:
        if not isinstance(proof, dict):
            errors.append("proof test must be an object")
            continue
        if proof.get("candidate_id") and not isinstance(proof["candidate_id"], str):
            errors.append("proof test candidate_id must be a string")
        if proof.get("outcome") is not None and proof.get("outcome") not in {"disproved", "supported", "inconclusive"}:
            errors.append("proof test has an invalid outcome")
        if proof.get("reachability") is not None and proof.get("reachability") not in {"confirmed", "not_reached", "unverified"}:
            errors.append("proof test has an invalid reachability state")
        if proof.get("test_patch_sha256") is not None and not _hash(proof["test_patch_sha256"]):
            errors.append("proof test has an invalid patch hash")
        if proof.get("command_plan_digest") is not None and not _hash(proof["command_plan_digest"], allow_empty=True):
            errors.append("proof test has an invalid command plan digest")
        if isinstance(proof.get("candidate_id"), str) and proof["candidate_id"] and proof["candidate_id"] not in candidate_ids:
            errors.append(f"proof test references unknown candidate: {proof['candidate_id']}")
        oracle_kind = proof.get("oracle_kind", proof.get("oracle_source", {}).get("kind") if isinstance(proof.get("oracle_source"), dict) else None)
        if proof.get("outcome") in {"disproved", "supported"} and oracle_kind not in ORACLE_KINDS:
            errors.append("completed proof test requires an independent oracle")
        if proof.get("outcome") in {"disproved", "supported"} and (proof.get("reachability") != "confirmed" or proof.get("current_result") not in {"pass", "fail"} or proof.get("control_result") not in {"pass", "fail"}):
            errors.append("completed proof test requires confirmed reachability and current and control results")
    static_analysis = data.get("static_analysis")
    if static_analysis is None:
        return
    _count_record(static_analysis, "static_analysis", errors)
    if not isinstance(static_analysis, dict):
        return
    if static_analysis.get("status") not in {"complete", "partial", "not_applicable", "failed"}:
        errors.append("static_analysis has an invalid status")
    if static_analysis.get("status") == "complete" and (static_analysis.get("checked_files") != static_analysis.get("applicable_files") or static_analysis.get("skipped_files") != 0):
        errors.append("complete static_analysis cannot contain skipped files")
    if static_analysis.get("status") == "not_applicable" and any(static_analysis.get(key, 0) for key in ("applicable_files", "checked_files", "skipped_files")):
        errors.append("not_applicable static_analysis cannot contain files")


def validate(data: Any) -> list[str]:
    if not isinstance(data, dict):
        return ["test evidence must be an object"]
    errors: list[str] = []
    test_artifacts_present = _validate_header(data, errors)
    artifact_ids = _validate_artifacts(data, errors)
    subject_ids = _validate_subjects(data, errors)
    _validate_mutations(data, errors, subject_ids)
    _validate_changes(data, errors, artifact_ids, subject_ids)
    candidate_ids = _validate_candidates(data, errors, artifact_ids, subject_ids)
    _validate_scenarios(data, errors, test_artifacts_present)
    _validate_relations_proofs_and_static(data, errors, artifact_ids, subject_ids, candidate_ids)
    errors.extend(_forbidden_output(data))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    try:
        errors = validate(json.loads(args.evidence.read_text(encoding="utf-8")))
    except (OSError, ValueError) as error:
        print(str(error))
        return 1
    if errors:
        print("\n".join(errors))
        return 1
    print("Test evidence is valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
