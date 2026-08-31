#!/usr/bin/env python3
"""Validate bounded test-integrity evidence records."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from dissect_checks.test_integrity.model import SCENARIO_IDS, PUBLIC_STATES, INTERNAL_STATES

TEST_RULE_IDS = {f"GOV-TESTS-{index:03d}" for index in range(1, 10)}


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


def validate(data: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["test evidence must be an object"]
    if data.get("status") not in INTERNAL_STATES:
        errors.append("invalid internal test evidence status")
    if data.get("state") not in PUBLIC_STATES:
        errors.append("invalid public test evidence state")
    arrays = ("artifacts", "subjects", "relations", "changes", "static_candidates", "matrix", "mutations", "proof_tests")
    for key in arrays:
        if not isinstance(data.get(key), list):
            errors.append(f"{key} must be an array")
    if data.get("status") == "not_applicable" and data.get("state") != "Not applicable":
        errors.append("not_applicable test evidence must use the Not applicable public state")
    if data.get("status") == "complete" and data.get("state") != "Checked":
        errors.append("complete test evidence must use the Checked public state")
    if data.get("status") in {"partial", "planned", "unavailable", "failed"} and data.get("state") != "Not verified":
        errors.append("incomplete test evidence must use the Not verified public state")
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
        artifact_ids.add(identifier)
        for key in ("logical_path", "framework_id", "role", "source_kind"):
            if not isinstance(artifact.get(key), str) or not artifact[key]:
                errors.append(f"test artefact {identifier or '<missing>'} requires {key}")
        digest = artifact.get("content_sha256", "")
        if not _hash(digest):
            errors.append(f"invalid test artefact hash: {identifier}")
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
        subject_ids.add(identifier)
        if not isinstance(subject.get("logical_path"), str) or not subject.get("logical_path"):
            errors.append(f"test subject {identifier or '<missing>'} requires a path")
        if not isinstance(subject.get("qualified_name"), str) or not subject.get("qualified_name"):
            errors.append(f"test subject {identifier or '<missing>'} requires a qualified name")
        if isinstance(subject.get("start_line"), bool) or not isinstance(subject.get("start_line"), int) or subject.get("start_line", 0) < 1:
            errors.append(f"test subject {identifier or '<missing>'} has an invalid start line")
        if isinstance(subject.get("end_line"), bool) or not isinstance(subject.get("end_line"), int) or subject.get("end_line", 0) < subject.get("start_line", 1):
            errors.append(f"test subject {identifier or '<missing>'} has an invalid end line")
        if not _hash(subject.get("content_sha256")):
            errors.append(f"invalid test subject hash: {identifier}")
    mutation_ids: set[str] = set()
    mutations = data.get("mutations", []) if isinstance(data.get("mutations"), list) else []
    for mutation in mutations:
        if not isinstance(mutation, dict):
            errors.append("mutation must be an object")
            continue
        identifier = mutation.get("mutation_id")
        if not isinstance(identifier, str) or not identifier:
            errors.append("mutation id is required")
        elif identifier in mutation_ids:
            errors.append(f"duplicate mutation id: {identifier}")
        mutation_ids.add(identifier)
        if not _hash(mutation.get("patch_sha256")):
            errors.append(f"mutation {identifier or '<missing>'} has an invalid patch hash")
        if "command_plan_digest" in mutation and not _hash(mutation.get("command_plan_digest"), allow_empty=True):
            errors.append(f"mutation {identifier or '<missing>'} has an invalid command plan digest")
        subject = mutation.get("subject")
        if not isinstance(subject, dict):
            errors.append(f"mutation {identifier or '<missing>'} requires a subject")
        elif subject.get("id") and subject.get("id") not in subject_ids:
            errors.append(f"mutation references unknown test subject: {subject.get('id')}")
    mutation_run = data.get("targeted_mutation")
    if mutation_run is not None:
        if not isinstance(mutation_run, dict):
            errors.append("targeted_mutation must be an object")
        else:
            if mutation_run.get("status") not in INTERNAL_STATES:
                errors.append("targeted_mutation has an invalid status")
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
        change_ids.add(identifier)
        test = change.get("test")
        if isinstance(test, dict) and test.get("id") and test.get("id") not in artifact_ids:
            errors.append(f"test change references unknown test artefact: {test.get('id')}")
        oracle = change.get("oracle_source")
        if not isinstance(oracle, dict) or not isinstance(oracle.get("kind"), str) or not oracle.get("kind") or not isinstance(oracle.get("reference"), str) or not oracle.get("reference"):
            errors.append(f"test change {identifier or '<missing>'} requires an oracle source record")
    scenarios = data.get("matrix", [])
    scenario_ids = [item.get("scenario_id") for item in scenarios if isinstance(item, dict)] if isinstance(scenarios, list) else []
    if scenario_ids and (len(scenario_ids) != len(SCENARIO_IDS) or set(scenario_ids) != set(SCENARIO_IDS)):
        errors.append("matrix must contain exactly the four test evidence scenarios")
    if len(scenario_ids) != len(set(scenario_ids)):
        errors.append("matrix scenario IDs must be unique")
    for scenario in scenarios if isinstance(scenarios, list) else []:
        if not isinstance(scenario, dict):
            errors.append("matrix scenario must be an object")
            continue
        if not isinstance(scenario.get("source_hashes"), dict):
            errors.append(f"matrix scenario {scenario.get('scenario_id')} requires source hashes")
        if not isinstance(scenario.get("selected_tests"), list) or not all(isinstance(item, str) for item in scenario.get("selected_tests", [])):
            errors.append(f"matrix scenario {scenario.get('scenario_id')} selected_tests must be an array of strings")
        result = scenario.get("result")
        if not isinstance(result, dict):
            errors.append(f"matrix scenario {scenario.get('scenario_id')} requires a result")
            continue
        if result.get("scenario_id") not in {None, scenario.get("scenario_id")}:
            errors.append(f"matrix scenario {scenario.get('scenario_id')} result ID does not match")
        for key in ("production_patch_sha256", "test_patch_sha256", "shared_config_patch_sha256"):
            if key in result and not _hash(result[key], allow_empty=True):
                errors.append(f"matrix scenario {scenario.get('scenario_id')} has an invalid {key}")
        source_hashes = scenario.get("source_hashes")
        if isinstance(source_hashes, dict):
            for key, value in source_hashes.items():
                if key == "source_files_sha256" and isinstance(value, dict):
                    if any(not _hash(item) for item in value.values()):
                        errors.append(f"matrix scenario {scenario.get('scenario_id')} has an invalid source file hash")
                elif key.endswith("_sha256") and not _hash(value, allow_empty=True):
                    errors.append(f"matrix scenario {scenario.get('scenario_id')} has an invalid source hash: {key}")
    for candidate in data.get("static_candidates", []) if isinstance(data.get("static_candidates"), list) else []:
        if not isinstance(candidate, dict):
            errors.append("static candidate must be an object")
            continue
        for evidence in candidate.get("supporting_evidence", []):
            if not isinstance(evidence, dict):
                continue
            if evidence.get("rule_id") and evidence["rule_id"] not in TEST_RULE_IDS:
                errors.append(f"static candidate has an unknown test-integrity rule: {evidence['rule_id']}")
            if evidence.get("test_artifact_id") and evidence["test_artifact_id"] not in artifact_ids:
                errors.append(f"candidate references unknown test artefact: {evidence['test_artifact_id']}")
            if evidence.get("focal_subject_id") and evidence["focal_subject_id"] not in subject_ids:
                errors.append(f"candidate references unknown test subject: {evidence['focal_subject_id']}")
    for relation in data.get("relations", []) if isinstance(data.get("relations"), list) else []:
        if not isinstance(relation, dict):
            errors.append("test relation must be an object")
            continue
        if relation.get("test_artifact_id") and relation["test_artifact_id"] not in artifact_ids:
            errors.append(f"relation references unknown test artefact: {relation['test_artifact_id']}")
        if relation.get("subject_id") and relation["subject_id"] not in subject_ids:
            errors.append(f"relation references unknown test subject: {relation['subject_id']}")
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
