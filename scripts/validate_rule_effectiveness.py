#!/usr/bin/env python3
"""Validate machine-readable rule evidence and its meta-mutation gate."""
from __future__ import annotations

import argparse
import ast
import json
import math
from pathlib import Path
import sys
from contextlib import ExitStack
from dataclasses import replace
from typing import Any, Mapping
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dissect_checks.complexity import orchestrator as complexity_orchestrator  # noqa: E402
from dissect_checks.anti_slop.rules import RULE_OWNERS, owner_for  # noqa: E402
from dissect_checks.legacy import CUSTOM_CHECK_IDS, LEGACY_RULES  # noqa: E402
from dissect_checks.rules import RULES as DETERMINISTIC_RULES  # noqa: E402
from dissect_checks.test_integrity.inventory import build_inventory  # noqa: E402
from dissect_checks.test_integrity import static_analysis as static_analysis_module  # noqa: E402
from dissect_checks.test_integrity.static_analysis import DEFAULT_ENABLED_RULES, RULES, analyse_static  # noqa: E402
from analysis_budget import AnalysisBudget  # noqa: E402
from dissect_checks import engine as deterministic_engine  # noqa: E402
from dissect_checks.anti_slop import python_ast_backend  # noqa: E402
from dissect_checks.anti_slop.model import AnalysisTarget  # noqa: E402
from run_rule_acceptance import CASES, run as run_acceptance  # noqa: E402


REQUIRED_EVIDENCE = (
    "failure_model", "positive_cases", "negative_cases", "valid_fixture",
    "exact_locations", "negative_control", "reviewed_sample", "precision", "evidence",
)
REQUIRED_EVIDENCE_ITEMS = ("malformed", "generated", "framework", "suppression", "locations", "manual_precision")


def validate(manifest: Any, calibration: Any | None = None) -> list[str]:
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return ["rule manifest must be an object"]
    if manifest.get("schema_version") != "1.0":
        errors.append("rule manifest schema_version must be 1.0")
    rules = manifest.get("rules")
    enabled = manifest.get("default_enabled")
    if not isinstance(rules, dict) or not isinstance(enabled, list):
        return errors + ["rule manifest requires rules and default_enabled"]
    if any(not isinstance(item, str) for item in enabled):
        errors.append("default_enabled must contain only strings")
    elif len(enabled) != len(set(enabled)):
        errors.append("default_enabled rule IDs must be unique")
    elif set(enabled) != set(DEFAULT_ENABLED_RULES):
        errors.append("default_enabled must exactly match the registered static defaults")
    if not isinstance(calibration, dict):
        errors.append("calibration evidence must be an object")
    else:
        if calibration.get("schema_version") != "1.0":
            errors.append("calibration evidence schema_version must be 1.0")
        if not isinstance(calibration.get("sample_id"), str) or not calibration.get("sample_id"):
            errors.append("calibration evidence requires a sample_id")
        if not isinstance(calibration.get("sample_source"), str) or not calibration.get("sample_source"):
            errors.append("calibration evidence requires a sample_source")
    calibration_rules = calibration.get("rules", {}) if isinstance(calibration, dict) else {}
    calibration_sample_id = calibration.get("sample_id") if isinstance(calibration, dict) else None
    for rule_id in enabled:
        if not isinstance(rule_id, str) or rule_id not in rules:
            errors.append(f"default-enabled rule is missing: {rule_id}")
            continue
        if rule_id not in RULES:
            errors.append(f"default-enabled rule is not implemented by the static analyser: {rule_id}")
        if rule_id not in DEFAULT_ENABLED_RULES:
            errors.append(f"default-enabled rule is not registered as a static default: {rule_id}")
        record = rules[rule_id]
        if not isinstance(record, dict):
            errors.append(f"rule {rule_id} must be an object")
            continue
        for key in REQUIRED_EVIDENCE:
            if key not in record:
                errors.append(f"rule {rule_id} is missing evidence field: {key}")
        if not isinstance(record.get("failure_model"), str) or not record.get("failure_model"):
            errors.append(f"rule {rule_id} needs a concrete failure model")
        positive_cases = record.get("positive_cases")
        if not isinstance(positive_cases, list) or len(positive_cases) < 3:
            errors.append(f"rule {rule_id} needs at least three positive cases")
        elif not all(isinstance(item, str) and item.strip() for item in positive_cases):
            errors.append(f"rule {rule_id} positive cases must be non-empty strings")
        elif len(set(positive_cases)) != len(positive_cases):
            errors.append(f"rule {rule_id} positive cases must be unique")
        negative_cases = record.get("negative_cases")
        if not isinstance(negative_cases, list) or len(negative_cases) < 8:
            errors.append(f"rule {rule_id} needs at least eight negative cases")
        elif not all(isinstance(item, str) and item.strip() for item in negative_cases):
            errors.append(f"rule {rule_id} negative cases must be non-empty strings")
        elif len(set(negative_cases)) != len(negative_cases):
            errors.append(f"rule {rule_id} negative cases must be unique")
        for key in ("valid_fixture", "exact_locations", "negative_control"):
            if record.get(key) is not True:
                errors.append(f"rule {rule_id} is missing required {key} evidence")
        if record.get("reviewed_sample") is not True:
            errors.append(f"rule {rule_id} has no reviewed sample")
        precision = record.get("precision")
        if isinstance(precision, bool) or not isinstance(precision, (int, float)) or not math.isfinite(float(precision)) or not 0 <= precision <= 1 or precision < 0.9:
            errors.append(f"rule {rule_id} precision is below the 90% gate")
        evidence = record.get("evidence")
        if not isinstance(evidence, dict):
            errors.append(f"rule {rule_id} evidence must be an object")
        else:
            for key in REQUIRED_EVIDENCE_ITEMS:
                if key not in evidence:
                    errors.append(f"rule {rule_id} evidence is missing {key}")
            for key in ("malformed", "generated", "framework", "suppression", "locations", "manual_precision"):
                value = evidence.get(key)
                if isinstance(value, dict):
                    if value.get("present") is not True and key != "manual_precision":
                        errors.append(f"rule {rule_id} evidence {key} is not present")
                elif value is not True:
                    errors.append(f"rule {rule_id} evidence {key} is not present")
            if isinstance(evidence.get("manual_precision"), dict) and evidence["manual_precision"].get("reviewed") is not True:
                errors.append(f"rule {rule_id} manual precision evidence is not reviewed")
            if isinstance(evidence.get("manual_precision"), dict):
                sample_id = evidence["manual_precision"].get("sample_id")
                if not isinstance(sample_id, str) or not sample_id or sample_id != calibration_sample_id:
                    errors.append(f"rule {rule_id} manual precision sample is not bound to the calibration record")
        calibration_record = calibration_rules.get(rule_id) if isinstance(calibration_rules, dict) else None
        if not isinstance(calibration_record, dict):
            errors.append(f"rule {rule_id} has no calibration record")
        elif not _valid_calibration(calibration_record):
            errors.append(f"rule {rule_id} calibration precision is below the 90% gate")
        elif isinstance(record.get("precision"), (int, float)) and abs(
            float(record["precision"]) - float(calibration_record["precision"])
        ) > 1e-9:
            errors.append(f"rule {rule_id} manifest precision does not match calibration")
    return errors


def _valid_calibration(record: Mapping[str, Any]) -> bool:
    values = {
        key: record.get(key)
        for key in ("reviewed_cases", "true_positive", "false_positive", "true_negative", "false_negative")
    }
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in values.values()):
        return False
    if values["true_positive"] < 3 or values["true_negative"] < 8:
        return False
    if values["reviewed_cases"] != sum(values[key] for key in values if key != "reviewed_cases"):
        return False
    precision = record.get("precision")
    if isinstance(precision, bool) or not isinstance(precision, (int, float)) or not math.isfinite(float(precision)) or not 0 <= precision <= 1:
        return False
    denominator = values["true_positive"] + values["false_positive"]
    measured = values["true_positive"] / denominator if denominator else 1.0
    if abs(float(precision) - measured) > 1e-9 or measured < 0.9:
        return False
    decisions = record.get("decisions")
    if not isinstance(decisions, list) or len(decisions) != values["reviewed_cases"]:
        return False
    if not all(
        isinstance(item, dict)
        and isinstance(item.get("case_id"), str)
        and item.get("classification") in {"true_positive", "false_positive", "true_negative", "false_negative"}
        for item in decisions
    ):
        return False
    if len({item["case_id"] for item in decisions}) != len(decisions):
        return False
    measured_counts = {
        kind: sum(1 for item in decisions if item["classification"] == kind)
        for kind in ("true_positive", "false_positive", "true_negative", "false_negative")
    }
    return all(measured_counts[kind] == values[kind] for kind in measured_counts)


def _static_meta_mutation(root: Path) -> list[str]:
    fixture_root = root / "tests" / "fixtures" / "test-integrity" / "acceptance"
    paths = ("test_cases.py", "negative_cases.py", "service.py", "runtime_seam.py")
    contents = {
        path: (fixture_root / path).read_bytes()
        for path in paths
    }
    inventory = build_inventory(fixture_root, paths, content_by_path=contents)
    head = {path: data.decode("utf-8") for path, data in contents.items()}
    errors: list[str] = []

    def assert_acceptance(result: Any, rule_id: str) -> None:
        if not any(item.get("source") == rule_id for item in result.candidates):
            raise AssertionError(f"{rule_id} acceptance corpus produced no candidate")

    detector_mutations = {
        "GOV-TESTS-001": ("_disabled_matches",),
        "GOV-TESTS-002": ("_assertion_weakening", "_assertion_moved_behind_branch"),
        "GOV-TESTS-003": ("_circular_oracles", "_derived_oracles", "_python_circular_oracles", "_python_derived_oracles", "_implementation_oracle_matches", "_snapshot_derived_oracle"),
        "GOV-TESTS-004": ("_mock_matches",),
        "GOV-TESTS-005": ("_tautologies", "_python_tautologies", "_python_early_return_matches", "_python_catch_all_matches", "_no_observable_test_bodies"),
        "GOV-TESTS-006": ("_test_only_production",),
        "GOV-TESTS-010": ("_new_test_file_matches",),
    }

    for rule_id in sorted(DEFAULT_ENABLED_RULES):
        base = dict(head)
        if rule_id == "GOV-TESTS-001":
            base["test_cases.py"] = base["test_cases.py"].replace(
                '    pytest.skip("quarantined until the independent contract is reviewed")\n',
                "    assert load() == {'value': 1}\n",
            )
        elif rule_id == "GOV-TESTS-002":
            base["test_cases.py"] = base["test_cases.py"].replace(
                "    assert load()\n\n\ndef test_circular_oracle():",
                "    assert load() == {'value': 1}\n\n\ndef test_circular_oracle():",
            )
        elif rule_id == "GOV-TESTS-010":
            base.pop("test_cases.py", None)
        result = analyse_static(
            fixture_root,
            inventory,
            paths=paths,
            base_contents=base,
            head_contents=head,
            changed_paths=paths,
            enabled_rules={rule_id},
        )
        try:
            assert_acceptance(result, rule_id)
        except AssertionError as error:
            errors.append(str(error))
            continue
        # Disable the detector implementation itself in-process. This is the
        # static equivalent of running an acceptance corpus against a copied,
        # mutated rule pack. Merely passing ``enabled_rules=set()`` would only
        # test configuration filtering and would provide false assurance.
        with ExitStack() as stack:
            for detector_name in detector_mutations[rule_id]:
                detector = getattr(static_analysis_module, detector_name)
                stack.enter_context(patch.object(static_analysis_module, detector_name, _empty_detector(detector_name)))
            disabled = analyse_static(
                fixture_root,
                inventory,
                paths=paths,
                base_contents=base,
                head_contents=head,
                changed_paths=paths,
                enabled_rules={rule_id},
            )
        if any(item.get("source") == rule_id for item in disabled.candidates):
            errors.append(f"disabling {rule_id} did not remove its acceptance candidate")
        else:
            # The normal acceptance candidate was present above and the same
            # assertion now fails against the mutated detector.
            try:
                assert_acceptance(disabled, rule_id)
            except AssertionError:
                pass
            else:
                errors.append(f"{rule_id} acceptance did not depend on its detector")
    return errors


def _validate_static_acceptance_fixtures(root: Path) -> list[str]:
    """Ensure the static-rule corpus is interpreter-valid before it is used."""
    fixture_root = root / "tests" / "fixtures" / "test-integrity" / "acceptance"
    errors: list[str] = []
    for path in sorted(fixture_root.glob("*.py")):
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, ValueError, TypeError) as error:
            errors.append(f"static acceptance fixture is not interpreter-valid: {path}: {error}")
    return errors


def _empty_detector(name: str) -> Any:
    """Return a correctly-shaped no-op for one static detector function."""
    if name == "_mock_matches":
        return lambda *_args, **_kwargs: iter(())
    if name in {"_circular_oracles", "_derived_oracles", "_python_circular_oracles", "_python_derived_oracles", "_implementation_oracle_matches", "_snapshot_derived_oracle", "_tautologies", "_python_tautologies", "_python_early_return_matches", "_python_catch_all_matches", "_no_observable_test_bodies", "_disabled_matches", "_assertion_weakening", "_assertion_moved_behind_branch", "_test_only_production", "_new_test_file_matches"}:
        return lambda *_args, **_kwargs: iter(())
    raise ValueError(f"unknown static detector mutation: {name}")


def validate_rule_ownership(root: Path) -> list[str]:
    """Compare rule IDs across legacy, deterministic, AST, and native packs."""
    errors: list[str] = []
    discovered: dict[str, str] = {}
    ast_root = root / "scripts" / "vendor" / "anti-slop" / "ast-grep" / "rules"
    for path in sorted(ast_root.rglob("*.yml")):
        first = path.read_text(encoding="utf-8").splitlines()[0] if path.is_file() else ""
        rule = first.removeprefix("id: ").strip() if first.startswith("id: ") else ""
        if not rule:
            errors.append(f"ast-grep rule has no ID: {path}")
            continue
        owner = f"ast-grep-{path.parent.name}"
        if rule in discovered:
            errors.append(f"duplicate structural rule ID: {rule}")
        else:
            discovered[rule] = owner
    native_root = root / "scripts" / "vendor" / "anti-slop"
    for path in sorted((native_root / "rules").glob("*.ts")):
        rule = f"anti-slop/{path.stem}"
        if rule in discovered:
            errors.append(f"duplicate structural rule ID: {rule}")
        else:
            discovered[rule] = "oxlint"
    for path in sorted((native_root / "effect" / "rules").glob("*.ts")):
        rule = f"anti-slop-effect/{path.stem}"
        if rule in discovered:
            errors.append(f"duplicate structural rule ID: {rule}")
        else:
            discovered[rule] = "oxlint"
    discovered["anti-slop-python/no-widen-then-cast"] = "python-ast"
    discovered["anti-slop-python/no-literal-getattr-without-default"] = "python-ast"
    legacy_ids = {rule.check_id for rule in LEGACY_RULES} | set(CUSTOM_CHECK_IDS)
    deterministic_ids = {rule.check_id for rule in DETERMINISTIC_RULES}
    for owner, rule_ids in (("legacy", legacy_ids), ("deterministic", deterministic_ids)):
        for rule_id in sorted(rule_ids):
            if rule_id in discovered:
                errors.append(f"rule ID is claimed by both {owner} and {discovered[rule_id]}: {rule_id}")
            discovered[rule_id] = owner
    for rule_id, expected_owner in sorted(discovered.items()):
        if expected_owner in {"ast-grep-c", "ast-grep-cpp", "ast-grep-go", "ast-grep-rust", "ast-grep-java", "ast-grep-csharp", "oxlint", "python-ast"} and owner_for(rule_id) != expected_owner:
            errors.append(f"rule ownership mismatch for {rule_id}: expected {expected_owner}, got {owner_for(rule_id)}")
    for rule_id, owner in RULE_OWNERS.items():
        if owner in {"ast-grep-c", "ast-grep-cpp", "ast-grep-go", "ast-grep-rust", "ast-grep-java", "ast-grep-csharp", "oxlint", "python-ast"} and rule_id not in discovered:
            errors.append(f"registered structural rule is not present in its pack: {rule_id}")
    return errors


def _complexity_meta_mutation(root: Path) -> list[str]:
    source = "\n".join([
        "def branch(value):",
        "    if value > 0:",
        "        return 1",
        "    if value > 1:",
        "        return 2",
        "    if value > 2:",
        "        return 3",
        "    if value > 3:",
        "        return 4",
        "    if value > 4:",
        "        return 5",
        "    return 0",
        ""])
    fixture = root / "tests" / "fixtures" / "test-integrity" / "acceptance"
    result = complexity_orchestrator.analyse(
        fixture,
        ["runtime_seam.py"],
        config={"review_options": {"analysis_limits": {"complexity_fallback_threshold": 2}}},
        head_contents={"runtime_seam.py": source},
    )
    if not result.candidates:
        return ["complexity acceptance corpus produced no candidate"]
    original_extract = complexity_orchestrator.extract_functions

    def constant_green(path: str, contents: bytes | str, *, source_kind: str = "working-tree") -> tuple[Any, ...]:
        return tuple(replace(item, cyclomatic=1) for item in original_extract(path, contents, source_kind=source_kind))

    # Replace the measured metric, not the configured threshold. The latter
    # would only prove that threshold filtering works, not that the acceptance
    # test depends on the complexity measurement.
    with patch.object(complexity_orchestrator, "extract_functions", constant_green):
        disabled = complexity_orchestrator.analyse(
            fixture,
            ["runtime_seam.py"],
            config={"review_options": {"analysis_limits": {"complexity_fallback_threshold": 2}}},
            head_contents={"runtime_seam.py": source},
        )
    if disabled.candidates:
        return ["complexity rule was not disabled by the mutation control"]
    # The acceptance assertion is expected to fail against the disabled run.
    return []


def _structured_meta_mutation() -> list[str]:
    """Require each deterministic rule fixture to depend on its matcher."""
    errors: list[str] = []
    for rule in DETERMINISTIC_RULES:
        path, positive = rule.positive_fixture
        if rule.check_id not in {item.check_id for item in deterministic_engine.scan_text(path, positive)}:
            errors.append(f"{rule.check_id} positive fixture produced no acceptance match")
            continue
        disabled_rules = tuple(
            replace(item, matcher=(lambda _path, _text: ()))
            if item.check_id == rule.check_id else item
            for item in DETERMINISTIC_RULES
        )
        with patch.object(deterministic_engine, "RULES", disabled_rules):
            disabled = deterministic_engine.scan_text(path, positive)
        if rule.check_id in {item.check_id for item in disabled}:
            errors.append(f"disabling {rule.check_id} did not remove its acceptance match")
    return errors


def _python_ast_meta_mutation(root: Path) -> list[str]:
    """Require the default Python AST contract to affect its fixture."""
    source = (
        "from typing import Any, cast\n"
        "def load(value):\n"
        "    return cast(str, cast(Any, value))\n"
    )
    target = AnalysisTarget(
        "tests/fixtures/python_ast_acceptance.py",
        root / "tests" / "fixtures" / "python_ast_acceptance.py",
        "python",
        data=source.encode("utf-8"),
    )
    baseline = python_ast_backend.analyse(root, [target], AnalysisBudget(5))
    rule_id = "anti-slop-python/no-widen-then-cast"
    errors: list[str] = []
    if not any(item.rule_id == rule_id for item in baseline.diagnostics):
        return [f"{rule_id} acceptance fixture produced no diagnostic"]
    with patch.object(python_ast_backend, "_diagnostics", lambda *_args, **_kwargs: []):
        disabled = python_ast_backend.analyse(root, [target], AnalysisBudget(5))
    if any(item.rule_id == rule_id for item in disabled.diagnostics):
        errors.append(f"disabling {rule_id} did not remove its acceptance diagnostic")
    return errors


def meta_mutation_errors(root: Path, *, require_toolchains: bool = False) -> list[str]:
    errors = _structured_meta_mutation()
    errors.extend(_python_ast_meta_mutation(root))
    errors.extend(_static_meta_mutation(root))
    errors.extend(_complexity_meta_mutation(root))
    for language, values in CASES.items():
        for rule_id in values["rules"]:
            try:
                baseline = run_acceptance(
                    languages=(language,),
                    require_toolchains=require_toolchains,
                )
                fixture = baseline.get("fixtures", {}).get(language, {})
                if fixture.get("compile") == "toolchain_unavailable" and not require_toolchains:
                    continue
                run_acceptance(
                    languages=(language,),
                    require_toolchains=require_toolchains,
                    disabled_rule=rule_id,
                    require_rule_effect=True,
                )
            except AssertionError as error:
                if f"disabling {rule_id} removed its required acceptance match" not in str(error):
                    errors.append(f"{rule_id} meta-mutation failed: {error}")
            except (FileNotFoundError, OSError, ValueError) as error:
                errors.append(f"{rule_id} meta-mutation failed: {error}")
            else:
                errors.append(f"{rule_id} meta-mutation did not fail its acceptance test")
    return errors


def load(root: Path) -> tuple[Any, Any]:
    manifest = json.loads((root / "reference" / "test-integrity-rule-manifest.json").read_text(encoding="utf-8"))
    calibration = json.loads((root / "reference" / "test-integrity-calibration.json").read_text(encoding="utf-8"))
    return manifest, calibration


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--require-toolchains", action="store_true")
    parser.add_argument("--skip-meta-mutation", action="store_true")
    args = parser.parse_args(argv)
    try:
        manifest, calibration = load(args.root.resolve())
        errors = validate(manifest, calibration)
        errors.extend(validate_rule_ownership(args.root.resolve()))
        errors.extend(_validate_static_acceptance_fixtures(args.root.resolve()))
        if not args.skip_meta_mutation:
            errors.extend(meta_mutation_errors(args.root.resolve(), require_toolchains=args.require_toolchains))
    except (OSError, ValueError) as error:
        errors = [str(error)]
    if args.format == "json":
        print(json.dumps({"valid": not errors, "errors": errors}, indent=2, sort_keys=True))
    elif errors:
        print("\n".join(errors))
    else:
        print("Rule effectiveness evidence is valid.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
