from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from analysis_budget import AnalysisBudget, AnalysisBudgetExceeded
from dissect_checks.anti_slop.model import AnalysisTarget, load_target
from dissect_checks import comment_slop
from dissect_checks.complexity.configuration import repository_policy, resolve_policy
from dissect_checks.complexity.lizard_backend import extract_functions
from dissect_checks.complexity.orchestrator import analyse as analyse_complexity
from dissect_checks.test_integrity.change_analysis import ChangePartition
from diff_file_list import DiffEntry
from dissect_checks.test_integrity.evidence_matrix import MatrixScenario, build_matrix, execute_approved_matrix, flakiness_evidence, interpret_matrix
from dissect_checks.test_integrity.model import TestRunResult, SCENARIO_IDS
from dissect_checks.test_integrity.mutation import removal_decision
from dissect_checks.test_integrity.proof_test import ProofCandidate, proof_outcome, validate_test_patch
from dissect_checks.test_integrity.orchestrator import source_maps
from dissect_checks.test_integrity.inventory import build_inventory
from dissect_checks.test_integrity.static_analysis import analyse_static


class TestIntegrityComplexityTests(unittest.TestCase):
    def test_source_budget_is_claimed_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app.py"
            source.write_text("value = 1\n")
            target = AnalysisTarget("app.py", source, "python")
            budget = AnalysisBudget(5, max_files=1, max_total_bytes=1)
            with patch.object(Path, "open", side_effect=AssertionError("source opened before byte budget rejection")):
                with self.assertRaises(AnalysisBudgetExceeded) as raised:
                    load_target(root, target, budget, max_file_bytes=1024)
            self.assertEqual(raised.exception.reason_code, "max_total_bytes")

    def test_comment_candidate_budget_stops_before_next_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("a.ts", "b.ts"):
                (root / name).write_text("// Update the account owner\nsaveUser(user);\n")
            opened: list[Path] = []
            original = Path.open

            def observe(path: Path, *args: object, **kwargs: object):
                opened.append(path)
                return original(path, *args, **kwargs)

            with patch.object(Path, "open", autospec=True, side_effect=observe):
                result = comment_slop.scan_comment_targets(
                    root,
                    ["a.ts", "b.ts"],
                    mode="diff",
                    changed_ranges={"a.ts": [(1, 2)], "b.ts": [(1, 2)]},
                    budget=AnalysisBudget(5, max_files=2, max_total_bytes=1024, max_candidates=1),
                )
            self.assertEqual(result.status, "partial")
            self.assertEqual(result.reason_code, "max_candidates")
            self.assertEqual(result.checked_files, 1)
            self.assertEqual(result.skipped_file_count, 1)
            self.assertEqual([path.name for path in opened if path.name in {"a.ts", "b.ts"}], ["a.ts"])

    def test_empty_matrix_is_not_applicable_without_test_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            matrix = build_matrix(Path(directory), ChangePartition(("app.py",), (), (), (), ()))
            self.assertEqual(matrix.status, "not_applicable")
            self.assertEqual(matrix.scenarios, ())

    def test_untracked_source_is_absent_from_the_base_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "new.py").write_text("def test_new():\n    assert 1 == 1\n")
            base, head = source_maps(
                root,
                [DiffEntry("A", "new.py", "new.py", True, "untracked")],
                ["new.py"],
            )
            self.assertNotIn("new.py", base)
            self.assertIn("new.py", head)

    def test_staged_deletion_is_absent_from_the_head_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
            subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=root, check=True)
            source = root / "tests" / "test_removed.py"
            source.parent.mkdir()
            source.write_text("def test_removed():\n    assert True\n")
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
            source.unlink()
            subprocess.run(["git", "add", "-u"], cwd=root, check=True)
            entries = [DiffEntry("D", "tests/test_removed.py", "tests/test_removed.py", False, "commit", "HEAD")]
            base, head = source_maps(root, entries, ["tests/test_removed.py"])
            self.assertIn("tests/test_removed.py", base)
            self.assertNotIn("tests/test_removed.py", head)

    def test_parser_only_fixture_rule_is_experimental_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fixtures").mkdir()
            path = root / "fixtures" / "parser_only.py"
            text = "# parser-only fixture\ndef broken(:\n"
            path.write_text(text)
            # The in-memory source keeps the test independent from filesystem
            # reads while retaining the fixture's exact content hash.
            relative = "fixtures/parser_only.py"
            inventory = build_inventory(root, [relative], content_by_path={relative: text})
            default = analyse_static(root, inventory, paths=[relative], head_contents={relative: text})
            experimental = analyse_static(root, inventory, paths=[relative], head_contents={relative: text}, enabled_rules={"GOV-TESTS-007"})
            self.assertFalse(any(item["source"] == "GOV-TESTS-007" for item in default.candidates))
            self.assertTrue(any(item["source"] == "GOV-TESTS-007" for item in experimental.candidates))

    def test_static_test_integrity_cases_keep_exact_rule_and_location(self) -> None:
        expected_lines = {
            "tests/test_disabled.py": {2},
            ".github/workflows/tests.yml": {3},
            "tests/test_assertion.js": {1},
            "tests/test_exception.py": {1},
            "tests/test_oracle.py": {1},
            "tests/test_derived.py": {1},
            "tests/test_mock.py": {4},
            "tests/test_tautology.py": {2},
            "tests/test_self_compare.py": {3},
            "tests/test_catch_all.py": {1, 4},
            "src/runtime.py": {3},
            "src/testing_marker.py": {1},
        }
        positives = (
            ("GOV-TESTS-001", "tests/test_disabled.py", "def test_case():\n    pytest.skip('quarantined')\n", "def test_case():\n    assert True\n"),
            ("GOV-TESTS-001", ".github/workflows/tests.yml", "jobs:\n  test:\n    continue-on-error: true\n", "jobs:\n  test:\n    runs-on: ubuntu\n"),
            ("GOV-TESTS-002", "tests/test_assertion.js", "expect(load()).toBeTruthy();\n", "expect(load()).toEqual({value: 1});\n"),
            ("GOV-TESTS-002", "tests/test_exception.py", "with pytest.raises(Exception):\n    load()\n", "with pytest.raises(ValueError):\n    load()\n"),
            ("GOV-TESTS-003", "tests/test_oracle.py", "assert load() == load()\n", ""),
            ("GOV-TESTS-003", "tests/test_derived.py", "expected = load()\nassert result == expected\n", ""),
            ("GOV-TESTS-004", "tests/test_mock.py", "from service import load\nfrom unittest.mock import patch\ndef test_case():\n    with patch('service.load'):\n        pass\n", ""),
            ("GOV-TESTS-005", "tests/test_tautology.py", "def test_case():\n    assert True\n", ""),
            ("GOV-TESTS-005", "tests/test_self_compare.py", "def test_case():\n    value = load()\n    assert value == value\n", ""),
            ("GOV-TESTS-005", "tests/test_catch_all.py", "def test_case():\n    try:\n        load()\n    except BaseException:\n        pass\n", ""),
            ("GOV-TESTS-006", "src/runtime.py", "import types\ndef dispatch(function):\n    if isinstance(function, types.FunctionType):\n        return function()\n    return function\n", ""),
            ("GOV-TESTS-006", "src/testing_marker.py", "if TESTING:\n    result = bypass()\n", ""),
        )
        negatives = {
            "GOV-TESTS-001": [
                "def test_case():\n    assert value\n",
                "def test_case():\n    with pytest.raises(ValueError):\n        raise ValueError\n",
                "def test_case():\n    compile('value = 1', 'fixture.py', 'exec')\n",
                "def test_case():\n    assert subprocess.run(['tool']).returncode == 0\n",
                "def test_case(value):\n    assert value is not None\n",
                "def test_case():\n    assert fixture == expected\n",
                "def test_case():\n    check_schema(payload)\n",
                "def test_case():\n    # documented quarantine is not a disabling marker\n    assert True\n",
            ],
            "GOV-TESTS-002": [
                "def test_case():\n    assert value == expected\n",
                "def test_case():\n    with pytest.raises(ValueError):\n        raise ValueError\n",
                "def test_case():\n    assert abs(value - expected) <= 0.1\n",
                "def test_case():\n    assert value in {'a', 'b'}\n",
                "def test_case():\n    assert not authorised(other_tenant)\n",
                "def test_case():\n    snapshot.assert_match(value)\n",
                "def test_case():\n    compile('value = 1', 'fixture.py', 'exec')\n",
                "def test_case():\n    assert response.status_code == 200\n",
            ],
            "GOV-TESTS-003": [
                "def test_case():\n    assert load() == expected\n",
                "def test_case():\n    assert load() == {'value': 1}\n",
                "def test_case():\n    assert parse(serialise(value)) == fixture\n",
                "def test_case():\n    expected = {'value': 1}\n    assert load() == expected\n",
                "def test_case():\n    assert encode(value) == decode(value)\n",
                "def test_case():\n    assert result == independent_fixture\n",
                "def test_case():\n    assert property_holds(value)\n",
                "def test_case():\n    assert schema.validate(value) is None\n",
            ],
            "GOV-TESTS-004": [
                "from unittest.mock import Mock\ndef test_case():\n    client = Mock()\n    assert client.fetch()\n",
                "def test_case(monkeypatch):\n    monkeypatch.setattr('client.fetch', lambda: {})\n    assert service()\n",
                "def test_case():\n    with patch('database.query'):\n        assert service()\n",
                "def test_case():\n    logger = Mock()\n    service(logger=logger)\n    logger.info.assert_called_once()\n",
                "def test_case():\n    clock = FakeClock()\n    assert service(clock=clock)\n",
                "def test_case():\n    queue = Mock()\n    assert service(queue=queue)\n",
                "def test_case():\n    dependency = Mock()\n    assert Service(dependency).run()\n",
                "def test_case():\n    factory = Mock(return_value=object())\n    assert factory()\n",
            ],
            "GOV-TESTS-005": [
                "def test_case():\n    assert value\n",
                "def test_case():\n    assert value == expected\n",
                "def test_case():\n    with pytest.raises(ValueError):\n        raise ValueError\n",
                "def test_case():\n    compile('value = 1', 'fixture.py', 'exec')\n",
                "def test_case():\n    assert subprocess.run(['tool']).returncode == 0\n",
                "def test_case():\n    property(value)\n",
                "def test_case():\n    assert response.status_code == 200\n",
                "def test_case():\n    snapshot.assert_match(value)\n",
            ],
            "GOV-TESTS-006": [
                "def dispatch(function):\n    return function()\n",
                "class Service:\n    def __init__(self, dependency):\n        self.dependency = dependency\n",
                "def now(clock):\n    return clock()\n",
                "def get_client(client):\n    return client\n",
                "class Service:\n    def run(self):\n        return self.dependency.run()\n",
                "def load(factory):\n    return factory()\n",
                "def validate(value, validator):\n    return validator(value)\n",
                "def send(queue, message):\n    return queue.publish(message)\n",
            ],
        }
        for rule_id, path, head, base in positives:
            with self.subTest(rule_id=rule_id, path=path), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                values = {path: head}
                if rule_id == "GOV-TESTS-004":
                    values["service.py"] = "def load():\n    return 1\n"
                inventory = build_inventory(root, values, content_by_path=values)
                result = analyse_static(
                    root, inventory, paths=[path], base_contents={path: base},
                    head_contents={path: head}, changed_paths=[path], enabled_rules={rule_id},
                )
                matches = [item for item in result.candidates if item["source"] == rule_id]
                self.assertEqual(
                    {item["supporting_evidence"][0]["line"] for item in matches},
                    expected_lines[path],
                )
                self.assertTrue(matches)
                self.assertTrue(all(item["supporting_evidence"][0]["file"] == path for item in matches))
        for rule_id, cases in negatives.items():
            for index, head in enumerate(cases):
                path = f"tests/negative-{rule_id.lower()}-{index}.py" if rule_id != "GOV-TESTS-006" else f"src/negative-{index}.py"
                with self.subTest(rule_id=rule_id, path=path), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    values = {path: head}
                    inventory = build_inventory(root, values, content_by_path=values)
                    result = analyse_static(
                        root, inventory, paths=[path], base_contents={path: head},
                        head_contents={path: head}, changed_paths=[path], enabled_rules={rule_id},
                    )
                    self.assertFalse(result.candidates)

    def test_matrix_keeps_four_scenarios_and_uses_exact_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            partition = ChangePartition(("service.py",), ("tests/test_service.py",), (), (), ())
            base = {"service.py": "def load():\n    return 1\n", "tests/test_service.py": "def test_load():\n    assert True\n"}
            head = {"service.py": "def load():\n    return 2\n", "tests/test_service.py": "def test_load():\n    assert True\n"}
            config = {"commands": {"test": "python3 -c 'import sys; sys.exit(0)'"}}
            matrix = build_matrix(root, partition, config=config, base_contents=base, head_contents=head)
            self.assertEqual([item.scenario_id for item in matrix.scenarios], [
                "base-code-base-tests", "base-code-head-tests", "head-code-base-tests", "head-code-head-tests",
            ])
            approvals = {item.scenario_id: item.plan.approval_digest for item in matrix.scenarios if item.plan is not None}
            with patch(
                "dissect_checks.test_integrity.evidence_matrix.execute_approved_plan",
                return_value=(subprocess.CompletedProcess([], 0, "", ""), None),
            ):
                executed = execute_approved_matrix(matrix, approvals)
            self.assertEqual(executed.status, "complete")
            self.assertTrue(all(item.result.completed and item.result.passed for item in executed.scenarios))

    def test_matrix_interpretation_keeps_the_four_questions_separate(self) -> None:
        results = {
            scenario: TestRunResult(scenario, "", 0 if scenario != "base-code-head-tests" else 1, True, scenario != "base-code-head-tests", 1, (), "")
            for scenario in SCENARIO_IDS
        }
        scenarios = tuple(
            MatrixScenario(scenario, "base", "base", {}, (), None, results[scenario])
            for scenario in SCENARIO_IDS
        )
        self.assertEqual(interpret_matrix(scenarios)["outcome"], "distinguishes_base_and_head")

    def test_unverified_repeated_runs_are_not_called_stable(self) -> None:
        result = TestRunResult(SCENARIO_IDS[0], "", None, False, None, None, (), "")
        self.assertEqual(flakiness_evidence([result])["status"], "not_verified")

    def test_complexity_uses_known_mccabe_values_and_policy_override(self) -> None:
        source = "def branch(value):\n    if value:\n        return 1\n    return 0\n"
        functions = extract_functions("branch.py", source)
        self.assertEqual([(item.qualified_name, item.cyclomatic) for item in functions], [("branch( value )", 2)])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text("[tool.ruff.lint.mccabe]\nmax-complexity = 7\n")
            self.assertEqual(resolve_policy(root, "python")["threshold"], 7)
            self.assertEqual(repository_policy(root, "python")["source"], "repository")

    def test_complexity_diff_reports_growth_and_parse_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            head = "\n".join([
                "def branch(value):",
                "    if value > 0:",
                "        return 1",
                "    if value > 1:",
                "        return 2",
                "    return 0",
            ]) + "\n"
            base = "def branch(value):\n    return 0\n"
            result = analyse_complexity(
                root,
                ["branch.py"],
                mode="diff",
                config={"review_options": {"analysis_limits": {"complexity_fallback_threshold": 1}}},
                base_contents={"branch.py": base},
                head_contents={"branch.py": head},
                changed_ranges={"branch.py": [(1, 6)]},
            )
            self.assertTrue(result.candidates)
            self.assertEqual(result.candidates[0].function.logical_path, "branch.py")
            malformed = analyse_complexity(
                root,
                ["branch.py"],
                config={"review_options": {"analysis_limits": {"complexity_fallback_threshold": 1}}},
                head_contents={"branch.py": "def broken(:\n"},
            )
            self.assertEqual(malformed.status, "partial")
            self.assertEqual(malformed.reason_code, "parse_error")

    def test_proof_patch_is_test_only_and_requires_independent_oracle(self) -> None:
        candidate = ProofCandidate("candidate-1", "The service rejects the request.", "public_contract", "ISSUE-1", ("service.load",), "fail", "known_good")
        production_patch = "--- a/service.py\n+++ b/service.py\n@@ -1 +1 @@\n-return 1\n+return 2\n"
        valid, errors = validate_test_patch(Path.cwd(), production_patch, candidate)
        self.assertFalse(valid)
        self.assertTrue(any("non-test path" in error for error in errors))
        self.assertEqual(proof_outcome(candidate, current_passed=True, control_passed=False, reachability="confirmed"), "disproved")

    def test_removal_needs_execution_and_unique_protection_evidence(self) -> None:
        self.assertEqual(
            removal_decision(
                has_unique_contract=False,
                reaches_unique_subject=False,
                unique_kills=False,
                passes_reverted_hunk=True,
                passes_base_and_head=True,
                independent_oracle=True,
                stable=True,
                sole_structural_check=False,
                execution_verified=True,
            ),
            "remove",
        )
        self.assertEqual(
            removal_decision(
                has_unique_contract=False,
                reaches_unique_subject=False,
                unique_kills=True,
                passes_reverted_hunk=True,
                passes_base_and_head=True,
                independent_oracle=True,
                stable=True,
                sole_structural_check=False,
                execution_verified=True,
            ),
            "keep",
        )


if __name__ == "__main__":
    unittest.main()
