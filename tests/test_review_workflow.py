from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_review_context import build  # noqa: E402
from review_ledger import blank_candidate, final_findings, transition, validate_ledger  # noqa: E402
from score_review_results import score  # noqa: E402
from validate_review_result import validate  # noqa: E402
from compare_review_runs import compare  # noqa: E402
from run_benchmarks import prepare_codex_environment, run_one, tree_manifest  # noqa: E402


class ReviewWorkflowTests(unittest.TestCase):
    def test_context_records_missing_intent_and_behavioural_units(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "routes.py").write_text("def update_invoice(request):\n    return request.json\n")
            context = build(root, "diff", "", None)
            self.assertEqual(context["intent"]["summary"], "")
            self.assertTrue(context["intent"]["ambiguities"])
            self.assertEqual(context["behavioural_units"][0]["kind"], "endpoint/server-action")
            self.assertIn("routes.py", context["scope"]["files"])

    def test_scanner_candidate_is_not_verified_automatically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config.py").write_text("try:\n    value = 1\nexcept Exception:\n    pass\n")
            context = build(root, "full", "", None)
            self.assertTrue(context["candidates"])
            self.assertTrue(all(item["status"] == "candidate" for item in context["candidates"]))

    def test_context_loads_intent_and_correlates_cross_file_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "intent.md").write_text("Only the authenticated tenant may read an invoice.\n")
            (root / "route.py").write_text("from fastapi import APIRouter\nfrom service import load_invoice\ndef get_invoice(request):\n    return load_invoice(request.params['id'])\n")
            (root / "service.py").write_text("def load_invoice(invoice_id):\n    return db.find(invoice_id)\n")
            context = build(root, "full", "", None)
            self.assertIn("authenticated tenant", context["intent"]["summary"])
            self.assertTrue(context["repository"]["framework_packs"])
            unit = next(item for item in context["behavioural_units"] if item["kind"] == "endpoint/server-action")
            self.assertTrue(unit["changed_symbols"])
            self.assertTrue(unit["state_read"] or unit["outputs"])
            self.assertTrue(any(any(item["path"] == "route.py" for item in candidate["callers"]) for candidate in context["behavioural_units"]))
            self.assertTrue(context["repository"]["touchpoints"]["routes"])

    def test_context_error_paths_are_semantic_lines_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "worker.py").write_text(
                "import json\n"
                "\n"
                "def normal(value):\n"
                "    return value\n"
                "try:\n"
                "    send(value)\n"
                "except TimeoutError:\n"
                "    retry()\n"
                "    raise\n"
                "finally:\n"
                "    rollback()\n"
                "catch(error)\n"
                "throw error\n"
                "timeout = 1\n"
                "fallback()\n"
            )
            first = build(root, "full", "", None)
            second = build(root, "full", "", None)
            self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
            errors = next(unit["error_paths"] for unit in first["behavioural_units"] if "worker.py" in unit["entry_points"])
            self.assertNotIn("import json", errors)
            self.assertNotIn("", errors)
            self.assertNotIn("def normal(value):", errors)
            self.assertNotIn("return value", errors)
            for expected in (
                "except TimeoutError:", "retry()", "raise", "finally:", "rollback()",
                "catch(error)", "throw error", "timeout = 1", "fallback()",
            ):
                self.assertIn(expected, errors)

    def test_benchmark_environment_installs_only_the_tested_skill(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_home = Path(directory) / "source-codex-home"
            (source_home / "skills" / "old-dissect").mkdir(parents=True)
            (source_home / "skills" / "old-dissect" / "SKILL.md").write_text("old\n")
            (source_home / "auth.json").write_text("{\"token\": \"fixture\"}\n")
            (source_home / "config.toml").write_text("model = \"fixture\"\n")
            previous = os.environ.get("CODEX_HOME")
            os.environ["CODEX_HOME"] = str(source_home)
            try:
                codex_home, skill, environment = prepare_codex_environment()
            finally:
                if previous is None:
                    os.environ.pop("CODEX_HOME", None)
                else:
                    os.environ["CODEX_HOME"] = previous
            try:
                self.assertEqual(skill, codex_home / "skills" / "dissect-full")
                self.assertIn("name: dissect-full", (skill / "SKILL.md").read_text())
                self.assertTrue((skill / "reference" / "review-workflow.md").exists())
                self.assertEqual((codex_home / "auth.json").read_text(), "{\"token\": \"fixture\"}\n")
                self.assertEqual((codex_home / "config.toml").read_text(), "model = \"fixture\"\n")
                self.assertEqual(environment["CODEX_HOME"], str(codex_home))
                self.assertFalse((codex_home / "skills" / "old-dissect").exists())
                self.assertEqual(environment["HOME"], str(codex_home / "home"))
                self.assertTrue(tree_manifest(skill)["files"])
            finally:
                shutil.rmtree(codex_home)

    def test_result_fixture_uses_unambiguous_reviewer_commit_name(self) -> None:
        result = json.loads((ROOT / "tests" / "fixtures" / "sample-review-result.json").read_text())
        self.assertNotIn("commit_under_review", result["provenance"])
        self.assertIn("reviewer_source_commit", result["provenance"])

    def test_benchmark_run_does_not_reuse_stale_final_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proposed = root / "proposed"
            proposed.mkdir()
            (proposed / "routes.py").write_text("def get_value():\n    return 1\n")
            (root / "intent.md").write_text("Return the value.\n")
            manifest = root / "benchmark.json"
            manifest.write_text(json.dumps({"id": "stale-output", "proposed": "proposed"}))
            output = root / "results"
            output.mkdir()
            stale = output / "agent-stale-output.json"
            stale.write_text(json.dumps({"status": "complete", "findings": [{"id": "stale"}]}))

            fake_codex = root / "fake-codex"
            fake_codex.write_text(
                "#!" + sys.executable + "\n"
                "import json, pathlib, sys\n"
                "if '--version' in sys.argv:\n"
                "    print('fixture-codex 1.0')\n"
                "    raise SystemExit(0)\n"
                "output = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])\n"
                "output.write_text(json.dumps({\n"
                "    'schema_version': '1.0', 'mode': 'full', 'findings': [],\n"
                "    'open_questions': [], 'not_verified': [], 'coverage': {},\n"
                "    'candidates': [], 'ledger': [],\n"
                "    'provenance': {'commit_under_review': 'stale', 'model_identifier': 'fixture-model'}\n"
                "}))\n"
            )
            fake_codex.chmod(0o755)
            codex_home, skill, environment = prepare_codex_environment()
            try:
                result = run_one(manifest, output, skill, str(fake_codex), environment)
            finally:
                shutil.rmtree(codex_home)
            self.assertEqual(result["findings"], [])
            self.assertNotIn("commit_under_review", result["provenance"])
            self.assertEqual(result["provenance"]["model_identifier"], "fixture-model")

    def test_verified_transition_requires_falsification_and_verification(self) -> None:
        candidate = blank_candidate("candidate-1", source="semantic", claim="wrong owner", contract="tenant isolation")
        candidate["falsification_attempts"].append({"result": "no wrapper or predicate found"})
        candidate["verification_attempts"].append({"result": "focused reproduction"})
        candidate = transition(candidate, "verified")
        self.assertEqual(final_findings([candidate]), [candidate])
        self.assertEqual(validate_ledger({"candidates": [candidate]}), [])

    def test_disproved_candidates_are_not_final_findings(self) -> None:
        candidate = blank_candidate("candidate-2", source="deterministic", claim="suspicious route", contract="auth")
        candidate = transition(candidate, "disproved", evidence={"result": "auth middleware covers mounted router"})
        self.assertEqual(final_findings([candidate]), [])

    def test_scorer_reports_precision_recall_without_composite_score(self) -> None:
        expected = {"id": "case", "expected_findings": [{"id": "F-1", "location": "routes.py", "severity": "high"}], "expected_severity": {"F-1": ["high"]}, "required_not_verified": ["runtime"]}
        result = {"findings": [{"id": "F-1", "location": "routes.py:4", "severity": "high"}], "not_verified": ["runtime"]}
        output = score(expected, result)
        self.assertEqual(output["critical_high_recall"], 1.0)
        self.assertEqual(output["finding_precision"], 1.0)
        self.assertNotIn("overall_score", output)

    def test_schema_and_benchmark_manifests_are_json(self) -> None:
        for path in (ROOT / "reference" / "review-context-schema.json", ROOT / "reference" / "review-result-schema.json", ROOT / "benchmarks" / "schema.json"):
            json.loads(path.read_text())

    def test_result_validator_requires_verified_ledger_backing(self) -> None:
        result = json.loads((ROOT / "tests" / "fixtures" / "sample-review-result.json").read_text())
        result["findings"] = [{"id": "F-1", "candidate_id": "missing", "severity": "high", "confidence": "high", "location": "x:1", "contract": "c", "trigger_path": "p", "impact": "i", "evidence": ["e"], "fix": "f", "verification": "v"}]
        errors = validate(result)
        self.assertTrue(any("candidate_id is not verified" in error for error in errors))

    def test_result_validator_accepts_provenance_and_empty_not_run_result(self) -> None:
        result = json.loads((ROOT / "tests" / "fixtures" / "sample-review-result.json").read_text())
        self.assertEqual(validate(result), [])

    def test_comparison_reports_deltas_and_no_composite_score(self) -> None:
        baseline = {"case": {"benchmark_id": "case", "finding_precision": 0.5, "critical_high_recall": 0.0}}
        current = {"case": {"benchmark_id": "case", "finding_precision": 1.0, "critical_high_recall": 1.0}}
        output = compare(current, baseline)
        self.assertEqual(output["cases"][0]["delta"]["finding_precision"], 0.5)
        self.assertIsNone(output["composite_score"])


if __name__ == "__main__":
    unittest.main()
