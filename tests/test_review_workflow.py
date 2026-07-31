from __future__ import annotations

import json
from pathlib import Path
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
