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


if __name__ == "__main__":
    unittest.main()
