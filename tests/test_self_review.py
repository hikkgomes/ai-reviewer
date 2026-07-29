from __future__ import annotations

from pathlib import Path
import sys
import unittest

from fixture_support import synthetic

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dissect_checks.engine import ScanOptions, _ignored, scan_report, scan_text
from dissect_checks.fixtures import mask_owned_fixture_spans


class SelfReviewTests(unittest.TestCase):
    def test_actual_repository_has_no_high_or_critical_fixture_findings(self) -> None:
        report = scan_report(ScanOptions(root=ROOT))
        severe = [
            finding for finding in report.findings
            if finding.severity in {"high", "critical"}
        ]
        self.assertEqual(severe, [], [(item.path, item.line, item.check_id) for item in severe])

    def test_structured_fixture_span_is_masked_but_real_secret_and_line_survive(self) -> None:
        real = synthetic("sk_live_" + "ZYXWVUTSRQPONMLK987654321")
        path = "scripts/dissect_checks/rules.py"
        text = (ROOT / path).read_text(encoding="utf-8")
        expected_line = len(text.splitlines()) + 2
        text += f"\nREAL_CREDENTIAL = '{real}'\n"
        masked = mask_owned_fixture_spans(ROOT, path, text)
        secrets = [
            item for item in scan_text(path, masked)
            if item.check_id == "SEC-SECRETS-002"
        ]
        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0].line, expected_line)

    def test_arbitrary_fixture_marker_never_suppresses_target_repository(self) -> None:
        findings = scan_text(
            "app.py",
            synthetic(
                "# synthetic fixture\nkey = 'sk_live_"
                + "ZYXWVUTSRQPONMLK987654321'\n"
            ),
        )
        self.assertIn("SEC-SECRETS-002", {item.check_id for item in findings})

    def test_dedicated_json_fixture_exclusion_is_exact(self) -> None:
        options = ScanOptions(root=ROOT)
        self.assertTrue(_ignored("tests/fixtures/security_cases.json", options))
        self.assertFalse(_ignored("tests/fixtures/other.json", options))


if __name__ == "__main__":
    unittest.main()
