from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from fixture_support import synthetic

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dissect_checks.engine import ScanOptions, _ignored, scan_report, scan_text
from dissect_checks.fixtures import (
    is_trusted_self_review,
    mask_owned_fixture_spans,
    trusted_self_review_digest,
)


class SelfReviewTests(unittest.TestCase):
    def test_actual_repository_has_no_high_or_critical_fixture_findings(self) -> None:
        approval = trusted_self_review_digest(ROOT)
        self.assertIsNotNone(approval)
        report = scan_report(ScanOptions(
            root=ROOT,
            self_review_approval=approval or "",
        ))
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
        approval = trusted_self_review_digest(ROOT)
        masked = mask_owned_fixture_spans(ROOT, path, text, approval or "")
        secrets = [
            item for item in scan_text(path, masked)
            if item.check_id == "SEC-SECRETS-002"
        ]
        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0].line, expected_line)

    def test_modified_fixture_literal_is_not_covered_by_manifest_node(self) -> None:
        path = "scripts/dissect_checks/rules.py"
        text = (ROOT / path).read_text(encoding="utf-8")
        changed = synthetic("sk_live_" + "ZYXWVUTSRQPONMLK987654321")
        text = text.replace(
            "sk_live_1234567890abcdefghij",
            changed,
            1,
        )
        approval = trusted_self_review_digest(ROOT)
        masked = mask_owned_fixture_spans(ROOT, path, text, approval or "")
        secrets = [
            item for item in scan_text(path, masked)
            if item.check_id == "SEC-SECRETS-002"
        ]
        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0].line, 201)

    def test_arbitrary_fixture_marker_never_suppresses_target_repository(self) -> None:
        findings = scan_text(
            "app.py",
            synthetic(
                "# synthetic fixture\nkey = 'sk_live_"
                + "ZYXWVUTSRQPONMLK987654321'\n"
            ),
        )
        self.assertIn("SEC-SECRETS-002", {item.check_id for item in findings})

    def test_self_review_masking_requires_explicit_trusted_approval(self) -> None:
        text = (ROOT / "scripts" / "dissect_checks" / "rules.py").read_text()
        unapproved = mask_owned_fixture_spans(
            ROOT,
            "scripts/dissect_checks/rules.py",
            text,
        )
        self.assertEqual(unapproved, text)
        severe = [
            item for item in scan_report(ScanOptions(root=ROOT)).findings
            if item.severity in {"high", "critical"}
        ]
        self.assertTrue(severe)

    def test_copying_complete_fixture_owners_cannot_reuse_checkout_approval(self) -> None:
        authentic_approval = trusted_self_review_digest(ROOT)
        self.assertIsNotNone(authentic_approval)
        with tempfile.TemporaryDirectory() as directory:
            lookalike = Path(directory) / "lookalike"
            shutil.copytree(
                ROOT,
                lookalike,
                ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
            )
            subprocess.run(["git", "init", "-q"], cwd=lookalike, check=True)
            self.assertFalse(
                is_trusted_self_review(lookalike, authentic_approval or "")
            )
            path = "scripts/dissect_checks/rules.py"
            text = (lookalike / path).read_text()
            self.assertEqual(
                mask_owned_fixture_spans(
                    lookalike, path, text, authentic_approval or ""
                ),
                text,
            )

    def test_dedicated_json_fixture_exclusion_is_exact(self) -> None:
        approval = trusted_self_review_digest(ROOT)
        options = ScanOptions(root=ROOT, self_review_approval=approval or "")
        self.assertTrue(_ignored("tests/fixtures/security_cases.json", options))
        self.assertFalse(_ignored("tests/fixtures/other.json", options))


if __name__ == "__main__":
    unittest.main()
