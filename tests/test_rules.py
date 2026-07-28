from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dissect_checks.engine import scan_text
from dissect_checks.legacy import validate_legacy_fixtures
from dissect_checks.rules import RULES, validate_rule_fixtures


class RuleFixtureTests(unittest.TestCase):
    def test_every_structured_rule_has_positive_and_negative_fixture(self) -> None:
        self.assertEqual(validate_rule_fixtures(), [])
        self.assertTrue(all(rule.positive_fixture and rule.negative_fixture for rule in RULES))

    def test_every_preserved_legacy_rule_has_positive_and_negative_fixture(self) -> None:
        self.assertEqual(validate_legacy_fixtures(), [])

    def test_required_security_fixture_corpus(self) -> None:
        cases = json.loads((ROOT / "tests" / "fixtures" / "security_cases.json").read_text())
        for case in cases["vulnerable"]:
            with self.subTest(case=case["name"]):
                ids = {finding.check_id for finding in scan_text(case["path"], case["code"])}
                self.assertTrue(set(case["expected"]) <= ids, (case["name"], ids))
        for case in cases["safe"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(scan_text(case["path"], case["code"]), [])


if __name__ == "__main__":
    unittest.main()
