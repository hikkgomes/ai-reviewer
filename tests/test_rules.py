from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dissect_checks.engine import scan_text
from dissect_checks.legacy import (
    LEGACY_EXPECTED_CHECK_IDS,
    LEGACY_RULES,
    scan_legacy,
    validate_legacy_fixtures,
)
from dissect_checks.rules import RULES, validate_rule_fixtures


class RuleFixtureTests(unittest.TestCase):
    def test_every_structured_rule_has_positive_and_negative_fixture(self) -> None:
        self.assertEqual(validate_rule_fixtures(), [])
        self.assertTrue(all(rule.positive_fixture and rule.negative_fixture for rule in RULES))

    def test_every_preserved_legacy_rule_has_positive_and_negative_fixture(self) -> None:
        self.assertEqual(validate_legacy_fixtures(), [])
        for rule in LEGACY_RULES:
            suffix = rule.suffixes[0] if rule.suffixes else ".py"
            path = f"src/fixture{suffix}"
            with self.subTest(check_id=rule.check_id):
                self.assertIn(
                    rule.check_id,
                    {item.check_id for item in scan_legacy(path, rule.positive)},
                )
                self.assertNotIn(
                    rule.check_id,
                    {item.check_id for item in scan_legacy(path, rule.negative)},
                )

    def test_complete_legacy_detector_baseline_cannot_shrink_silently(self) -> None:
        expected = {
            "LEG-PLACEHOLDER-001", "COR-EXC-001", "SEC-INJECT-001",
            "SEC-TLS-001", "SEC-DATA-LEGACY-001", "SEC-INJECT-002",
            "LEG-CONFIG-001", "SEC-SECRETS-LEGACY-001", "LEG-DEBUG-001",
            "LEG-DEAD-001", "SEC-CODE-001", "COR-JS-001",
            "COR-CONFIG-001", "SEC-DESER-001", "COR-EXC-002",
            "LEG-CONFIG-002", "LEG-MAGIC-001", "COR-EXC-003",
            "COR-PY-001", "COR-GO-001", "COR-GO-002", "COR-CS-001",
            "COR-SQL-001", "COR-SQL-002", "COR-PHP-001",
            "LEG-NAMING-001", "LEG-TODO-001", "LEG-LONG-FUNCTION-001",
            "LEG-DOCSTRING-001", "LEG-TS-ASSERT-001",
            "LEG-PHP-STRICT-001", "LEG-RUST-REFCELL-001",
            "LEG-MAGIC-STRING-001", "SUP-DEPENDENCY-002",
            "SUP-DEPENDENCY-004",
        }
        custom = {
            "LEG-TODO-001", "LEG-LONG-FUNCTION-001", "LEG-DOCSTRING-001",
            "LEG-TS-ASSERT-001", "LEG-PHP-STRICT-001",
            "LEG-RUST-REFCELL-001", "LEG-MAGIC-STRING-001",
            "SUP-DEPENDENCY-002", "SUP-DEPENDENCY-004",
        }
        self.assertEqual(LEGACY_EXPECTED_CHECK_IDS, expected)
        self.assertEqual({rule.check_id for rule in LEGACY_RULES}, expected - custom)

    def test_custom_legacy_detectors_have_positive_and_negative_cases(self) -> None:
        cases = {
            "LEG-TODO-001": (
                "src/code.py", "\n".join("# TODO" for _ in range(6)), "# TODO once",
            ),
            "LEG-LONG-FUNCTION-001": (
                "src/code.py",
                "def long():\n" + "\n".join("    value = 1" for _ in range(82)),
                "def short():\n    return 1",
            ),
            "LEG-DOCSTRING-001": (
                "src/code.py",
                'def documented():\n    """a\nb\nc\nd\ne\nf\n"""\n    return 1',
                'def documented():\n    """short"""\n    return 1',
            ),
            "LEG-TS-ASSERT-001": (
                "src/code.ts",
                "\n".join(f"const v{i} = input as any;" for i in range(6)),
                "const value = input as string;",
            ),
            "LEG-PHP-STRICT-001": (
                "src/code.php",
                "<?php\nfunction run() {}",
                "<?php\ndeclare(strict_types=1);\nfunction run() {}",
            ),
            "LEG-RUST-REFCELL-001": (
                "src/code.rs",
                "Rc<RefCell<A>> Rc<RefCell<B>> Rc<RefCell<C>>",
                "Rc<RefCell<A>>",
            ),
            "LEG-MAGIC-STRING-001": (
                "src/code.py",
                "\n".join(['value = "repeated-value"'] * 4),
                'value = "repeated-value"',
            ),
        }
        for check_id, (path, positive, negative) in cases.items():
            with self.subTest(check_id=check_id):
                self.assertIn(check_id, {item.check_id for item in scan_legacy(path, positive)})
                self.assertNotIn(check_id, {item.check_id for item in scan_legacy(path, negative)})

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
