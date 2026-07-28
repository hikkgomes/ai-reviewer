# dissect: scanner-definition
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dissect_checks.engine import ScanOptions, scan_paths


class ScannerTests(unittest.TestCase):
    def test_generated_bundle_is_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "dist" / "app.js"
            bundle.parent.mkdir()
            bundle.write_text("const key='sk_live_1234567890abcdefghij';")
            self.assertEqual(scan_paths(ScanOptions(root=root)), [])
            findings = scan_paths(
                ScanOptions(root=root, include_generated=True, ignore=("dist/",))
            )
            self.assertIn("SEC-SECRETS-002", {item.check_id for item in findings})

    def test_git_history_scan_is_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
            subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=root, check=True)
            tracked = root / "config.ts"
            tracked.write_text("const key='sk_live_1234567890abcdefghij';")
            subprocess.run(["git", "add", "config.ts"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "credential fixture"], cwd=root, check=True)
            tracked.write_text("const key=process.env.STRIPE_KEY;")
            subprocess.run(["git", "add", "config.ts"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "remove fixture"], cwd=root, check=True)
            self.assertEqual(scan_paths(ScanOptions(root=root)), [])
            findings = scan_paths(ScanOptions(root=root, include_history=True))
            self.assertTrue(any(item.source.startswith("git:") for item in findings))

    def test_json_output_schema_and_ci_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bad.ts").write_text("const key='sk_live_1234567890abcdefghij';")
            script = ROOT / "scripts" / "scan_ai_gotchas.py"
            result = subprocess.run(
                [sys.executable, str(script), "--format", "json", "--fail-on", "critical"],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["schema_version"], "1.0")
            self.assertEqual(
                set(payload),
                {"complete", "findings", "options", "scanner", "schema_version", "summary"},
            )
            self.assertIn("remediation", payload["findings"][0])

    def test_file_list_limits_diff_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bad.ts").write_text("const key='sk_live_1234567890abcdefghij';")
            (root / "safe.ts").write_text("const key=process.env.KEY;")
            findings = scan_paths(ScanOptions(root=root, file_list=("safe.ts",)))
            self.assertEqual(findings, [])

    def test_undeclared_import_and_missing_lockfile_are_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text('{"dependencies":{"react":"18.0.0"}}')
            (root / "app.ts").write_text("import thing from 'react-router-dmo';")
            findings = scan_paths(ScanOptions(root=root))
            ids = {item.check_id for item in findings}
            self.assertIn("SUP-DEPENDENCY-002", ids)
            self.assertIn("SUP-DEPENDENCY-003", ids)
            self.assertTrue(all(item.disposition == "review-candidate" for item in findings))

    def test_declared_import_with_lockfile_is_not_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text('{"dependencies":{"react":"18.0.0"}}')
            (root / "package-lock.json").write_text('{"lockfileVersion":3}')
            (root / "app.ts").write_text("import React from 'react';")
            self.assertEqual(
                scan_paths(ScanOptions(root=root, file_list=("app.ts",))),
                [],
            )


if __name__ == "__main__":
    unittest.main()
