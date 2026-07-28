from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dissect_checks.engine import ScanOptions, scan_paths, scan_report, scan_text


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
            tracked.write_text("const key=getStripeKey();")
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
                {
                    "complete", "coverage_errors", "findings", "options",
                    "scanner", "schema_version", "summary",
                },
            )
            self.assertIn("remediation", payload["findings"][0])
            self.assertNotIn("sk_live_1234567890abcdefghij", result.stdout)

    def test_file_list_limits_diff_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bad.ts").write_text("const key='sk_live_1234567890abcdefghij';")
            (root / "safe.ts").write_text("const key=getKey();")
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

    def test_unknown_python_import_has_positive_and_negative_cases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app.py"
            source.write_text("import hallucinated_review_package\n")
            self.assertIn(
                "SUP-DEPENDENCY-004",
                {item.check_id for item in scan_paths(ScanOptions(root=root))},
            )
            source.write_text("import json\n")
            self.assertNotIn(
                "SUP-DEPENDENCY-004",
                {item.check_id for item in scan_paths(ScanOptions(root=root))},
            )

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

    def test_secret_evidence_is_redacted_centrally(self) -> None:
        raw = "sk_live_1234567890abcdefghij"
        findings = scan_text("config.ts", f"const key='{raw}';")
        secret_findings = [item for item in findings if item.category == "secrets"]
        self.assertTrue(secret_findings)
        for finding in secret_findings:
            self.assertNotIn(raw, finding.evidence)
            self.assertIn("sha256=", finding.evidence)
        repeated = scan_text(
            "config.py",
            "\n".join(f'value = "{raw}"' for _ in range(4)),
        )
        self.assertTrue(repeated)
        self.assertTrue(all(raw not in finding.evidence for finding in repeated))

    def test_server_side_supabase_service_role_name_is_not_secret_exposure(self) -> None:
        findings = scan_text(
            "server/supabase.ts",
            "const key = process.env.SUPABASE_SERVICE_ROLE_KEY;",
        )
        self.assertNotIn("SEC-SECRETS-001", {item.check_id for item in findings})

    def test_content_marker_cannot_disable_scanning(self) -> None:
        findings = scan_text(
            "src/vulnerable.ts",
            "// dissect: scanner-definition\nconst key='sk_live_1234567890abcdefghij';",
        )
        self.assertIn("SEC-SECRETS-002", {item.check_id for item in findings})

    def test_diff_history_is_limited_to_file_list(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
            subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=root, check=True)
            (root / "in-scope.ts").write_text("export const ok = true;")
            (root / "unrelated.ts").write_text("const key='sk_live_1234567890abcdefghij';")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "history"], cwd=root, check=True)
            findings = scan_paths(ScanOptions(
                root=root,
                include_history=True,
                file_list=("in-scope.ts",),
            ))
            self.assertFalse(any(item.path == "unrelated.ts" for item in findings))

    def test_monorepo_uses_nearest_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for package in ("a", "b"):
                (root / "packages" / package).mkdir(parents=True)
            (root / "package-lock.json").write_text('{"lockfileVersion":3}')
            (root / "packages" / "a" / "package.json").write_text(
                '{"dependencies":{"react":"18.0.0"}}'
            )
            (root / "packages" / "b" / "package.json").write_text(
                '{"dependencies":{"left-pad":"1.3.0"}}'
            )
            source = root / "packages" / "a" / "app.ts"
            source.write_text("import leftPad from 'left-pad';")
            findings = scan_paths(ScanOptions(root=root))
            dependency = [
                item for item in findings
                if item.check_id == "SUP-DEPENDENCY-002" and item.path.endswith("a/app.ts")
            ]
            self.assertEqual(len(dependency), 1)
            self.assertIn("packages/a/package.json", dependency[0].explanation)

    def test_history_failure_marks_report_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = scan_report(ScanOptions(
                root=Path(directory),
                include_history=True,
            ))
            self.assertFalse(report.complete)
            self.assertTrue(report.coverage_errors)

    def test_individual_history_read_failure_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bad.ts").write_text("export const ok = true;")
            responses = [
                subprocess.CompletedProcess([], 0, stdout="deadbeef\n", stderr=""),
                subprocess.CompletedProcess([], 0, stdout="bad.ts\n", stderr=""),
                subprocess.CompletedProcess([], 128, stdout="", stderr="missing"),
            ]
            with patch("dissect_checks.engine.subprocess.run", side_effect=responses):
                report = scan_report(ScanOptions(
                    root=root,
                    include_history=True,
                    file_list=("bad.ts",),
                ))
            self.assertFalse(report.complete)
            self.assertIn("could not read bad.ts", report.coverage_errors[0])


if __name__ == "__main__":
    unittest.main()
