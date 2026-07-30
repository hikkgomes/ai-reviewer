from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from fixture_support import synthetic


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dissect_checks.engine import ScanOptions, scan_report


SECRET = synthetic("sk_live_" + "ZYXWVUTSRQPONMLK987654321")


def initialise(root: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=root, check=True)


def commit(root: Path, message: str) -> None:
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", message], cwd=root, check=True)


def secret_findings(report):
    return [item for item in report.findings if item.check_id == "SEC-SECRETS-002"]


class HistoryLineageTests(unittest.TestCase):
    def test_identical_secret_occurrences_receive_only_their_own_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            target = root / "app.ts"
            target.write_text(
                f"function oldPlace() {{\n  const key = '{SECRET}';\n  return 1;\n}}\n"
            )
            commit(root, "first occurrence")
            target.write_text(target.read_text() + (
                f"\nfunction newPlace() {{\n  const key = '{SECRET}';\n  return 2;\n}}\n"
            ))
            report = scan_report(ScanOptions(root=root, include_history=True))
            findings = secret_findings(report)
            self.assertEqual(len(findings), 2)
            old, new = sorted(findings, key=lambda item: item.line)
            self.assertTrue(old.historical_sources)
            self.assertEqual(new.historical_sources, ())
            self.assertNotEqual(old.occurrence_id, new.occurrence_id)

    def test_two_history_only_occurrences_remain_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            target = root / "app.ts"
            target.write_text(
                f"function one() {{\n const key = '{SECRET}';\n return 1;\n}}\n"
                f"function two() {{\n const key = '{SECRET}';\n return 2;\n}}\n"
            )
            commit(root, "two occurrences")
            target.write_text("const safe = true;\n")
            commit(root, "remove both")
            findings = secret_findings(scan_report(
                ScanOptions(root=root, include_history=True)
            ))
            self.assertEqual(len(findings), 2)
            self.assertEqual(len({item.context_fingerprint for item in findings}), 2)

    def test_removed_occurrence_does_not_contaminate_remaining_occurrence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            target = root / "app.ts"
            target.write_text(
                f"function stays() {{\n const key = '{SECRET}';\n return 1;\n}}\n"
                f"function removed() {{\n const key = '{SECRET}';\n return 2;\n}}\n"
            )
            commit(root, "both")
            target.write_text(
                f"function stays() {{\n const key = '{SECRET}';\n return 1;\n}}\n"
            )
            commit(root, "remove one")
            findings = secret_findings(scan_report(
                ScanOptions(root=root, include_history=True)
            ))
            self.assertEqual(len(findings), 2)
            current = next(item for item in findings if item.source == "working-tree")
            history_only = next(item for item in findings if item.source != "working-tree")
            self.assertTrue(current.historical_sources)
            self.assertNotEqual(
                current.context_fingerprint,
                history_only.context_fingerprint,
            )

    def test_ambiguous_identical_context_preserves_history_separately(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            target = root / "app.ts"
            block = (
                f"const key = '{SECRET}';\n"
                "const tail = true;\n"
                "const tailTwo = true;\n"
            )
            target.write_text(block + "\n" + block)
            commit(root, "ambiguous twins")
            target.write_text(block)
            commit(root, "remove indistinguishable twin")
            findings = secret_findings(scan_report(
                ScanOptions(root=root, include_history=True)
            ))
            current = [item for item in findings if item.source == "working-tree"]
            history_only = [item for item in findings if item.source != "working-tree"]
            self.assertEqual(len(current), 1)
            self.assertEqual(current[0].historical_sources, ())
            self.assertTrue(history_only)

    def test_secret_removed_during_rename_follows_old_lineage_for_both_scopes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            old = root / "old.ts"
            old.write_text("\n".join([f"const safe{i} = {i};" for i in range(30)] + [
                f"const key = '{SECRET}';",
            ]))
            commit(root, "old secret")
            old.rename(root / "new.ts")
            (root / "new.ts").write_text(
                "\n".join(f"const safe{i} = {i};" for i in range(30))
            )
            commit(root, "rename and remove secret")
            for scoped_path in ("new.ts", "old.ts"):
                with self.subTest(scope=scoped_path):
                    report = scan_report(ScanOptions(
                        root=root,
                        include_history=True,
                        file_list=(scoped_path,),
                    ))
                    self.assertTrue(report.complete, report.coverage_errors)
                    findings = secret_findings(report)
                    self.assertTrue(findings)
                    self.assertTrue(any("old.ts" in item.source for item in findings))
                    self.assertTrue(all(item.path == scoped_path for item in findings))
            combined = scan_report(ScanOptions(
                root=root,
                include_history=True,
                file_list=("old.ts", "new.ts"),
            ))
            self.assertEqual(
                {item.path for item in secret_findings(combined)},
                {"new.ts"},
            )

    def test_sequential_renames_and_duplicate_blob_findings_are_deduplicated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            (root / "one.ts").write_text(f"const key = '{SECRET}';\n")
            commit(root, "one")
            (root / "one.ts").rename(root / "two.ts")
            commit(root, "two")
            (root / "two.ts").rename(root / "three.ts")
            commit(root, "three")
            report = scan_report(ScanOptions(
                root=root,
                include_history=True,
                file_list=("three.ts",),
            ))
            self.assertTrue(report.complete, report.coverage_errors)
            findings = secret_findings(report)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].path, "three.ts")

    def test_full_history_canonicalises_three_renames_and_prefers_current_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            (root / "one.ts").write_text(f"const key = '{SECRET}';\n")
            commit(root, "one")
            for old, new in (
                ("one.ts", "two.ts"),
                ("two.ts", "three.ts"),
                ("three.ts", "four.ts"),
            ):
                (root / old).rename(root / new)
                commit(root, new)
            (root / "four.ts").write_text(
                "\n\n" + (root / "four.ts").read_text()
            )
            commit(root, "move current line")
            report = scan_report(ScanOptions(root=root, include_history=True))
            self.assertTrue(report.complete, report.coverage_errors)
            findings = secret_findings(report)
            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertEqual(finding.path, "four.ts")
            self.assertEqual(finding.line, 3)
            self.assertEqual(finding.source, "working-tree")
            self.assertGreaterEqual(len(finding.historical_sources), 4)
            self.assertEqual(
                {"one.ts", "two.ts", "three.ts", "four.ts"},
                {source.path for source in finding.historical_sources},
            )

    def test_full_history_two_renames_with_content_change_is_one_lineage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            (root / "one.ts").write_text(f"const key = '{SECRET}';\n")
            commit(root, "one")
            (root / "one.ts").rename(root / "two.ts")
            (root / "two.ts").write_text(
                "// changed during rename\n" + (root / "two.ts").read_text()
            )
            commit(root, "rename and modify")
            (root / "two.ts").rename(root / "three.ts")
            commit(root, "second rename")
            report = scan_report(ScanOptions(root=root, include_history=True))
            findings = secret_findings(report)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].path, "three.ts")
            self.assertEqual(findings[0].line, 2)
            self.assertEqual(findings[0].source, "working-tree")

    def test_removed_secret_is_history_only_with_multiple_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            target = root / "removed.ts"
            target.write_text(f"const key = '{SECRET}';\n")
            commit(root, "secret")
            target.write_text("\n" + target.read_text())
            commit(root, "line change")
            target.write_text("const safe = true;\n")
            commit(root, "remove")
            report = scan_report(ScanOptions(root=root, include_history=True))
            findings = secret_findings(report)
            self.assertEqual(len(findings), 1)
            self.assertTrue(findings[0].source.startswith("git:"))
            self.assertGreaterEqual(len(findings[0].historical_sources), 2)
            self.assertEqual(
                {1, 2},
                {source.line for source in findings[0].historical_sources},
            )

    def test_copy_then_rename_keeps_copy_and_source_lineages_separate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            source = root / "source.ts"
            source.write_text(f"const key = '{SECRET}';\n")
            commit(root, "source")
            (root / "copy.ts").write_text(source.read_text())
            commit(root, "copy")
            (root / "copy.ts").rename(root / "renamed-copy.ts")
            commit(root, "rename copy")
            report = scan_report(ScanOptions(root=root, include_history=True))
            findings = secret_findings(report)
            self.assertEqual(
                {"source.ts", "renamed-copy.ts"},
                {finding.path for finding in findings},
            )
            self.assertEqual(len(findings), 2)

    def test_rename_across_merge_parents_does_not_duplicate_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            (root / "old.ts").write_text(f"const key = '{SECRET}';\n")
            commit(root, "base")
            main_branch = subprocess.run(
                ["git", "branch", "--show-current"],
                cwd=root,
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip()
            subprocess.run(["git", "checkout", "-qb", "rename"], cwd=root, check=True)
            (root / "old.ts").rename(root / "new.ts")
            commit(root, "rename")
            subprocess.run(["git", "checkout", "-q", main_branch], cwd=root, check=True)
            (root / "side.txt").write_text("side\n")
            commit(root, "side")
            subprocess.run(
                ["git", "merge", "--no-ff", "-m", "merge rename", "rename"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            report = scan_report(ScanOptions(root=root, include_history=True))
            self.assertTrue(report.complete, report.coverage_errors)
            findings = secret_findings(report)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].path, "new.ts")
            self.assertEqual(findings[0].source, "working-tree")

    def test_text_and_json_distinguish_current_and_historical_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            (root / "app.ts").write_text(f"const key = '{SECRET}';\n")
            commit(root, "secret")
            script = ROOT / "scripts" / "scan_ai_gotchas.py"
            json_result = subprocess.run(
                [sys.executable, str(script), "--history", "--format", "json"],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(json_result.returncode, 0, json_result.stderr)
            payload = json.loads(json_result.stdout)
            finding = next(
                item for item in payload["findings"]
                if item["check_id"] == "SEC-SECRETS-002"
            )
            self.assertEqual(finding["source"], "working-tree")
            self.assertTrue(finding["historical_sources"])

            text_result = subprocess.run(
                [sys.executable, str(script), "--history", "--format", "text"],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(text_result.returncode, 0, text_result.stderr)
            self.assertIn("source=working-tree", text_result.stdout)
            self.assertIn("historical-source: git:", text_result.stdout)

    def test_root_commit_and_deleted_file_are_complete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            target = root / "deleted.ts"
            target.write_text(f"const key = '{SECRET}';\n")
            commit(root, "root")
            root_report = scan_report(ScanOptions(
                root=root, include_history=True, file_list=("deleted.ts",),
            ))
            self.assertTrue(root_report.complete, root_report.coverage_errors)
            target.unlink()
            commit(root, "delete")
            deleted_report = scan_report(ScanOptions(
                root=root, include_history=True, file_list=("deleted.ts",),
            ))
            self.assertTrue(deleted_report.complete, deleted_report.coverage_errors)
            self.assertTrue(secret_findings(deleted_report))

    def test_copy_ancestry_is_followed_only_for_scoped_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            source = root / "source.ts"
            source.write_text(f"const key = '{SECRET}';\n")
            commit(root, "source")
            (root / "copy.ts").write_text(source.read_text())
            commit(root, "copy")
            report = scan_report(ScanOptions(
                root=root, include_history=True, file_list=("copy.ts",),
            ))
            self.assertTrue(report.complete, report.coverage_errors)
            findings = secret_findings(report)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].path, "copy.ts")
            self.assertEqual(findings[0].source, "working-tree")
            self.assertTrue(any(
                "copy" in source.source for source in findings[0].historical_sources
            ))

    def test_nul_status_parsing_handles_spaces_and_tabs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            for name in ("with space.ts", "with\ttab.ts"):
                path = root / name
                path.write_text(f"const key = '{SECRET}';\n")
                commit(root, f"add {name!r}")
                report = scan_report(ScanOptions(
                    root=root, include_history=True, file_list=(name,),
                ))
                self.assertTrue(report.complete, report.coverage_errors)
                self.assertTrue(secret_findings(report))


if __name__ == "__main__":
    unittest.main()
