from __future__ import annotations

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
            self.assertIn("copy", findings[0].source)

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
