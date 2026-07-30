from __future__ import annotations

import os
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from fixture_support import synthetic


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "dissect_diff_file_list",
    ROOT / "scripts" / "diff_file_list.py",
)
diff_file_list = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(diff_file_list)
changed_paths = diff_file_list.changed_paths
read_file_list = diff_file_list.read_file_list
changed_entries = diff_file_list.changed_entries
serialize_entries = diff_file_list.serialize_entries


def initialise(root: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=root, check=True)


def commit(root: Path, message: str) -> str:
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", message], cwd=root, check=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()


def review(root: Path, base: str) -> subprocess.CompletedProcess[str]:
    python = Path(shutil.which("python3.11") or sys.executable)
    return subprocess.run(
        ["bash", str(ROOT / "scripts" / "review_changed.sh"), base],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
        env={
            **os.environ,
            "PATH": f"{python.parent}:{os.environ.get('PATH', '')}",
        },
    )


def detected_languages(output: str) -> set[str]:
    marker = "== Detected languages ==\n"
    assert marker in output
    line = output.split(marker, 1)[1].splitlines()[0]
    return set() if line == "none" else set(line.split(", "))


class ReviewChangedLanguageTests(unittest.TestCase):
    def test_unusual_git_filenames_remain_exact_and_nul_delimited(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            old = "old name\tpart.py"
            deleted = "delete\nme.sql"
            (root / old).write_text("value = 1\n")
            (root / deleted).write_text("select 1;\n")
            base = commit(root, "unusual base")
            new = "renamed\n\u00fcnicode.py"
            (root / old).rename(root / new)
            (root / deleted).unlink()
            names = [
                new,
                deleted,
                "space name.ts",
                "tab\tname.go",
                "line\nbreak.py",
                "-leading.rs",
                "\u96ea.c",
            ]
            for name in names[2:]:
                content = (
                    f"secret = '{synthetic('sk_' + 'live_ZYXWVUTSRQPONMLK987654321')}'\n"
                    if name == "line\nbreak.py"
                    else "value = 1\n"
                )
                (root / name).write_text(content)

            raw_paths = changed_paths(root, f"{base}...HEAD")
            decoded = {
                value.decode("utf-8", errors="surrogateescape")
                for value in raw_paths
            }
            expected_paths = set(names) | {old}
            self.assertEqual(decoded, expected_paths)
            file_list = root / "paths.bin"
            file_list.write_bytes(b"\0".join(raw_paths) + b"\0")
            self.assertEqual(set(read_file_list(file_list)), expected_paths)

            result = review(root, base)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in expected_paths:
                self.assertIn(json.dumps(name, ensure_ascii=True), result.stdout)
            self.assertEqual(
                detected_languages(result.stdout),
                {"python", "sql", "typescript", "go", "rust", "cpp"},
            )

            scan = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "scan_ai_gotchas.py"),
                    "--format", "json",
                ],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
                env={**os.environ, "AI_REVIEW_FILE_LIST": str(file_list)},
            )
            payload = json.loads(scan.stdout)
            matching = [
                item for item in payload["findings"]
                if item["check_id"] == "SEC-SECRETS-002"
            ]
            self.assertEqual([item["path"] for item in matching], ["line\nbreak.py"])

    def test_clean_committed_diff_uses_generated_file_list(self) -> None:
        for filename, expected in (("app.py", "python"), ("app.ts", "typescript")):
            with self.subTest(filename=filename):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    initialise(root)
                    (root / "README.md").write_text("base\n")
                    base = commit(root, "base")
                    (root / filename).write_text("value = 1\n")
                    commit(root, "committed language")
                    result = review(root, base)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(detected_languages(result.stdout), {expected})

    def test_staged_unstaged_untracked_and_multiple_languages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            (root / "tracked.ts").write_text("export const value = 1;\n")
            base = commit(root, "base")
            (root / "staged.py").write_text("value = 1\n")
            subprocess.run(["git", "add", "staged.py"], cwd=root, check=True)
            (root / "tracked.ts").write_text("export const value = 2;\n")
            (root / "untracked.go").write_text("package main\n")
            result = review(root, base)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                detected_languages(result.stdout),
                {"python", "typescript", "go"},
            )

    def test_deleted_renamed_and_empty_diffs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            (root / "old.py").write_text("value = 1\n")
            (root / "deleted.sql").write_text("select 1;\n")
            base = commit(root, "base")
            (root / "old.py").rename(root / "new.ts")
            (root / "deleted.sql").unlink()
            result = review(root, base)
            self.assertEqual(result.returncode, 0, result.stderr)
            languages = detected_languages(result.stdout)
            self.assertIn("typescript", languages)
            self.assertIn("sql", languages)

            commit(root, "rename and delete")
            result = review(root, "HEAD")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(detected_languages(result.stdout), set())

    def test_deleted_secret_is_scanned_from_base_without_incomplete_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            deleted = "deleted\ncredential.ts"
            secret = synthetic("sk_live_1234567890abcdefghij")
            (root / deleted).write_text(f"const key='{secret}';\n")
            base = commit(root, "base credential")
            (root / deleted).unlink()
            result = review(root, base)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("[INCOMPLETE]", result.stderr)
            self.assertIn("deleted-base", result.stdout)
            self.assertNotIn(secret, result.stdout)

    def test_unstaged_deletions_read_index_backed_blobs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            (root / "README.md").write_text("base\n")
            base = commit(root, "base")
            secret = synthetic("sk_live_1234567890abcdefghij")
            added = "added\nfrom-index.ts"
            (root / added).write_text(f"const key='{secret}';\n")
            subprocess.run(["git", "add", added], cwd=root, check=True)
            (root / added).unlink()
            entries = changed_entries(root, f"{base}...HEAD")
            deletion = next(item for item in entries if item.status.startswith("D") and item.old_path == added)
            self.assertEqual(deletion.source_kind, "index")
            self.assertEqual(deletion.index_stage, 0)
            transport = root / "scope.bin"
            transport.write_bytes(serialize_entries(entries))
            scan = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "scan_ai_gotchas.py"), "--format", "json"],
                cwd=root, text=True, capture_output=True, check=False,
                env={**os.environ, "AI_REVIEW_FILE_LIST": str(transport)},
            )
            self.assertEqual(scan.returncode, 0, scan.stderr)
            payload = json.loads(scan.stdout)
            self.assertTrue(payload["complete"], payload["coverage_errors"])
            self.assertTrue(any(
                item["path"] == added and item["source"].startswith("git:index:0")
                for item in payload["findings"]
            ))

    def test_staged_rename_then_unstaged_deletion_preserves_index_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            old, new = "old.py", "new\nname.py"
            (root / old).write_text("value = 1\n")
            commit(root, "base")
            (root / old).rename(root / new)
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            (root / new).unlink()
            entries = changed_entries(root)
            self.assertTrue(any(item.status.startswith("R") and item.new_path == new for item in entries))
            deletion = next(item for item in entries if item.status.startswith("D") and item.old_path == new)
            self.assertEqual((deletion.source_kind, deletion.index_stage), ("index", 0))


if __name__ == "__main__":
    unittest.main()
