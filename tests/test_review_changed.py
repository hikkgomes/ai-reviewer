from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


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


if __name__ == "__main__":
    unittest.main()
