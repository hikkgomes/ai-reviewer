from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_review_context  # noqa: E402
from dissect_checks import comment_slop  # noqa: E402
from language_registry import detect_languages  # noqa: E402


class AnalysisRegressionTests(unittest.TestCase):
    def test_language_detector_handles_generator_filter_without_name_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("value = 1\n")
            (root / "client.TS").write_text("export const value = 1;\n")
            paths = (path for path in root.rglob("*") if path.is_file())
            self.assertEqual(detect_languages(paths), ("python", "typescript"))

    def test_full_shell_propagates_detector_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_python = fake_bin / "python3"
            fake_python.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"-c\" ]; then\n"
                f"  exec {sys.executable} \"$@\"\n"
                "fi\n"
                "case \"$(basename \"$1\")\" in\n"
                "  detect_languages.py) echo 'detector failed' >&2; exit 37;;\n"
                "esac\n"
                f"exec {sys.executable} \"$@\"\n"
            )
            fake_python.chmod(0o755)
            result = subprocess.run(
                ["bash", str(ROOT / "scripts" / "review.sh")],
                cwd=root,
                env={**os.environ, "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("detector failed", result.stderr)
            self.assertNotIn("== Deterministic scan ==", result.stdout)

    def test_comment_scope_filters_before_opening_unsupported_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app.py"
            source.write_text("# Perform the required operation.\nsave_user(user)\n")
            binary = root / "data.parquet"
            binary.write_bytes(b"not source\x00")
            with patch.object(Path, "open", autospec=True, wraps=Path.open) as open_source:
                build_review_context.optional_analyser_evidence(
                    root,
                    "full",
                    ["app.py", "data.parquet"],
                    [],
                    "",
                    {"review_options": {"anti_slop": False}},
                )
            self.assertFalse(any(call.args[0] == binary for call in open_source.call_args_list))

    def test_generic_scanner_exposes_linear_cursor_work(self) -> None:
        text = ("// Update the account owner\nconst value = 1;\n" * 2000)
        observed = [0]
        comments, work = comment_slop.extract_comments_with_work(
            "app.ts", text, observer=lambda count: observed.__setitem__(0, observed[0] + count),
        )
        self.assertTrue(comments)
        self.assertLessEqual(observed[0], len(text.encode("utf-8")) * 6)
        self.assertEqual(work, observed[0])

    def test_generic_scanner_work_scales_linearly(self) -> None:
        measurements = []
        unit = b"// Update the account owner\nconst value = 1;\n"
        for kib in (20, 40, 80, 160):
            target = kib * 1024
            data = (unit * ((target // len(unit)) + 1))[:target]
            text = data.decode("utf-8")
            observed = [0]
            _, _reported_work = comment_slop.extract_comments_with_work(
                "app.ts", text, observer=lambda count: observed.__setitem__(0, observed[0] + count),
            )
            measurements.append((len(text.encode("utf-8")), observed[0]))
        for size, work in measurements:
            self.assertLessEqual(work, size * 6)
        self.assertLessEqual(measurements[-1][1], measurements[0][1] * 9)


if __name__ == "__main__":
    unittest.main()
