from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_review_context  # noqa: E402
from dissect_checks.comment_slop import extract_comments, scan_comments, score_comment  # noqa: E402
from review_ledger import validate_candidate  # noqa: E402


class CommentSlopTests(unittest.TestCase):
    def test_positive_and_negative_fixtures_cover_three_languages(self) -> None:
        fixtures = {
            "typescript.ts": ROOT / "tests/fixtures/comment-slop/typescript.ts",
            "python.py": ROOT / "tests/fixtures/comment-slop/python.py",
            "go.go": ROOT / "tests/fixtures/comment-slop/go.go",
        }
        for path, fixture in fixtures.items():
            candidates = scan_comments(path, fixture.read_text(), [(1, 3)], "diff")
            self.assertTrue(candidates, path)
            self.assertTrue(all(validate_candidate(item) == [] for item in candidates))
        self.assertEqual(
            scan_comments("keep.ts", "// The transaction can retry, so external side effects must run after commit.\ncommit()\n", [(1, 2)], "diff"),
            [],
        )

    def test_scoring_regressions(self) -> None:
        self.assertTrue(scan_comments("note.ts", "// NOTE: Update the user name here\nsaveUser(user)\n", [(1, 2)], "diff"))
        self.assertTrue(scan_comments("perform.ts", "// Perform the required operation.\nsaveUser(user)\n", [(1, 2)], "diff"))
        score = score_comment(
            "Keep the old slug because external webhook signatures include it. The transaction can retry, so external side effects must run after commit.",
            ["const slug = existingSlug;", "commit();"],
        )
        self.assertLess(score, 2.0)

    def test_extraction_ignores_strings_urls_regexes_and_heredocs(self) -> None:
        typescript = (
            'const text = "// Perform the required operation.";\n'
            'const url = "https://example.com/a//b";\n'
            'const pattern = /https?:\\/\\/example\\.com/;\n'
            "const value = 1;\n"
        )
        self.assertEqual(extract_comments("source.ts", typescript), [])
        python = 'value = """// not a comment\nhttps://example.com\n"""\nresult = 1\n'
        self.assertEqual(extract_comments("source.py", python), [])
        go = 'raw := `// not a comment`\nvalue := 1\n'
        self.assertEqual(extract_comments("source.go", go), [])
        heredoc = "cat <<EOF\n// not a comment\nEOF\nvalue=1\n"
        self.assertEqual(extract_comments("source.sh", heredoc), [])

    def test_user_reported_patterns_have_expected_subtypes(self) -> None:
        cases = (
            ("a.ts", "// This function won't do that\nrun()\n", "comment-slop/negative-claim"),
            ("b.ts", "// It no longer sends notifications like the previous implementation\nrun()\n", "comment-slop/historical"),
            ("c.ts", "// This function won't do that\n// It no longer sends notifications like the previous implementation\nrun()\n", "comment-slop/mixed"),
            ("d.ts", "// This function does not send notifications, validate input, or mutate state.\nrun()\n", "comment-slop/negative-claim"),
        )
        for path, text, source in cases:
            candidates = scan_comments(path, text, [(1, 3)], "diff")
            self.assertEqual([item["source"] for item in candidates], [source])

    def test_diff_mode_requires_line_evidence_and_ignores_old_comments(self) -> None:
        text = "// Check if the user exists\nif (user) {\n  save(user)\n}\n"
        self.assertEqual(scan_comments("app.ts", text, [(3, 3)], "diff"), [])
        self.assertEqual(scan_comments("app.ts", text, None, "diff"), [])
        self.assertTrue(scan_comments("app.ts", text, None, "full"))

    def test_disabled_toggle_skips_comment_slop_without_invoking_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".ai-review").mkdir()
            (root / ".ai-review/local.json").write_text(json.dumps({"review_options": {"comment_slop": False}}))
            (root / "app.py").write_text("# Perform the required operation.\nsave_user(user)\n")
            with patch("dissect_checks.comment_slop.scan_comments", side_effect=AssertionError("comment-slop should be disabled")):
                context = build_review_context.build(root, "full", "", None)
            self.assertIn("comment-slop disabled by review_options", context["limitations"])
            self.assertFalse(any(item.get("source", "").startswith("comment-slop/") for item in context["candidates"]))


if __name__ == "__main__":
    unittest.main()
