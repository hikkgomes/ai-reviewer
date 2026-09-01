from __future__ import annotations

import json
from pathlib import Path
import sys
from subprocess import CompletedProcess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_review_context  # noqa: E402
import run_anti_slop  # noqa: E402
from dissect_checks.comment_slop import (  # noqa: E402
    _group_comments,
    _normalize_verb,
    extract_comments,
    scan_comments,
    score_comment,
)
from dissect_checks.redaction import redact_payload  # noqa: E402
from diff_file_list import DiffEntry  # noqa: E402
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
        self.assertGreaterEqual(score_comment("Set the security token", ["setSecurityToken(token)"]), 2.0)
        self.assertGreaterEqual(score_comment("Update the external cache", ["updateExternalCache(cache)"]), 2.0)
        self.assertEqual(
            score_comment("Binance writes observations, not synthetic ledger positions.", []),
            1.0,
        )
        self.assertLess(score_comment("Previously this used Redis.", []), 2.0)

    def test_gate_d_rationales_remain_below_candidate_threshold(self) -> None:
        cases = (
            (
                "Validate the canonical environment rather than trusting a forged plan object.",
                [
                    "if canonical_environment(plan.environment_dict) != plan.environment:",
                    'return None, "execution-plan environment is not canonical"',
                    "resolved = _resolve_executable(plan.argv[0], plan.environment_dict)",
                ],
                0.0,
            ),
            (
                "A legacy client is the tenant boundary. Never derive it from the portfolio creator.",
                ["for client_row in select * from public.clients order by id loop"],
                1.0,
            ),
            (
                "Only portfolios with no client are self-service portfolios.",
                ["where p.client_id is null"],
                1.0,
            ),
            (
                "Persistent, run-scoped work tables keep calculations concurrent-safe and allow plpgsql_check to validate every statement during database lint.",
                ["create table if not exists pg_temp.calculation_work"],
                1.0,
            ),
        )
        for comment, following_code, diff_density in cases:
            with self.subTest(comment=comment):
                self.assertLess(score_comment(comment, following_code, diff_density), 2.0)

    def test_untruncated_untracked_comment_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text = ("const value = 0;\n" * 1000) + "// Update the account owner\nsaveUser(user);\n"
            path = root / "untracked.ts"
            path.write_text(text)
            entries = [DiffEntry("??", "untracked.ts", "untracked.ts", True, "untracked")]
            self.assertGreater(text.index("// Update"), 12000)
            self.assertEqual(
                build_review_context.changed_line_ranges(root, "untracked.ts", entries, "", build_review_context.read_full(path)),
                [(1, len(text.splitlines()))],
            )
            values, limitations, coverage, _commands = build_review_context.optional_analyser_evidence(
                root,
                "diff",
                ["untracked.ts"],
                entries,
                "",
                {"review_options": {"anti_slop": False}},
            )
            self.assertTrue(any(item["source"].startswith("comment-slop/") for item in values))
            self.assertEqual(coverage["comment-slop"]["state"], "Checked")
            self.assertFalse(any("too large" in item for item in limitations))

    def test_oversized_comment_file_is_not_reported_as_checked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "oversized.ts"
            path.write_bytes(b"x" * (build_review_context.COMMENT_ANALYSIS_MAX_BYTES + 1))
            with patch("build_review_context.read_full", wraps=build_review_context.read_full) as read_full:
                values, limitations, coverage, commands = build_review_context.optional_analyser_evidence(
                    root,
                    "diff",
                    ["oversized.ts"],
                    [DiffEntry("??", "oversized.ts", "oversized.ts", True, "untracked")],
                    "",
                    {"review_options": {"anti_slop": False}},
                )
            read_full.assert_not_called()
            self.assertEqual(values, [])
            self.assertTrue(any("file too large for comment analysis oversized.ts" in item for item in limitations))
            self.assertEqual(coverage["comment-slop"]["state"], "Not verified")
            comment_command = next(item for item in commands if item["name"] == "comment-slop")
            self.assertFalse(comment_command["complete"])

    def test_unreadable_source_is_not_verified_but_readable_candidates_survive(self) -> None:
        for mode in ("diff", "full"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                good = root / "good.ts"
                bad = root / "bad.ts"
                good.write_text("// This function saves the account owner\nsaveUser(user);\n")
                bad.write_text("// This function saves the account owner\nsaveUser(user);\n")
                original_bounded = build_review_context._bounded_file_bytes

                def bounded_file_bytes(path: Path, limit: int) -> tuple[bytes | None, str | None]:
                    if path == bad:
                        return None, "read_failure: permission denied"
                    return original_bounded(path, limit)

                entries = [
                    DiffEntry("??", name, name, True, "untracked")
                    for name in ("good.ts", "bad.ts")
                ]
                with patch(
                    "build_review_context._bounded_file_bytes", side_effect=bounded_file_bytes,
                ):
                    values, limitations, coverage, commands = build_review_context.optional_analyser_evidence(
                        root, mode, ["good.ts", "bad.ts"], entries, "",
                        {"review_options": {"anti_slop": False}},
                    )
                self.assertTrue(any(item["trigger_path"] == ["good.ts:1"] for item in values))
                self.assertTrue(any("source unreadable for comment analysis bad.ts" in item for item in limitations))
                self.assertEqual(coverage["comment-slop"]["state"], "Not verified")
                comment_command = next(item for item in commands if item["name"] == "comment-slop")
                self.assertFalse(comment_command["complete"])

    def test_comment_analysis_reads_each_non_oversized_path_at_most_once(self) -> None:
        for mode in ("diff", "full"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name in ("one.ts", "two.ts"):
                    (root / name).write_text("// Update the account owner\nsaveUser(user);\n")
                entries = [DiffEntry("??", name, name, True, "untracked") for name in ("one.ts", "two.ts")]
                counts: dict[Path, int] = {}
                original_bounded = build_review_context._bounded_file_bytes

                def bounded_file_bytes(path: Path, limit: int) -> tuple[bytes | None, str | None]:
                    counts[path] = counts.get(path, 0) + 1
                    return original_bounded(path, limit)

                with patch("build_review_context._bounded_file_bytes", side_effect=bounded_file_bytes):
                    build_review_context.optional_analyser_evidence(
                        root, mode, ["one.ts", "two.ts"], entries, "",
                        {"review_options": {"anti_slop": False}},
                    )
                source_counts = {
                    path: count for path, count in counts.items()
                    if path.name in {"one.ts", "two.ts"}
                }
                self.assertEqual(source_counts, {root / "one.ts": 1, root / "two.ts": 1})
                self.assertTrue(all(path.name != "one.ts" or count == 1 for path, count in counts.items()))
                self.assertTrue(all(path.name != "two.ts" or count == 1 for path, count in counts.items()))

    def test_changed_line_ranges_distinguishes_empty_evidence_from_failure(self) -> None:
        entries = [DiffEntry("R", "old.ts", "new.ts", True, "commit")]
        success = CompletedProcess([], 0, "@@ -1,1 +1,0 @@\n", "")
        with tempfile.TemporaryDirectory() as directory, patch("build_review_context.subprocess.run", return_value=success):
            self.assertEqual(build_review_context.changed_line_ranges(Path(directory), "new.ts", entries, "base", ""), [])
        failure = CompletedProcess([], 1, "", "git unavailable")
        with tempfile.TemporaryDirectory() as directory, patch("build_review_context.subprocess.run", return_value=failure):
            self.assertIsNone(build_review_context.changed_line_ranges(Path(directory), "new.ts", entries, "base", ""))

    def test_partial_diff_coverage_keeps_evidenced_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "good.ts").write_text("// Update the account owner\nsaveUser(user);\n")
            (root / "bad.ts").write_text("// Update the account owner\nsaveUser(user);\n")
            with patch(
                "build_review_context.changed_line_ranges",
                side_effect=[[(1, 2)], None],
            ):
                values, _limitations, coverage, commands = build_review_context.optional_analyser_evidence(
                    root,
                    "diff",
                    ["good.ts", "bad.ts"],
                    [],
                    "",
                    {"review_options": {"anti_slop": False}},
                )
            self.assertTrue(any(item["trigger_path"] == ["good.ts:1"] for item in values))
            self.assertEqual(coverage["comment-slop"]["state"], "Not verified")
            comment_command = next(item for item in commands if item["name"] == "comment-slop")
            self.assertFalse(comment_command["complete"])

    def test_behavioural_claim_normalises_verbs_and_has_contract(self) -> None:
        self.assertEqual(
            [_normalize_verb(value) for value in ("sends", "handles", "validated", "sending", "returns")],
            ["send", "handle", "validate", "send", "return"],
        )
        candidates = scan_comments(
            "app.ts",
            "// This function sends an email to the account owner.\nsaveUser(user);\n",
            [(1, 2)],
            "diff",
        )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["source"], "comment-slop/behavioural-claim")
        self.assertEqual(
            candidates[0]["contract"],
            "Verify the asserted behaviour exists in the current implementation (truthfulness), is in scope (relevance), and describes the current invariant (stability).",
        )

    def test_comment_slop_and_anti_slop_payloads_share_recursive_redaction(self) -> None:
        token = "sk-abc123secretvalue"
        candidates = scan_comments(
            "app.ts",
            f"// Set API key to {token}\nsetApiKey(value);\n",
            [(1, 2)],
            "diff",
        )
        self.assertEqual(len(candidates), 1)
        serialised = json.dumps(candidates)
        self.assertNotIn(token, serialised)
        self.assertIn("[REDACTED type=generic-secret-token", serialised)
        self.assertIs(run_anti_slop.redact_payload, redact_payload)
        envelope = run_anti_slop._envelope({
            "status": "unavailable",
            "state": "Not verified",
            "reason": token,
            "files_scanned": 0,
            "candidates": [],
            "backends": {},
        })
        self.assertNotIn(token, json.dumps(envelope))

    def test_syntax_map_supports_multi_family_suffixes(self) -> None:
        self.assertEqual(
            [comment.text for comment in extract_comments("source.hpp", "// Update header\n/* Preserve ABI */\nint value = 1;\n")],
            ["Update header", "Preserve ABI"],
        )
        self.assertEqual(
            [comment.text for comment in extract_comments("source.php", "# Update the account\n$value = 1;\n")],
            ["Update the account"],
        )
        self.assertEqual(
            [comment.text for comment in extract_comments("source.tf", "// Update the resource\n# Keep the provider\nvalue = 1\n")],
            ["Update the resource", "Keep the provider"],
        )
        self.assertEqual(
            extract_comments(
                "source.hpp",
                'const char* text = "// not a comment";\nconst auto pattern = /https?:\\/\\/example/;\n',
            ),
            [],
        )
        self.assertEqual(
            extract_comments("source.tf", 'value = "https://example.test/#not-comment"\n'),
            [],
        )
        self.assertEqual(
            extract_comments("source.tf", "value = <<EOF\n// not a comment\n# not a comment\nEOF\n"),
            [],
        )

    def test_php_attributes_are_not_comments(self) -> None:
        text = (
            "#[Route('/users/{id}')]\n"
            "#[Example(\n"
            "    name: 'user',\n"
            ")]\n"
            "function showUser() {}\n"
            "# actual comment\n"
            "$value = 1;\n"
        )
        self.assertEqual([comment.text for comment in extract_comments("source.php", text)], ["actual comment"])
        self.assertFalse(any(item["location"]["line"] == 1 for item in scan_comments("source.php", text, None, "full")))

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

    def test_multiline_verbatim_groups_map_to_expected_subtypes(self) -> None:
        cases = (
            (
                "a.ts",
                "// This is the function to do this\n// This function won't do that\nrun();\n",
                "comment-slop/negative-claim",
            ),
            (
                "b.ts",
                "// This function do this\n// This function doesn't do that other thing that it used to do\nrun();\n",
                "comment-slop/mixed",
            ),
            (
                "c.ts",
                "// This is the function to do this\n// This function won't do that\n// This function doesn't do that other thing that it used to do\nrun();\n",
                "comment-slop/mixed",
            ),
            (
                "d.ts",
                "// This function won't do that\n// This function doesn't do that other thing that it used to do\nrun();\n",
                "comment-slop/mixed",
            ),
        )
        for path, text, source in cases:
            comments = extract_comments(path, text)
            groups = _group_comments(comments, text.splitlines())
            self.assertEqual(len(groups), 1)
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
            with patch("dissect_checks.comment_slop.scan_comment_targets", side_effect=AssertionError("comment-slop should be disabled")):
                context = build_review_context.build(root, "full", "", None)
            self.assertIn("comment-slop disabled by review_options", context["limitations"])
            self.assertFalse(any(item.get("source", "").startswith("comment-slop/") for item in context["candidates"]))


if __name__ == "__main__":
    unittest.main()
