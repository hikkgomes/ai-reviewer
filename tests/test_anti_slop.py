from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import shutil
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_review_context  # noqa: E402
import run_anti_slop  # noqa: E402
from diff_file_list import DiffEntry, deserialize_entries, serialize_entries  # noqa: E402
from dissect_checks.anti_slop import oxlint_backend  # noqa: E402
from dissect_checks.anti_slop.model import AnalysisTarget  # noqa: E402
from review_ledger import validate_candidate  # noqa: E402


class AntiSlopTests(unittest.TestCase):
    def test_preflight_skip_reasons_are_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.ts"
            source.write_text("export const value = 1;\n")
            vendor = root / "vendor"
            with patch("dissect_checks.anti_slop.oxlint_backend.shutil.which", return_value=None):
                result = run_anti_slop.analyse(root, [source], vendor_dir=vendor)
                self.assertEqual(result["backends"]["oxlint-js-ts"]["reason_code"], "node_unavailable")
            with patch("dissect_checks.anti_slop.oxlint_backend.shutil.which", return_value="/node"), patch(
                "dissect_checks.anti_slop.oxlint_backend._node_version", return_value=(22, 17, 0)
            ):
                result = run_anti_slop.analyse(root, [source], vendor_dir=vendor)
                self.assertEqual(result["backends"]["oxlint-js-ts"]["reason_code"], "node_version_unsupported")
            with patch("dissect_checks.anti_slop.oxlint_backend.shutil.which", return_value="/node"), patch(
                "dissect_checks.anti_slop.oxlint_backend._node_version", return_value=(22, 18, 0)
            ), patch("dissect_checks.anti_slop.oxlint_backend._oxlint_path", return_value=vendor / "missing"):
                result = run_anti_slop.analyse(root, [source], vendor_dir=vendor)
                self.assertEqual(result["backends"]["oxlint-js-ts"]["reason_code"], "deps_missing")

    def test_entries_from_canonical_stream_selects_existing_js_ts_once(self) -> None:
        entries = [
            DiffEntry("D", "deleted.ts", "deleted.ts", False, "commit"),
            DiffEntry("M", "src/app.ts", "src/app.ts", True, "index"),
            DiffEntry("M", "src/app.ts", "src/app.ts", True, "working-tree"),
            DiffEntry("M", "README.md", "README.md", True, "working-tree"),
            DiffEntry("M", "src/app.ts", "src/app.ts", True, "commit"),
        ]
        decoded = deserialize_entries(serialize_entries(entries))
        self.assertEqual(run_anti_slop._entries_paths(decoded), ["src/app.ts"])

    def test_file_filter_rejects_escape_with_exit_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root.parent / f"escape-{root.name}.ts"
            outside.write_text("export const escape = true;\n")
            try:
                with redirect_stdout(io.StringIO()):
                    status = run_anti_slop.main(["--target-root", str(root), "--file", "../escape.ts"])
                self.assertEqual(status, 1)
            finally:
                outside.unlink()

    def test_effect_detection_in_root_and_workspace_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text(json.dumps({"dependencies": {"effect": "^3"}}))
            source = root / "consumer.ts"
            source.write_text("export const value = 1;\n")
            target = AnalysisTarget("consumer.ts", source, "typescript")
            enriched = oxlint_backend.enrich_targets(root, (target,))
            self.assertEqual(enriched[0].config_variant, "effect")
            self.assertEqual(enriched[0].manifest_path, "package.json")
            self.assertTrue(enriched[0].manifest_sha256)
            (root / "package.json").write_text("not json")
            self.assertEqual(oxlint_backend.enrich_targets(root, (target,))[0].config_variant, "generic")

    def test_effect_variant_uses_the_index_manifest_snapshot(self) -> None:
        def git(root: Path, *arguments: str) -> None:
            subprocess.run(["git", *arguments], cwd=root, capture_output=True, check=True)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git(root, "init", "-q")
            git(root, "config", "user.email", "test@example.com")
            git(root, "config", "user.name", "Test")
            git(root, "config", "commit.gpgsign", "false")
            (root / "package.json").write_text(json.dumps({"dependencies": {"typescript": "^5"}}))
            (root / "consumer.ts").write_text("export const value = 1;\n")
            git(root, "add", "-A")
            git(root, "commit", "-qm", "base")
            (root / "package.json").write_text(json.dumps({"dependencies": {"effect": "^3"}}))
            (root / "consumer.ts").write_text("export const value = 2;\n")
            git(root, "add", "-A")
            (root / "package.json").write_text(json.dumps({"dependencies": {"typescript": "^5"}}))
            (root / "consumer.ts").write_text("export const value = 1;\n")
            entries = build_review_context.changed_entries(root, "diff", None, "")
            with build_review_context._diff_optional_targets(root, ["consumer.ts"], entries, "", {}) as snapshot:
                target = next(item for item in snapshot.anti_targets if item.source_kind == "index")
                self.assertEqual(target.config_variant, "effect")
                self.assertEqual(target.manifest_source_layer, "index")
                self.assertTrue(target.manifest_sha256)

    def test_effect_variant_reads_an_unchanged_manifest_from_each_snapshot(self) -> None:
        def git(root: Path, *arguments: str) -> None:
            subprocess.run(["git", *arguments], cwd=root, capture_output=True, check=True)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git(root, "init", "-q")
            git(root, "config", "user.email", "test@example.com")
            git(root, "config", "user.name", "Test")
            git(root, "config", "commit.gpgsign", "false")
            (root / "package.json").write_text(json.dumps({"dependencies": {"effect": "^3"}}))
            source = root / "consumer.ts"
            source.write_text("export const value = 1;\n")
            git(root, "add", "-A")
            git(root, "commit", "-qm", "base")
            source.write_text("export const value = 2;\n")
            git(root, "add", "consumer.ts")
            entries = build_review_context.changed_entries(root, "diff", None, "")
            with build_review_context._diff_optional_targets(root, ["consumer.ts"], entries, "", {}) as snapshot:
                target = next(item for item in snapshot.anti_targets if item.source_kind == "index")
                self.assertEqual(target.config_variant, "effect")
                self.assertEqual(target.manifest_path, "package.json")
                self.assertEqual(target.manifest_source_layer, "index")

    def test_candidate_mapping_filters_default_rule_and_validates_ledger_shape(self) -> None:
        fixture = ROOT / "tests" / "fixtures" / "anti-slop" / "oxlint-diagnostics.json"
        diagnostics, parser_errors = oxlint_backend.parse_diagnostics_with_errors(fixture.read_text())
        self.assertEqual(parser_errors, [])
        fixture_root = Path("/tmp/anti-slop-fixture")
        target = AnalysisTarget("src/bad.ts", fixture_root / "src/bad.ts", "typescript", content_sha256="0" * 64)
        # The fixture parser output is bound to the requested source identity
        # before it can become a ledger candidate.
        bound = oxlint_backend.diagnostics_from_tool(diagnostics, fixture_root, (target,))
        self.assertEqual(len(bound), 2)
        self.assertEqual(bound[0].metadata["source_layer"], "working-tree")
        envelope = run_anti_slop._envelope({
            "status": "complete", "state": "Checked", "reason": "ok",
            "files_scanned": 1, "candidates": [], "backends": {},
        })
        self.assertNotIn("legacy_status", envelope)
        self.assertNotIn("skip_reason", envelope)

    @unittest.skipUnless(
        shutil.which("node") and (ROOT / "scripts/vendor/anti-slop/node_modules/.bin/oxlint").exists(),
        "skill-local Node runtime is unavailable",
    )
    def test_end_to_end_positive_and_negative_fixtures(self) -> None:
        positive = ROOT / "tests/fixtures/anti-slop/unknown-returns-positive.ts"
        negative = ROOT / "tests/fixtures/anti-slop/unknown-returns-negative.ts"
        positive_result = run_anti_slop.analyse(ROOT, [positive])
        negative_result = run_anti_slop.analyse(ROOT, [negative])
        self.assertEqual(positive_result["status"], "complete")
        self.assertEqual(positive_result["schema_version"], "anti-slop/2.0")
        self.assertEqual(len(positive_result["candidates"]), 1)
        self.assertEqual(positive_result["candidates"][0]["source"], "anti-slop/no-unknown-returns")
        self.assertEqual(positive_result["candidates"][0]["supporting_evidence"][0]["line"], 2)
        self.assertEqual(negative_result["candidates"], [])

    @unittest.skipUnless(
        shutil.which("node") and (ROOT / "scripts/vendor/anti-slop/node_modules/.bin/oxlint").exists(),
        "skill-local Node runtime is unavailable",
    )
    def test_effect_rule_uses_the_second_plugin_prefix(self) -> None:
        target = ROOT / "tests/fixtures/anti-slop/effect"
        result = run_anti_slop.analyse(target, [target / "consumer.ts"])
        self.assertEqual(result["backends"]["oxlint-js-ts"]["status"], "complete")
        self.assertEqual(result["candidates"][0]["source"], "anti-slop-effect/no-service-constructor-imports")

    def test_empty_scope_is_a_non_fatal_skip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = run_anti_slop.analyse(root, [])
        self.assertEqual(result["status"], "not_applicable")
        self.assertEqual(result["state"], "Not applicable")

    def test_unsupported_scope_is_not_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "data.parquet"
            source.write_bytes(b"not source")
            result = run_anti_slop.analyse(root, [source])
        self.assertEqual(result["status"], "not_applicable")
        self.assertEqual(result["state"], "Not applicable")

    @unittest.skipUnless(
        shutil.which("node") and (ROOT / "scripts/vendor/anti-slop/node_modules/.bin/oxlint").exists(),
        "skill-local Node runtime is unavailable",
    )
    def test_context_integrates_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app.ts"
            source.write_text("declare const value: unknown;\nexport function load(): unknown { return value; }\n")
            context = build_review_context.build(root, "full", "", None)
            self.assertTrue(any(item["source"] == "anti-slop/no-unknown-returns" for item in context["candidates"]))

    def test_context_survives_missing_node(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app.ts"
            source.write_text("declare const value: unknown;\nexport function load(): unknown { return value; }\n")
            with patch("build_review_context.anti_slop_orchestrator.analyse", wraps=build_review_context.anti_slop_orchestrator.analyse) as analyse_call, patch(
                "dissect_checks.anti_slop.oxlint_backend.shutil.which", return_value=None,
            ):
                degraded = build_review_context.build(root, "full", "", None)
            analyse_call.assert_called_once()
            self.assertTrue(any("Not verified — anti-slop pass unavailable (node_unavailable)" in item for item in degraded["limitations"]))
            self.assertEqual(degraded["coverage"]["anti-slop"]["state"], "Not verified")

    def test_disabled_toggle_skips_anti_slop_without_invoking_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".ai-review").mkdir()
            (root / ".ai-review/local.json").write_text(json.dumps({"review_options": {"anti_slop": False}}))
            (root / "app.ts").write_text("declare const value: unknown;\nexport function load(): unknown { return value; }\n")
            with patch(
                "build_review_context.anti_slop_orchestrator.analyse",
                side_effect=AssertionError("anti-slop should be disabled"),
            ):
                context = build_review_context.build(root, "full", "", None)
            self.assertIn("anti-slop disabled by review_options", context["limitations"])
            self.assertFalse(any(item.get("source", "").startswith("anti-slop/") for item in context["candidates"]))

    def test_paths_ignore_is_shared_with_full_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".ai-review").mkdir()
            (root / ".ai-review/local.json").write_text(json.dumps({"paths": {"ignore": ["ignored/"]}}))
            (root / "included.ts").write_text("declare const value: unknown;\nexport function load(): unknown { return value; }\n")
            (root / "ignored").mkdir()
            (root / "ignored/skipped.ts").write_text("declare const value: unknown;\nexport function load(): unknown { return value; }\n")
            context = build_review_context.build(root, "full", "", None)
            self.assertIn("included.ts", context["scope"]["files"])
            self.assertNotIn("ignored/skipped.ts", context["scope"]["files"])
            self.assertTrue(all("ignored/skipped.ts" not in str(item) for item in context["candidates"]))


if __name__ == "__main__":
    unittest.main()
