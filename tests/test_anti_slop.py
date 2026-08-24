from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_review_context  # noqa: E402
import run_anti_slop  # noqa: E402
from diff_file_list import DiffEntry, deserialize_entries, serialize_entries  # noqa: E402
from review_ledger import validate_candidate  # noqa: E402


class AntiSlopTests(unittest.TestCase):
    def test_preflight_skip_reasons_are_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.ts"
            source.write_text("export const value = 1;\n")
            vendor = root / "vendor"
            with patch("run_anti_slop.shutil.which", return_value=None):
                self.assertEqual(run_anti_slop.analyse(root, [source], vendor_dir=vendor)["skip_reason"], "node_unavailable")
            with patch("run_anti_slop.shutil.which", return_value="/node"), patch(
                "run_anti_slop._node_version", return_value=(22, 17, 0)
            ):
                self.assertEqual(run_anti_slop.analyse(root, [source], vendor_dir=vendor)["skip_reason"], "node_version_unsupported")
            with patch("run_anti_slop.shutil.which", return_value="/node"), patch(
                "run_anti_slop._node_version", return_value=(22, 18, 0)
            ), patch("run_anti_slop._oxlint_path", return_value=vendor / "missing"):
                self.assertEqual(run_anti_slop.analyse(root, [source], vendor_dir=vendor)["skip_reason"], "deps_missing")

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
            self.assertTrue(run_anti_slop.detect_effect(root))
            (root / "package.json").write_text(json.dumps({"workspaces": ["packages/*"]}))
            package = root / "packages" / "app"
            package.mkdir(parents=True)
            (package / "package.json").write_text(json.dumps({"devDependencies": {"effect": "^3"}}))
            self.assertTrue(run_anti_slop.detect_effect(root))
            (root / "package.json").write_text("not json")
            self.assertFalse(run_anti_slop.detect_effect(root))

    def test_candidate_mapping_filters_default_rule_and_validates_ledger_shape(self) -> None:
        fixture = ROOT / "tests" / "fixtures" / "anti-slop" / "oxlint-diagnostics.json"
        diagnostics = run_anti_slop.parse_diagnostics(fixture.read_text())
        candidates = run_anti_slop.to_candidates(diagnostics, Path("/tmp/anti-slop-fixture"))
        self.assertEqual(len(candidates), 2)
        self.assertTrue(all(item["id"].startswith("candidate-anti-slop-") for item in candidates))
        self.assertTrue(all(not any("signal" in evidence for evidence in item["supporting_evidence"]) for item in candidates))
        self.assertTrue(all(validate_candidate(item) == [] for item in candidates))

    @unittest.skipUnless(
        shutil.which("node") and (ROOT / "scripts/vendor/anti-slop/node_modules/.bin/oxlint").exists(),
        "skill-local Node runtime is unavailable",
    )
    def test_end_to_end_positive_and_negative_fixtures(self) -> None:
        positive = ROOT / "tests/fixtures/anti-slop/unknown-returns-positive.ts"
        negative = ROOT / "tests/fixtures/anti-slop/unknown-returns-negative.ts"
        positive_result = run_anti_slop.analyse(ROOT, [positive])
        negative_result = run_anti_slop.analyse(ROOT, [negative])
        self.assertEqual(positive_result["status"], "ok")
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
        self.assertEqual(result["config_variant"], "effect")
        self.assertEqual(result["candidates"][0]["source"], "anti-slop-effect/no-service-constructor-imports")

    def test_empty_scope_is_a_non_fatal_skip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = run_anti_slop.analyse(Path(directory), [])
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["skip_reason"], "no_js_ts_files")

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
            with patch("run_anti_slop.shutil.which", return_value=None):
                degraded = build_review_context.build(root, "full", "", None)
            self.assertTrue(any("Not verified — anti-slop pass unavailable (node_unavailable)" in item for item in degraded["limitations"]))
            self.assertEqual(degraded["coverage"]["anti-slop"]["state"], "Not verified")

    def test_disabled_toggle_skips_anti_slop_without_invoking_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".ai-review").mkdir()
            (root / ".ai-review/local.json").write_text(json.dumps({"review_options": {"anti_slop": False}}))
            (root / "app.ts").write_text("declare const value: unknown;\nexport function load(): unknown { return value; }\n")
            with patch("run_anti_slop.analyse", side_effect=AssertionError("anti-slop should be disabled")):
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
