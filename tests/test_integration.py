from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_installer():
    spec = importlib.util.spec_from_file_location("dissect_installer", ROOT / "scripts" / "install.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class IntegrationTests(unittest.TestCase):
    def test_adapters_are_synchronised(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "sync_adapters.py"), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ci_runs_offline_tests_and_adapter_drift_check(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIn("python3 -m unittest discover -s tests -v", workflow)
        self.assertIn("python3 scripts/sync_adapters.py --check", workflow)

    def test_family_ids_and_layers_match_rules_config(self) -> None:
        import re

        catalog = (ROOT / "reference" / "check-families.md").read_text()
        rules = (ROOT / "config" / "rules.yaml").read_text()
        documented = {}
        sections = re.split(r"(?m)^## ", catalog)[1:]
        for section in sections:
            heading, _, body = section.partition("\n")
            family = heading.split(" ", 1)[0]
            if not re.match(r"^[A-Z]+-[A-Z]+$", family):
                continue
            layer_match = re.search(r"(?m)^- Layers: ([0-9, ]+)$", body)
            self.assertIsNotNone(layer_match, family)
            documented[family] = [
                int(value.strip()) for value in layer_match.group(1).split(",")
            ]
        configured = {}
        for family, values in re.findall(r"(?m)^  ([A-Z]+-[A-Z]+): \[([0-9, ]+)\]$", rules):
            configured[family] = [int(value.strip()) for value in values.split(",")]
        self.assertEqual(configured, documented)

    def test_old_configuration_remains_valid(self) -> None:
        old = {"review_options": {"run_install_on_review": False}, "paths": {"ignore": []}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_dir = root / ".ai-review"
            config_dir.mkdir()
            (config_dir / "local.json").write_text(json.dumps(old))
            (root / "safe.py").write_text("value = 1\n")
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "scan_ai_gotchas.py"), "--format", "json"],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["findings"], [])

    def test_invalid_optional_history_depth_falls_back_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_dir = root / ".ai-review"
            config_dir.mkdir()
            (config_dir / "local.json").write_text(
                '{"security_review":{"git_history_depth":"not-a-number"}}'
            )
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "scan_ai_gotchas.py"), "--format", "json"],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["options"]["git_history_depth"], 0)

    def test_configuration_template_is_valid_json(self) -> None:
        data = json.loads((ROOT / "config" / "local.json.template").read_text())
        self.assertIn("security_review", data)
        self.assertEqual(data["review_options"]["fail_on_severity"], "none")

    def test_codex_installer_preserves_two_workflows(self) -> None:
        installer = load_installer()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for name in installer.CODEX_SKILL_NAMES:
                installer.install_codex_skill(name, base)
                skill = (base / "skills" / name / "SKILL.md").read_text()
                self.assertIn(f"name: {name}", skill)
                self.assertTrue((base / "skills" / name / "reference" / "check-families.md").exists())

    def test_cursor_merge_replaces_only_managed_block(self) -> None:
        installer = load_installer()
        old = "user rule\n\n<!-- DISSECT-START -->\nold\n<!-- DISSECT-END -->\n"
        merged = installer.merge_block(
            old,
            "<!-- DISSECT-START -->\nnew\n<!-- DISSECT-END -->",
            "<!-- DISSECT-START -->",
            "<!-- DISSECT-END -->",
        )
        self.assertIn("user rule", merged)
        self.assertIn("\nnew\n", merged)
        self.assertNotIn("\nold\n", merged)

    def test_legacy_shell_tool_command_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_dir = root / ".ai-review"
            config_dir.mkdir()
            config = {
                "security_review": {
                    "tool_commands": {
                        "definitely-missing-dissect-tool": "definitely-missing-dissect-tool scan"
                    }
                }
            }
            (config_dir / "local.json").write_text(json.dumps(config))
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "tool_integrations.py"), "--format", "json"],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
            )
            payload = json.loads(result.stdout)
            missing = next(item for item in payload["tools"] if item["tool"] == "definitely-missing-dissect-tool")
            self.assertTrue(missing["configured"])
            self.assertFalse(missing["executed"])
            self.assertIn("shell command strings are rejected", missing["output"])

    def test_configured_tool_requires_explicit_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_dir = root / ".ai-review"
            config_dir.mkdir()
            marker = root / "executed"
            config = {
                "security_review": {
                    "tool_commands": {
                        "fixture-tool": {
                            "argv": ["/bin/sh", "-c", f"touch {marker}"],
                        }
                    }
                }
            }
            (config_dir / "local.json").write_text(json.dumps(config))
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "tool_integrations.py"), "--format", "json"],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
            )
            payload = json.loads(result.stdout)
            tool = next(item for item in payload["tools"] if item["tool"] == "fixture-tool")
            self.assertFalse(tool["executed"])
            self.assertFalse(marker.exists())
            self.assertIn("--allow-configured-tools", tool["output"])

    def test_approved_tool_redacts_output_and_reports_finding_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_dir = root / ".ai-review"
            config_dir.mkdir()
            raw_secret = "sk_live_" + "1234567890abcdefghij"
            config = {
                "security_review": {
                    "tool_commands": {
                        "fixture-tool": {
                            "argv": ["/bin/sh", "-c", f"printf '%s' '{raw_secret}'; exit 1"],
                            "finding_exit_codes": [1]
                        }
                    }
                }
            }
            (config_dir / "local.json").write_text(json.dumps(config))
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "tool_integrations.py"),
                    "--format",
                    "json",
                    "--allow-configured-tools",
                ],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
            )
            payload = json.loads(result.stdout)
            tool = next(item for item in payload["tools"] if item["tool"] == "fixture-tool")
            self.assertTrue(tool["execution_completed"])
            self.assertTrue(tool["complete"])
            self.assertFalse(tool["passed"])
            self.assertTrue(tool["findings_produced"])
            self.assertTrue(tool["coverage_complete"])
            self.assertNotIn(raw_secret, result.stdout)
            self.assertIn("REDACTED", tool["output"])

    def test_review_script_does_not_run_repository_commands_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_dir = root / ".ai-review"
            config_dir.mkdir()
            marker = root / "executed"
            (config_dir / "local.json").write_text(json.dumps({
                "commands": {"test": f"touch {marker}"},
            }))
            result = subprocess.run(
                ["bash", str(ROOT / "scripts" / "review.sh")],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists())
            self.assertIn("were not executed", result.stdout)


if __name__ == "__main__":
    unittest.main()
