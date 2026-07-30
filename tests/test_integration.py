from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def planned_digest(command: list[str], cwd: Path, key: str, item_name: str) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    payload = json.loads(result.stdout)
    item = next(value for value in payload[key] if value.get("tool") == item_name or value.get("name") == item_name)
    return item["plan"]["approval_digest"]


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
        for version in ("3.11", "3.13", "3.14"):
            self.assertIn(f'"{version}"', workflow)

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
        self.assertIn("python_import_aliases", data["security_review"])
        self.assertEqual(data["review_options"]["fail_on_severity"], "none")

    def test_unsupported_python_fails_with_clear_message_when_available(self) -> None:
        legacy = Path("/usr/bin/python3")
        if not legacy.exists():
            self.skipTest("system Python is unavailable")
        unsupported = subprocess.run(
            [
                str(legacy),
                "-c",
                "import sys; raise SystemExit(0 if sys.version_info < (3, 11) else 1)",
            ],
            check=False,
        )
        if unsupported.returncode != 0:
            self.skipTest("system Python is supported")
        result = subprocess.run(
            [str(legacy), str(ROOT / "scripts" / "scan_ai_gotchas.py")],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires Python 3.11", result.stderr)

    def test_codex_installer_preserves_two_workflows(self) -> None:
        installer = load_installer()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for name in installer.CODEX_SKILL_NAMES:
                installer.install_codex_skill(name, base)
                installed = base / "skills" / name
                skill = (installed / "SKILL.md").read_text()
                self.assertIn(f"name: {name}", skill)
                self.assertTrue((installed / "reference" / "check-families.md").exists())
                project = base / f"project-{name}"
                project.mkdir()
                (project / "safe.py").write_text("import json\n")
                result = subprocess.run(
                    [
                        sys.executable,
                        str(installed / "scripts" / "scan_ai_gotchas.py"),
                        "--format",
                        "json",
                    ],
                    cwd=project,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(json.loads(result.stdout)["complete"])

    def test_installed_codex_skills_authenticate_dissect_fixtures_only(self) -> None:
        installer = load_installer()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            installed_skills = []
            for name in installer.CODEX_SKILL_NAMES:
                installer.install_codex_skill(name, base)
                installed = base / "skills" / name
                installed_skills.append(installed)
                scanner = installed / "scripts" / "scan_ai_gotchas.py"
                plan = subprocess.run(
                    [sys.executable, str(scanner), "--plan-self-review"],
                    cwd=ROOT, text=True, capture_output=True, check=False,
                )
                self.assertEqual(plan.returncode, 0, plan.stderr)
                approval = json.loads(plan.stdout)["approval_digest"]
                result = subprocess.run(
                    [
                        sys.executable,
                        str(scanner),
                        "--format",
                        "json",
                        "--approve-self-review",
                        approval,
                        "--fail-on",
                        "high",
                    ],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                payload = json.loads(result.stdout)
                severe = [
                    item for item in payload["findings"]
                    if item["severity"] in {"high", "critical"}
                ]
                self.assertEqual(severe, [])

            checkout = base / "dissect-checkout"
            subprocess.run(
                ["git", "clone", "-q", "--no-hardlinks", str(ROOT), str(checkout)],
                check=True,
            )
            rules = checkout / "scripts" / "dissect_checks" / "rules.py"
            expected_line = len(rules.read_text().splitlines()) + 2
            real = "sk_live_" + "ZYXWVUTSRQPONMLK987654321"
            with rules.open("a", encoding="utf-8") as handle:
                handle.write(f"\nREAL_CREDENTIAL = '{real}'\n")
            plan = subprocess.run(
                [
                    sys.executable,
                    str(installed_skills[0] / "scripts" / "scan_ai_gotchas.py"),
                    "--plan-self-review",
                ],
                cwd=checkout, text=True, capture_output=True, check=False,
            )
            self.assertEqual(plan.returncode, 0, plan.stderr)
            approval = json.loads(plan.stdout)["approval_digest"]
            result = subprocess.run(
                [
                    sys.executable,
                    str(installed_skills[0] / "scripts" / "scan_ai_gotchas.py"),
                    "--format",
                    "json",
                    "--approve-self-review",
                    approval,
                ],
                cwd=checkout,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            secrets = [
                item for item in json.loads(result.stdout)["findings"]
                if item["check_id"] == "SEC-SECRETS-002"
                and item["path"] == "scripts/dissect_checks/rules.py"
            ]
            self.assertEqual(len(secrets), 1)
            self.assertEqual(secrets[0]["line"], expected_line)
            self.assertNotIn(real, result.stdout)

            lookalike = base / "lookalike"
            (lookalike / "scripts" / "dissect_checks").mkdir(parents=True)
            (lookalike / "SKILL.md").write_text("name: dissect\n")
            fake = (
                "Rule('ID', 'secrets', 'critical', 'high', 'e', 'r', matcher,\n"
                "     ('fixture.ts', \"key='sk_live_"
                + "ZYXWVUTSRQPONMLK987654321'\"),\n"
                "     ('safe.ts', 'safe'))\n"
            )
            (lookalike / "scripts" / "dissect_checks" / "rules.py").write_text(fake)
            result = subprocess.run(
                [
                    sys.executable,
                    str(installed_skills[1] / "scripts" / "scan_ai_gotchas.py"),
                    "--format",
                    "json",
                    "--approve-self-review",
                    approval,
                ],
                cwd=lookalike,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                "SEC-SECRETS-002",
                {item["check_id"] for item in json.loads(result.stdout)["findings"]},
            )

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
            self.assertIsNotNone(tool["plan"])
            self.assertIn("--approve-plan", tool["output"])

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
            command = [
                sys.executable,
                str(ROOT / "scripts" / "tool_integrations.py"),
                "--format",
                "json",
            ]
            approval = planned_digest(command, root, "tools", "fixture-tool")
            result = subprocess.run(
                [
                    *command,
                    "--approve-plan",
                    approval,
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
            self.assertFalse(raw_secret in result.stdout, "tool output leaked credential")
            self.assertIn("REDACTED", tool["output"])

    def test_repository_tool_plan_mutation_invalidates_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".ai-review").mkdir()
            marker = root / "executed"
            config_path = root / ".ai-review" / "local.json"
            config_path.write_text(json.dumps({
                "security_review": {
                    "tool_commands": {
                        "fixture": {"argv": ["/bin/sh", "-c", "exit 0"]},
                    }
                }
            }))
            command = [
                sys.executable,
                str(ROOT / "scripts" / "tool_integrations.py"),
                "--format", "json",
            ]
            approval = planned_digest(command, root, "tools", "fixture")
            config_path.write_text(json.dumps({
                "security_review": {
                    "tool_commands": {
                        "fixture": {
                            "argv": ["/bin/sh", "-c", f"touch {marker}"],
                        },
                    }
                }
            }))
            result = subprocess.run(
                [*command, "--approve-plan", approval],
                cwd=root, text=True, capture_output=True, check=False,
            )
            payload = json.loads(result.stdout)
            tool = next(item for item in payload["tools"] if item["tool"] == "fixture")
            self.assertFalse(tool["executed"])
            self.assertFalse(marker.exists())
            self.assertIn(
                "Unknown or stale execution-plan approval digest.",
                payload["approval_errors"],
            )

    def test_tool_label_and_path_basename_never_authorise_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            trusted_bin = base / "trusted-bin"
            root = base / "target"
            trusted_bin.mkdir()
            (root / ".ai-review").mkdir(parents=True)
            executable = trusted_bin / "gitleaks"
            executable.write_text("#!/bin/sh\nprintf 'token=tool-output-secret'\n")
            executable.chmod(0o755)
            secret = "configured-argv-secret"
            (root / ".ai-review" / "local.json").write_text(json.dumps({
                "security_review": {
                    "tool_commands": {
                        "gitleaks": {
                            "argv": [str(executable), "detect", "--token", secret],
                        }
                    }
                }
            }))
            command = [
                sys.executable,
                str(ROOT / "scripts" / "tool_integrations.py"),
                "--format", "json",
            ]
            result = subprocess.run(
                command,
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
                env={**os.environ, "PATH": f"{trusted_bin}:{os.environ.get('PATH', '')}"},
            )
            payload = json.loads(result.stdout)
            tool = next(item for item in payload["tools"] if item["tool"] == "gitleaks")
            self.assertFalse(tool["approved"])
            self.assertFalse(tool["executed"])
            self.assertEqual(Path(tool["plan"]["executable_path"]), executable.resolve())
            self.assertFalse((root / "executed").exists())
            self.assertNotIn(secret, result.stdout)
            self.assertIn("REDACTED", result.stdout)

    def test_one_exact_tool_plan_cannot_authorise_other_executable_identities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "target"
            root.mkdir()
            (root / ".ai-review").mkdir()
            candidates = [Path("/bin/sh")]
            symlink = base / "gitleaks-symlink"
            symlink.symlink_to("/bin/sh")
            candidates.append(symlink)
            renamed = base / "gitleaks"
            shutil.copyfile("/bin/sh", renamed)
            renamed.chmod(0o755)
            candidates.append(renamed)
            marker = root / "executed"
            command = [
                sys.executable,
                str(ROOT / "scripts" / "tool_integrations.py"),
                "--format", "json",
            ]
            (root / ".ai-review" / "local.json").write_text(json.dumps({
                "security_review": {
                    "tool_commands": {
                        "gitleaks": {"argv": ["/usr/bin/true"]},
                    }
                }
            }))
            first_approval = planned_digest(command, root, "tools", "gitleaks")
            for candidate in candidates:
                with self.subTest(candidate=str(candidate)):
                    (root / ".ai-review" / "local.json").write_text(json.dumps({
                        "security_review": {
                            "tool_commands": {
                                "gitleaks": {
                                    "argv": [str(candidate), "-c", f"touch {marker}"],
                                }
                            }
                        }
                    }))
                    result = subprocess.run(
                        [*command, "--approve-plan", first_approval],
                        cwd=root,
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    tool = next(
                        item for item in json.loads(result.stdout)["tools"]
                        if item["tool"] == "gitleaks"
                    )
                    self.assertFalse(tool["approved"])
                    self.assertFalse(tool["executed"])
                    self.assertFalse(marker.exists())
                    self.assertTrue(json.loads(result.stdout)["approval_errors"])

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
                env={
                    **os.environ,
                    "PATH": (
                        f"{Path(shutil.which('python3.11') or sys.executable).parent}:"
                        f"{os.environ.get('PATH', '')}"
                    ),
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists())
            self.assertIn("Planned but not executed", result.stdout)

    def test_approved_review_command_output_and_plan_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_dir = root / ".ai-review"
            config_dir.mkdir()
            secret = "review-command-secret"
            (config_dir / "local.json").write_text(json.dumps({
                "commands": {
                    "test": f"printf 'token={secret}'",
                    "build": f"printf 'password={secret}'",
                },
            }))
            command = [
                sys.executable,
                str(ROOT / "scripts" / "review_commands.py"),
                "--scope", "full", "--format", "json",
            ]
            approval = planned_digest(command, root, "commands", "full:root:test")
            result = subprocess.run(
                [*command, "--approve-plan", approval],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
                env={
                    **os.environ,
                    "PATH": (
                        f"{Path(shutil.which('python3.11') or sys.executable).parent}:"
                        f"{os.environ.get('PATH', '')}"
                    ),
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(
                secret in result.stdout + result.stderr,
                "review command output leaked credential",
            )
            self.assertIn("REDACTED", result.stdout)
            payload = json.loads(result.stdout)
            build = next(item for item in payload["commands"] if item["name"] == "full:root:build")
            self.assertFalse(build["executed"])

    def test_review_command_approval_cannot_cross_categories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".ai-review").mkdir()
            test_marker = root / "test-executed"
            build_marker = root / "build-executed"
            (root / ".ai-review" / "local.json").write_text(json.dumps({
                "commands": {
                    "test": f"touch {test_marker}",
                    "build": f"touch {build_marker}",
                },
            }))
            command = [
                sys.executable,
                str(ROOT / "scripts" / "review_commands.py"),
                "--scope", "full", "--format", "json",
            ]
            approval = planned_digest(command, root, "commands", "full:root:test")
            result = subprocess.run(
                [*command, "--approve-plan", approval],
                cwd=root, text=True, capture_output=True, check=False,
            )
            payload = json.loads(result.stdout)
            test = next(item for item in payload["commands"] if item["name"] == "full:root:test")
            build = next(item for item in payload["commands"] if item["name"] == "full:root:build")
            self.assertTrue(test["executed"])
            self.assertFalse(build["executed"])
            self.assertTrue(test_marker.exists())
            self.assertFalse(build_marker.exists())


if __name__ == "__main__":
    unittest.main()
