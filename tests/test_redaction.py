from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from fixture_support import synthetic

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dissect_checks.engine import scan_text
from dissect_checks.redaction import redact_argv, redact_sensitive_text, redact_shell_command


class RedactionTests(unittest.TestCase):
    def assert_redacted(self, text: str, secret: str) -> None:
        result = redact_sensitive_text(text)
        self.assertFalse(secret in result, "credential leaked from redacted text")
        self.assertIn("REDACTED", result)

    def test_sensitive_argv_relationships_and_assignments(self) -> None:
        separate = "unknown-value-that-has-no-provider-shape"
        assigned = "another-unknown-value"
        environment = "environment-value"
        short_value = "short-option-value"
        argv = redact_argv([
            "scanner", "--token", separate, f"--client-secret={assigned}",
            f"TOKEN={environment}", "-p", short_value, "--verbose",
        ])
        rendered = json.dumps(argv)
        for secret in (separate, assigned, environment, short_value):
            self.assertFalse(secret in rendered, "credential leaked from argv")
        self.assertIn("--verbose", argv)

    def test_shell_assignment_redaction_keeps_executable_structure_visible(self) -> None:
        cases = {
            "TOKEN=literal-credential-value npm test": ("literal-credential-value", "npm test"),
            "TOKEN=$(dangerous-command) npm test": ("", "$(dangerous-command) npm test"),
            "PASSWORD=literal-password-value; rm -rf target": ("literal-password-value", "; rm -rf target"),
            "TOKEN=literal-credential-value npm test | tee output > log": ("literal-credential-value", "| tee output > log"),
            "TOKEN=`dangerous-command` npm test": ("", "`dangerous-command` npm test"),
        }
        for command, (secret, visible) in cases.items():
            with self.subTest(command=command):
                rendered = redact_shell_command(command)
                if secret:
                    self.assertNotIn(secret, rendered)
                self.assertIn(visible, rendered)
                self.assertIn("REDACTED", rendered) if secret else self.assertNotIn("[REDACTED type=environment-secret", rendered)

    def test_shell_sensitive_options_keep_substitutions_and_operators_visible(self) -> None:
        cases = {
            "tool --token literal-secret": ("literal-secret", "--token [REDACTED"),
            "tool --token=$(dangerous-command)": ("", "--token=$(dangerous-command)"),
            "tool --token $(dangerous-command)": ("", "--token $(dangerous-command)"),
            "tool --token `dangerous-command`": ("", "--token `dangerous-command`"),
            "tool --password \"$(dangerous-command)\"": ("", "--password \"$(dangerous-command)\""),
            "tool --api-key=literal-secret; next && final | tee out > log": (
                "literal-secret", "; next && final | tee out > log",
            ),
        }
        for command, (secret, visible) in cases.items():
            with self.subTest(command=command):
                rendered = redact_shell_command(command)
                if secret:
                    self.assertNotIn(secret, rendered)
                self.assertIn(visible, rendered)

    def test_shell_redaction_has_no_collidable_placeholder_state(self) -> None:
        marker = "__DISSECT_SHELL_SECRET_0__"
        command = f"{marker}; before && tool --token secret; {marker} after"
        rendered = redact_shell_command(command)
        self.assertIn(f"{marker}; before", rendered)
        self.assertIn(f"; {marker} after", rendered)
        self.assertIn("before && tool --token", rendered)
        self.assertNotIn("secret", rendered)

    def test_shell_redaction_handles_escaped_words_quotes_and_expansions(self) -> None:
        rendered = redact_shell_command(
            'tool --token secret\\ value --password foo\\"bar '
            '&& tool --token "${VARIABLE}" --token "$((1 + $(echo 2)))"'
        )
        self.assertNotIn("secret", rendered)
        self.assertNotIn("value", rendered)
        self.assertIn('\\"', rendered)
        self.assertIn('"${VARIABLE}"', rendered)
        self.assertIn('"$((1 + $(echo 2)))"', rendered)

    def test_malformed_shell_is_rejected(self) -> None:
        for command in (
            'tool --token "unterminated',
            "tool --token $(unterminated",
            "tool --token `unterminated",
        ):
            with self.subTest(command=command):
                with self.assertRaises(ValueError):
                    redact_shell_command(command)

    def test_urls_private_keys_jwt_and_auth_headers(self) -> None:
        password = "url-password"
        self.assert_redacted(f"https://user:{password}@example.com/path", password)
        private_key = (
            "-----BEGIN PRIVATE KEY-----\n"
            "c3VwZXItc2VjcmV0LWtleS1tYXRlcmlhbA==\n"
            "-----END PRIVATE KEY-----"
        )
        self.assert_redacted(private_key, "c3VwZXItc2VjcmV0LWtleS1tYXRlcmlhbA==")
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue"
        self.assert_redacted(jwt, jwt)
        bearer = "bearer-secret-material"
        self.assert_redacted(f"Authorization: Bearer {bearer}", bearer)
        basic = "dXNlcjpwYXNzd29yZA=="
        self.assert_redacted(f"Authorization: Basic {basic}", basic)

    def test_provider_and_labelled_credentials(self) -> None:
        credentials = [
            synthetic("sk_live_1234567890abcdefghij"),
            synthetic("AKIAIOSFODNN7EXAMPLE"),
            synthetic("ghp_abcdefghijklmnopqrstuvwxyz1234567890"),
            synthetic("glpat-abcdefghijklmnopqrst"),
            synthetic("xoxb-1234567890-abcdefghijkl"),
            synthetic("AIzaSyA123456789012345678901234567890"),
        ]
        payload = "\n".join(credentials)
        redacted = redact_sensitive_text(payload)
        for credential in credentials:
            self.assertFalse(credential in redacted, "provider credential leaked")
        labelled = "password: completely-arbitrary-value"
        self.assertFalse(
            "completely-arbitrary-value" in redact_sensitive_text(labelled),
            "labelled credential leaked",
        )

    def test_internal_finding_retains_type_location_and_fingerprint(self) -> None:
        raw = synthetic("sk_live_1234567890abcdefghij")
        finding = next(
            item for item in scan_text("config.py", f"\n\nsecret = '{raw}'")
            if item.check_id == "SEC-SECRETS-002"
        )
        self.assertEqual(finding.path, "config.py")
        self.assertEqual(finding.line, 3)
        self.assertIn("type=stripe-live", finding.evidence)
        self.assertIn("sha256=", finding.evidence)
        self.assertFalse(raw in finding.evidence, "internal finding leaked credential")

    def test_external_stdout_stderr_and_argv_are_redacted_in_text_and_json(self) -> None:
        stdout_secret = "stdout-arbitrary-secret"
        stderr_secret = "stderr-arbitrary-secret"
        argv_secret = "argv-arbitrary-secret"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_dir = root / ".ai-review"
            config_dir.mkdir()
            config = {
                "security_review": {
                    "tool_commands": {
                        "fixture": {
                            "argv": [
                                "/bin/sh", "-c",
                                (
                                    f"printf 'token={stdout_secret}'; "
                                    f"printf 'password={stderr_secret}' >&2"
                                ),
                                "--token", argv_secret,
                            ],
                        }
                    }
                }
            }
            (config_dir / "local.json").write_text(json.dumps(config))
            planning = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "tool_integrations.py"),
                    "--format",
                    "json",
                ],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(planning.returncode, 0, planning.stderr)
            planned = next(
                item for item in json.loads(planning.stdout)["tools"]
                if item["tool"] == "fixture"
            )
            approval = planned["plan"]["approval_digest"]
            for output_format in ("text", "json"):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "scripts" / "tool_integrations.py"),
                        "--format",
                        output_format,
                        "--approve-plan",
                        approval,
                    ],
                    cwd=root,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                retained = result.stdout + result.stderr
                for secret in (stdout_secret, stderr_secret, argv_secret):
                    self.assertFalse(secret in retained, "tool output leaked credential")
                self.assertIn("REDACTED", retained)


if __name__ == "__main__":
    unittest.main()
