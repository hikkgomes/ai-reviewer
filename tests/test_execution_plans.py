from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dissect_checks.execution_plan import (
    build_execution_plan,
    execute_approved_plan,
)


class ExecutionPlanTests(unittest.TestCase):
    def _script(self, root: Path, name: str = "scanner") -> Path:
        path = root / name
        path.write_text("#!/bin/sh\nprintf '%s' \"${2:-$1}\"\n")
        path.chmod(0o755)
        return path

    def test_planning_is_inert_and_unchanged_exact_plan_executes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = self._script(root)
            marker = root / "not-created-by-planning"
            plan, error = build_execution_plan(
                kind="tool",
                name="company-scanner",
                argv=[
                    str(executable),
                    "--token",
                    "original-secret-value",
                    str(marker),
                ],
                working_directory=root,
                finding_exit_codes={1},
            )
            self.assertIsNone(error)
            assert plan
            self.assertFalse(marker.exists())
            display = json.dumps(plan.redacted_payload(), sort_keys=True)
            self.assertNotIn("original-secret-value", display)
            self.assertIn("REDACTED", display)

            completed, error = execute_approved_plan(plan, plan.approval_digest)
            self.assertIsNone(error)
            assert completed
            self.assertEqual(completed.stdout, "original-secret-value")

    def test_every_execution_affecting_field_changes_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            other = root / "other"
            other.mkdir()
            first = self._script(root, "first")
            second = self._script(root, "second")
            plan, error = build_execution_plan(
                kind="tool",
                name="first-tool",
                argv=[str(first), "one", "two"],
                working_directory=root,
                finding_exit_codes={1},
            )
            self.assertIsNone(error)
            assert plan
            mutations = (
                replace(plan, name="second-tool"),
                replace(plan, executable_path=str(second)),
                replace(plan, executable_sha256="0" * 64),
                replace(plan, argv=(plan.argv[0], "changed", "two")),
                replace(plan, argv=(plan.argv[0], "two", "one")),
                replace(plan, working_directory=str(other)),
                replace(plan, finding_exit_codes=(2,)),
            )
            self.assertEqual(
                len({plan.approval_digest, *(item.approval_digest for item in mutations)}),
                len(mutations) + 1,
            )

    def test_replaced_executable_and_stale_plan_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = self._script(root)
            plan, error = build_execution_plan(
                kind="tool",
                name="scanner",
                argv=[str(executable), "safe"],
                working_directory=root,
            )
            self.assertIsNone(error)
            assert plan
            executable.write_text("#!/bin/sh\nprintf replaced\n")
            executable.chmod(0o755)
            completed, error = execute_approved_plan(plan, plan.approval_digest)
            self.assertIsNone(completed)
            self.assertIn("bytes changed", error or "")

    def test_time_of_check_mutation_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = self._script(root)
            plan, error = build_execution_plan(
                kind="tool",
                name="scanner",
                argv=[str(executable), "safe"],
                working_directory=root,
            )
            self.assertIsNone(error)
            assert plan

            def mutate_then_return(_plan, _fd):
                executable.write_text("#!/bin/sh\nprintf mutated\n")
                executable.chmod(0o755)
                return subprocess.CompletedProcess(
                    args=list(_plan.argv),
                    returncode=0,
                    stdout="not trusted",
                    stderr="",
                )

            completed, error = execute_approved_plan(
                plan,
                plan.approval_digest,
                runner=mutate_then_return,
            )
            self.assertIsNone(completed)
            self.assertIn("during execution", error or "")

    def test_malformed_unknown_and_cross_plan_approvals_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = self._script(root)
            first, _ = build_execution_plan(
                kind="tool",
                name="first",
                argv=[str(executable), "first"],
                working_directory=root,
            )
            second, _ = build_execution_plan(
                kind="tool",
                name="second",
                argv=[str(executable), "second"],
                working_directory=root,
            )
            assert first and second
            for approval in ("bad", second.approval_digest):
                completed, error = execute_approved_plan(first, approval)
                self.assertIsNone(completed)
                self.assertTrue(error)


if __name__ == "__main__":
    unittest.main()
