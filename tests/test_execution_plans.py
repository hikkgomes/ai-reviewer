from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch


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
            if sys.platform == "darwin":
                self.assertIsNone(completed)
                self.assertIn("snapshot", error or "")
                return
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

    def test_snapshot_is_independent_when_original_mutates_after_copy(self) -> None:
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

            def mutate_then_return(_plan, snapshot_fd):
                executable.write_text("#!/bin/sh\nprintf mutated\n")
                executable.chmod(0o755)
                self.assertNotEqual(os.fstat(snapshot_fd).st_ino, executable.stat().st_ino)
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
            self.assertIsNone(error)
            self.assertIsNotNone(completed)

    def test_controlled_environment_is_bound_redacted_and_passed_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = self._script(root)
            plan, error = build_execution_plan(
                kind="tool", name="environment", argv=[str(executable), "$TOKEN"],
                working_directory=root, environment={"TOKEN": "original-secret", "LANG": "C"},
            )
            self.assertIsNone(error)
            assert plan
            changed = replace(plan, environment=(("LANG", "C"), ("PATH", "/bin:/usr/bin"), ("TOKEN", "changed")))
            self.assertNotEqual(plan.approval_digest, changed.approval_digest)
            displayed = json.dumps(plan.redacted_payload())
            self.assertNotIn("original-secret", displayed)
            self.assertIn("REDACTED", displayed)

            captured: dict[str, str] = {}
            def inspect(child_plan, snapshot_fd):
                captured.update(child_plan.environment_dict)
                self.assertNotIn("LD_PRELOAD", captured)
                self.assertNotIn("PYTHONPATH", captured)
                self.assertNotIn("UNAPPROVED", captured)
                self.assertEqual(os.fstat(snapshot_fd).st_mode & 0o222, 0)
                return subprocess.CompletedProcess([], 0, "", "")
            previous = os.environ.copy()
            os.environ.update({"LD_PRELOAD": "evil", "PYTHONPATH": "evil", "UNAPPROVED": "evil"})
            try:
                completed, error = execute_approved_plan(plan, plan.approval_digest, runner=inspect)
            finally:
                os.environ.clear(); os.environ.update(previous)
            self.assertIsNone(error)
            self.assertIsNotNone(completed)
            self.assertEqual(captured["TOKEN"], "original-secret")

    def test_shell_uses_approved_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            tool = bin_dir / "chosen"
            tool.write_text("#!/bin/sh\nprintf approved\n")
            tool.chmod(0o755)
            plan, error = build_execution_plan(
                kind="review-command", name="shell", argv=["/bin/sh", "-c", "chosen"],
                working_directory=root, environment={"PATH": str(bin_dir)},
            )
            self.assertIsNone(error)
            assert plan
            completed, execution_error = execute_approved_plan(plan, plan.approval_digest)
            if sys.platform == "darwin":
                self.assertIsNone(completed)
                self.assertIn("snapshot", execution_error or "")
                return
            self.assertIsNone(execution_error)
            assert completed
            self.assertEqual(completed.stdout, "approved")

    def test_real_concurrent_mutation_cannot_change_snapshot_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "slow"
            executable.write_text("#!/bin/sh\nsleep 0.05\nprintf approved\n")
            executable.chmod(0o755)
            plan, error = build_execution_plan(kind="tool", name="slow", argv=[str(executable)], working_directory=root)
            self.assertIsNone(error)
            assert plan
            def mutate() -> None:
                time.sleep(0.01)
                executable.write_text("#!/bin/sh\nprintf malicious\n")
                executable.chmod(0o755)
            thread = threading.Thread(target=mutate)
            thread.start()
            completed, execution_error = execute_approved_plan(plan, plan.approval_digest)
            thread.join()
            if sys.platform == "darwin":
                self.assertIsNone(completed)
                self.assertIn("snapshot", execution_error or "")
                return
            self.assertIsNone(execution_error)
            assert completed
            self.assertEqual(completed.stdout, "approved")

    def test_snapshot_execution_never_falls_back_to_mutable_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = self._script(root)
            plan, error = build_execution_plan(
                kind="tool", name="snapshot", argv=[str(executable)], working_directory=root,
            )
            self.assertIsNone(error)
            assert plan
            failed_snapshot = subprocess.CompletedProcess([], -9, "", "")
            with patch("dissect_checks.execution_plan._run_snapshot", return_value=failed_snapshot) as run:
                completed, execution_error = execute_approved_plan(plan, plan.approval_digest)
            self.assertIsNone(completed)
            self.assertIn("snapshot", execution_error or "")
            _called_plan, executable_snapshot, interpreter_snapshot = run.call_args.args
            self.assertNotEqual(executable_snapshot, executable)
            self.assertNotEqual(str(interpreter_snapshot), plan.interpreter_path)

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
