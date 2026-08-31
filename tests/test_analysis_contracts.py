from __future__ import annotations

from pathlib import Path
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from analysis_budget import AnalysisBudget, AnalysisBudgetExceeded, analysis_limits  # noqa: E402
from build_review_context import _diff_optional_targets, _terminate_process_group, main  # noqa: E402
from dissect_checks import comment_slop  # noqa: E402
from dissect_checks.anti_slop import orchestrator  # noqa: E402
from dissect_checks.anti_slop.chunking import CommandChunkError, iter_command_chunks  # noqa: E402
from dissect_checks.anti_slop.ast_grep_backend import _matches_to_diagnostics  # noqa: E402
from dissect_checks.anti_slop.model import AnalysisTarget, BackendDiagnostic, BackendResult, canonical_diagnostic_identity  # noqa: E402
from dissect_checks.anti_slop.python_ast_backend import analyse as analyse_python  # noqa: E402
from dissect_checks.anti_slop.rules import owner_for  # noqa: E402
from diff_file_list import DiffEntry, changed_entries  # noqa: E402
from language_registry import (  # noqa: E402
    LANGUAGE_SPECS,
    ambiguous_header_paths,
    detect_languages,
    language_for_path,
    paths_for_anti_slop,
)
from validate_review_context import validate  # noqa: E402
from validate_rule_effectiveness import validate_rule_ownership  # noqa: E402


class AnalysisContractTests(unittest.TestCase):
    def test_registry_covers_required_suffixes_and_case(self) -> None:
        required = {
            ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
            ".py", ".pyi", ".go", ".rs", ".c", ".cc", ".cpp", ".cxx", ".c++",
            ".hh", ".hpp", ".hxx", ".ipp", ".tpp", ".java", ".cs",
        }
        registered = {suffix for spec in LANGUAGE_SPECS for suffix in spec.suffixes}
        self.assertTrue(required <= registered)
        self.assertEqual(language_for_path("module.PYI").language_id, "python")
        self.assertEqual(detect_languages(["z.CPP", "a.PY", "b.GO"]), ("cpp", "go", "python"))

    def test_header_policy_distinguishes_c_cpp_and_ambiguous_scopes(self) -> None:
        self.assertEqual(paths_for_anti_slop(["api.h", "main.c"])["ast-grep-c"], ("api.h", "main.c"))
        self.assertEqual(paths_for_anti_slop(["api.h", "main.cpp"])["ast-grep-cpp"], ("api.h", "main.cpp"))
        self.assertEqual(ambiguous_header_paths(["api.h"]), ("api.h",))
        self.assertNotIn("api.h", {path for values in paths_for_anti_slop(["api.h"]).values() for path in values})

    def test_analysis_limits_reject_invalid_values_and_budget_claims_are_distinct(self) -> None:
        with self.assertRaises(ValueError):
            analysis_limits({"review_options": {"analysis_limits": {"worker_threads": -1}}})
        with self.assertRaises(ValueError):
            analysis_limits({"review_options": {"analysis_limits": {"anti_slop_max_files": 1.5}}})
        with self.assertRaises(ValueError):
            analysis_limits({"review_options": {"analysis_limits": {"anti_slop_timeout_seconds": float("nan")}}})

        budget = AnalysisBudget(1, max_files=1, max_total_bytes=2, max_candidates=1)
        budget.claim_file()
        budget.claim_bytes(2)
        budget.claim_candidate()
        for action in (budget.claim_file, budget.claim_candidate):
            with self.assertRaises(AnalysisBudgetExceeded) as raised:
                action()
            self.assertIn(raised.exception.reason_code, {"max_files", "max_candidates"})
        with self.assertRaises(AnalysisBudgetExceeded) as raised:
            budget.claim_bytes(1)
        self.assertEqual(raised.exception.reason_code, "max_total_bytes")

    def test_comment_candidate_survives_same_file_candidate_budget(self) -> None:
        text = (
            "# Perform the required operation.\n"
            "save_user(user)\n"
            "# Update the account owner.\n"
            "save_user(user)\n"
        )
        result = comment_slop.scan_comment_targets(
            Path.cwd(), ["app.py"], mode="diff", changed_ranges={"app.py": [(1, 4)]},
            budget=AnalysisBudget(1, max_candidates=1),
            text_by_path={"app.py": text},
        )
        self.assertEqual(result.status, "partial")
        self.assertEqual(result.reason_code, "max_candidates")
        self.assertEqual(len(result.candidates), 1)

    def test_generated_paths_are_not_backend_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generated = root / "generated.py"
            generated.write_text("# Perform the required operation.\nsave_user(user)\n")
            config = {"paths": {"generated": ["generated.py"]}}
            result = orchestrator.analyse(root, ["generated.py"], config=config)
            self.assertEqual(result["state"], "Not applicable")
            self.assertEqual(result["candidates"], [])

    def test_comment_scope_rejects_unsupported_files_before_any_open(self) -> None:
        unsupported = ("data.parquet", "image.png", "archive.zip", "state.sqlite", "backup.bak", "extensionless")
        with patch.object(Path, "open", side_effect=AssertionError("unsupported source was opened")):
            result = comment_slop.scan_comment_targets(
                Path.cwd(), unsupported, mode="full", text_by_path={},
            )
        self.assertEqual(result.status, "not_applicable")
        self.assertEqual(result.applicable_files, 0)

    def test_supported_binary_source_is_bounded_and_not_checked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "source.ts"
            binary.write_bytes(b"const value = 1;\x00\n")
            result = comment_slop.scan_comment_targets(root, ["source.ts"], mode="full")
        self.assertEqual(result.status, "partial")
        self.assertEqual(result.reason_code, "binary_source")
        self.assertEqual(result.checked_files, 0)

    def test_python_ast_backend_reports_narrow_rules_and_parse_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            positive = root / "positive.py"
            positive.write_text(
                "from typing import Any as Erased, cast as narrow\n"
                "\n"
                "def load(value):\n"
                "    return narrow(Target, narrow(Erased, value))\n"
                "\n"
                "class Service:\n"
                "    def read(self, value):\n"
                "        return getattr(value, 'name')\n"
            )
            negative = root / "negative.py"
            negative.write_text(
                "from typing import cast\n"
                "def read(value):\n"
                "    return cast(Target, value)\n"
                "\n"
                "class Proxy:\n"
                "    def __getattr__(self, name):\n"
                "        return name\n"
                "    def read(self):\n"
                "        return getattr(self, 'name')\n"
            )
            malformed = root / "malformed.py"
            malformed.write_text("def broken(:\n")
            targets = tuple(
                AnalysisTarget(path.name, path, "python")
                for path in (positive, negative, malformed)
            )
            result = analyse_python(root, targets, AnalysisBudget(1))
            rules = {diagnostic.rule_id for diagnostic in result.diagnostics}
            self.assertIn("anti-slop-python/no-widen-then-cast", rules)
            self.assertNotIn("anti-slop-python/no-literal-getattr-without-default", rules)
            self.assertEqual(result.status, "partial")
            self.assertEqual(result.reason_code, "parse_error")
            self.assertEqual(result.checked_files, 2)
            self.assertEqual(result.skipped_files, 1)

    def test_anti_slop_limits_are_shared_across_backend_packs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("value = 1\n")
            (root / "app.go").write_text("package p\nfunc load() {}\n")
            config = {"review_options": {"analysis_limits": {"anti_slop_max_files": 1}}}
            result = orchestrator.analyse(root, ["app.py", "app.go"], config=config)
            self.assertEqual(result["state"], "Not verified")
            self.assertEqual(result["backends"]["python-ast"]["checked_files"], 1)
            self.assertEqual(result["backends"]["ast-grep-go"]["status"], "unavailable")
            self.assertEqual(result["backends"]["ast-grep-go"]["reason_code"], "max_files")

    def test_external_command_chunking_is_bounded_by_encoded_bytes(self) -> None:
        chunks = list(iter_command_chunks(["a", "bbbb", "cc"], max_files=2, max_argument_bytes=6))
        self.assertEqual(chunks, [["a"], ["bbbb"], ["cc"]])
        with self.assertRaises(CommandChunkError):
            list(iter_command_chunks(["a" * 7], max_files=2, max_argument_bytes=6))

    def test_python_ast_rule_corpus_asserts_exact_case_locations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            casts = root / "casts.py"
            casts.write_text(
                "from typing import Any as Erased, cast as narrow\n"
                "from typing_extensions import Any as DynamicAny, cast as dynamic_cast\n"
                "import typing as typing_api\n"
                "from other_module import cast as other_cast\n"
                "\n"
                "def direct(value):\n"
                "    return narrow(Target, narrow(Erased, value))\n"
                "\n"
                "def qualified(value):\n"
                "    return typing_api.cast(Target, typing_api.cast(typing_api.Any, value))\n"
                "\n"
                "class Service:\n"
                "    def method(self, value):\n"
                "        return dynamic_cast(Target, dynamic_cast(DynamicAny, value))\n"
                "\n"
                "def one_cast(value):\n"
                "    return narrow(Target, value)\n"
                "\n"
                "def separate(value):\n"
                "    widened = narrow(Erased, value)\n"
                "    return narrow(Target, widened)\n"
                "\n"
                "def conditional(value):\n"
                "    if value:\n"
                "        widened = narrow(Erased, value)\n"
                "    return narrow(Target, value)\n"
                "\n"
                "def different_inner(value):\n"
                "    return narrow(Target, narrow(Protocol, value))\n"
                "\n"
                "def unrelated_alias(value):\n"
                "    return other_cast(Target, other_cast(Erased, value))\n"
                "\n"
                "def untracked_module(value):\n"
                "    return other_cast(Target, other_cast(Any, value))\n"
                "\n"
                "def type_comment(value):  # type: (Target) -> Target\n"
                "    return narrow(Target, value)\n"
            )
            getattrs = root / "getattrs.py"
            getattrs.write_text(
                "def direct(value):\n"
                "    return getattr(value, 'name')\n"
                "\n"
                "def nested(value):\n"
                "    def inner(service):\n"
                "        return getattr(service, 'status')\n"
                "    return inner(value)\n"
                "\n"
                "class Service:\n"
                "    def read(self, value):\n"
                "        return getattr(value, 'owner')\n"
                "\n"
                "def with_default(value):\n"
                "    return getattr(value, 'name', None)\n"
                "\n"
                "def with_keyword(value):\n"
                "    return getattr(value, 'name', default=None)\n"
                "\n"
                "def dunder(value):\n"
                "    return getattr(value, '__name__')\n"
                "\n"
                "def invalid_name(value):\n"
                "    return getattr(value, 'not-valid')\n"
                "\n"
                "class DynamicGetattr:\n"
                "    def __getattr__(self, name):\n"
                "        return name\n"
                "    def read(self):\n"
                "        return getattr(self, 'name')\n"
                "\n"
                "class DynamicGetattribute:\n"
                "    def __getattribute__(self, name):\n"
                "        return object.__getattribute__(self, name)\n"
                "    def read(self):\n"
                "        return getattr(self, 'name')\n"
                "\n"
                "def proxy_lookup(proxy):\n"
                "    return getattr(proxy, 'name')\n"
                "\n"
                "def reflective_lookup(reflective):\n"
                "    return getattr(reflective, 'name')\n"
            )
            encoded = root / "encoded.py"
            encoded.write_bytes(
                b"# -*- coding: latin-1 -*-\n"
                b"# caf\xe9 is valid source text\n"
                b"value = 1  # type: int\n"
            )
            large = root / "large.py"
            large.write_text("value = 1\n" * 10000)
            malformed = root / "malformed.py"
            malformed.write_text("def broken(:\n")
            paths = (casts, getattrs, encoded, large, malformed)
            targets = tuple(
                AnalysisTarget(path.name, path, "python")
                for path in paths
            )
            result = analyse_python(root, targets, AnalysisBudget(5))
            locations = {
                (diagnostic.rule_id, diagnostic.path, diagnostic.line, diagnostic.column)
                for diagnostic in result.diagnostics
            }
            self.assertEqual(
                locations,
                {
                    ("anti-slop-python/no-widen-then-cast", "casts.py", 7, 11),
                    ("anti-slop-python/no-widen-then-cast", "casts.py", 10, 11),
                    ("anti-slop-python/no-widen-then-cast", "casts.py", 14, 15),
                },
            )
            self.assertEqual(result.status, "partial")
            self.assertEqual(result.reason_code, "parse_error")
            self.assertEqual(result.checked_files, 4)
            self.assertEqual(result.skipped_files, 1)

    def test_backend_result_and_context_validator_enforce_coverage_invariants(self) -> None:
        with self.assertRaises(ValueError):
            BackendResult("python-ast", "structural", ("python",), "complete", 1, 2, 0)
        context = {
            "schema_version": "1.2", "mode": "full", "scope": {}, "intent": {},
            "repository": {}, "behavioural_units": [], "candidates": [], "commands": [],
            "limitations": [], "test_evidence": {
                "status": "complete", "state": "Checked", "artifacts": [], "subjects": [],
                "relations": [], "changes": [], "static_candidates": [], "matrix": [],
                "mutations": [], "proof_tests": [],
            }, "complexity": {
                "status": "complete", "backend_id": "lizard-fallback", "functions": [],
                "candidates": [], "policy": {},
            }, "coverage": {
                "anti-slop": {"state": "Checked", "reason": "ok", "backends": {
                    "python-ast": {
                        "state": "Checked", "level": "structural", "languages": ["python"],
                        "applicable_files": 1, "checked_files": 2, "skipped_files": 0,
                        "reason": "bad", "status": "complete",
                    },
                }},
            },
        }
        self.assertTrue(any("exceeds applicable_files" in error for error in validate(context)))

    def test_ast_grep_diagnostic_paths_are_bound_to_requested_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "main.go"
            source.write_text("package main\n")
            target = AnalysisTarget("main.go", source, "go")
            match = {"file": "../outside.go", "ruleId": "no-interface-round-trip", "range": {"start": {"line": 1, "column": 0}}}
            with self.assertRaises(ValueError):
                _matches_to_diagnostics([match], root, [target], "anti-slop-go")

    def test_ast_grep_locations_are_one_based_in_the_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "main.go"
            source.write_text("package main\nfunc load() {}\n")
            target = AnalysisTarget("main.go", source, "go")
            match = {"file": "main.go", "ruleId": "no-interface-round-trip", "range": {"start": {"line": 1, "column": 4}}}
            diagnostics = _matches_to_diagnostics([match], root, [target], "anti-slop-go")
            self.assertEqual((diagnostics[0].line, diagnostics[0].column), (2, 4))

    def test_same_line_different_columns_keep_distinct_evidence(self) -> None:
        first = BackendDiagnostic("backend", "python", "rule", "app.py", 4, 2, "same", {"source_layer": "index", "content_sha256": "a" * 64, "rule_discriminator": "left"})
        second = BackendDiagnostic("backend", "python", "rule", "app.py", 4, 9, "same", {"source_layer": "index", "content_sha256": "a" * 64, "rule_discriminator": "right"})
        self.assertNotEqual(canonical_diagnostic_identity(first), canonical_diagnostic_identity(second))

    def test_optional_analyser_targets_preserve_diff_source_layers(self) -> None:
        violation = (
            "from typing import Any, cast\n"
            "value = cast(Target, cast(Any, source))\n"
        )

        def git(root: Path, *arguments: str) -> str:
            result = subprocess.run(
                ["git", *arguments], cwd=root, text=True,
                capture_output=True, check=True,
            )
            return result.stdout.strip()

        def initialise(root: Path) -> None:
            git(root, "init", "-q")
            git(root, "config", "user.email", "test@example.com")
            git(root, "config", "user.name", "Test")
            git(root, "config", "commit.gpgsign", "false")

        def commit(root: Path, message: str) -> str:
            git(root, "add", "-A")
            git(root, "commit", "-qm", message)
            return git(root, "rev-parse", "HEAD")

        def evidence(
            root: Path,
            path: str,
            entries: list[DiffEntry],
            base: str = "",
        ) -> tuple[dict, tuple[str, ...], Path | None, bool]:
            with _diff_optional_targets(root, [path], entries, base, {}) as snapshot:
                physical = snapshot.anti_targets[0].physical_path if snapshot.anti_targets else None
                result = orchestrator.analyse(root, targets=snapshot.anti_targets, config={})
                layers = tuple(
                    evidence_item["source_layer"]
                    for candidate in result["candidates"]
                    for evidence_item in candidate["supporting_evidence"]
                )
                outside_snapshot = bool(physical and not physical.is_relative_to(root.resolve()))
            return result, layers, physical, outside_snapshot

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            source = root / "staged.py"
            source.write_text("value = 1\n")
            commit(root, "base")
            source.write_text(violation)
            git(root, "add", "staged.py")
            source.write_text("value = 1\n")
            result, layers, physical, outside_snapshot = evidence(root, "staged.py", changed_entries(root))
            self.assertEqual(result["state"], "Checked")
            self.assertEqual(layers, ("index",))
            self.assertTrue(outside_snapshot)
            self.assertIsNotNone(physical)
            self.assertFalse(physical.exists())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            source = root / "worktree.py"
            source.write_text("value = 1\n")
            commit(root, "base")
            source.write_text(violation)
            result, layers, _physical, _outside_snapshot = evidence(root, "worktree.py", changed_entries(root))
            self.assertEqual(result["state"], "Checked")
            self.assertEqual(layers, ("working-tree",))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            source = root / "committed.py"
            source.write_text("value = 1\n")
            base = commit(root, "base")
            source.write_text(violation)
            commit(root, "reviewed commit")
            entries = changed_entries(root, f"{base}...HEAD")
            result, layers, _physical, _outside_snapshot = evidence(root, "committed.py", entries, base)
            self.assertEqual(result["state"], "Checked")
            self.assertEqual(layers, ("commit", "working-tree"))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            tracked = root / "tracked.py"
            tracked.write_text("value = 1\n")
            commit(root, "base")
            untracked = root / "untracked.py"
            untracked.write_text(violation)
            result, layers, _physical, _outside_snapshot = evidence(root, "untracked.py", changed_entries(root))
            self.assertEqual(result["state"], "Checked")
            self.assertEqual(layers, ("untracked",))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            source = root / "same.py"
            source.write_text("value = 1\n")
            commit(root, "base")
            source.write_text(violation)
            git(root, "add", "same.py")
            identical_entries = [
                DiffEntry("M", "same.py", "same.py", True, "index", index_stage=0),
                DiffEntry("M", "same.py", "same.py", True, "working-tree"),
            ]
            with _diff_optional_targets(root, ["same.py"], identical_entries, "", {}) as snapshot:
                self.assertEqual(len(snapshot.anti_targets), 2)
                self.assertEqual(
                    {target.source_kind for target in snapshot.anti_targets},
                    {"index", "working-tree"},
                )
                result = orchestrator.analyse(root, targets=snapshot.anti_targets, config={})
            self.assertEqual(result["state"], "Checked")
            self.assertEqual(
                len(result["candidates"]),
                2,
            )
            self.assertEqual(
                {
                    evidence["source_layer"]
                    for candidate in result["candidates"]
                    for evidence in candidate["supporting_evidence"]
                },
                {"index", "working-tree"},
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            source = root / "different.py"
            source.write_text("value = 1\n")
            commit(root, "base")
            source.write_text(violation)
            git(root, "add", "different.py")
            source.write_text("value = getattr(source, 'name')\n")
            with _diff_optional_targets(root, ["different.py"], changed_entries(root), "", {}) as snapshot:
                self.assertEqual(len(snapshot.anti_targets), 2)
                self.assertEqual(
                    {target.source_kind for target in snapshot.anti_targets},
                    {"index", "working-tree"},
                )
                result = orchestrator.analyse(root, targets=snapshot.anti_targets, config={})
            self.assertEqual(result["state"], "Checked")
            evidence_layers = {
                evidence_item["source_layer"]
                for candidate in result["candidates"]
                for evidence_item in candidate["supporting_evidence"]
            }
            self.assertEqual(evidence_layers, {"index"})
            self.assertEqual(
                {candidate["source"] for candidate in result["candidates"]},
                {"anti-slop-python/no-widen-then-cast"},
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            source = root / "old.py"
            source.write_text("value = 1\n")
            base = commit(root, "base")
            source.rename(root / "new.py")
            (root / "new.py").write_text(violation)
            commit(root, "rename")
            entries = changed_entries(root, f"{base}...HEAD")
            result, layers, _physical, _outside_snapshot = evidence(root, "new.py", entries, base)
            self.assertEqual(result["state"], "Checked")
            self.assertEqual(layers, ("commit", "working-tree"))
            self.assertEqual(result["candidates"][0]["trigger_path"], ["new.py:2"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialise(root)
            source = root / "deleted.py"
            source.write_text(violation)
            base = commit(root, "base")
            source.unlink()
            entries = changed_entries(root, f"{base}...HEAD")
            with _diff_optional_targets(root, ["deleted.py"], entries, base, {}) as snapshot:
                self.assertEqual(snapshot.anti_targets, ())
                self.assertEqual(snapshot.comment_targets, ())

    def test_process_group_termination_removes_worker_and_child(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "child.pid"
            worker = (
                "import pathlib, subprocess, sys, time\n"
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                f"pathlib.Path({str(pid_path)!r}).write_text(str(child.pid))\n"
                "time.sleep(60)\n"
            )
            process = subprocess.Popen(
                [sys.executable, "-c", worker],
                start_new_session=True,
            )
            try:
                for _ in range(100):
                    if pid_path.exists():
                        break
                    time.sleep(0.01)
                self.assertTrue(pid_path.exists())
                child_pid = int(pid_path.read_text())
                _terminate_process_group(process)
                self.assertIsNotNone(process.poll())
                for _ in range(100):
                    try:
                        os.kill(child_pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.01)
                with self.assertRaises(ProcessLookupError):
                    os.kill(child_pid, 0)
            finally:
                if process.poll() is None:
                    _terminate_process_group(process)

    def test_context_supervisor_timeout_preserves_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("value = 1\n")
            output = root / "context.json"
            output.write_text("previous context\n")
            command = [
                sys.executable, str(ROOT / "scripts" / "build_review_context.py"),
                "--root", str(root), "--mode", "full", "--timeout", "0.01", "--output", str(output),
            ]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 124, result.stderr)
            self.assertIn("context construction exceeded", result.stderr)
            self.assertEqual(output.read_text(), "previous context\n")

    def test_context_cli_has_no_mock_type_control_path(self) -> None:
        source = (ROOT / "scripts" / "build_review_context.py").read_text(encoding="utf-8")
        self.assertNotIn("types.FunctionType", source)
        self.assertNotIn("threading.Thread", source)

    def test_context_cli_rejects_success_without_worker_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch(
            "build_review_context._worker_arguments",
            return_value=[sys.executable, "-c", "pass"],
        ), patch.object(
            sys,
            "argv",
            ["build_review_context.py", "--mode", "full", "--timeout", "2", "--output", str(Path(directory) / "context.json")],
        ):
            self.assertEqual(main(), 1)
            self.assertFalse((Path(directory) / "context.json").exists())

    def test_rule_ownership_is_unique_for_all_backend_contracts(self) -> None:
        rule_ids: list[str] = []
        for path in (ROOT / "scripts" / "vendor" / "anti-slop" / "ast-grep" / "rules").rglob("*.yml"):
            first = path.read_text(encoding="utf-8").splitlines()[0]
            self.assertTrue(first.startswith("id: "), path)
            rule_id = first.removeprefix("id: ").strip()
            rule_ids.append(rule_id)
            self.assertEqual(owner_for(rule_id), "ast-grep-" + path.parent.name)
        self.assertEqual(len(rule_ids), len(set(rule_ids)))
        self.assertEqual(validate_rule_ownership(ROOT), [])


if __name__ == "__main__":
    unittest.main()
