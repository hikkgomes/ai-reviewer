from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dissect_checks.engine import ScanOptions, options_from_environment, scan_report


def dependency_candidates(root: Path, **kwargs):
    return [
        item for item in scan_report(ScanOptions(root=root, **kwargs)).findings
        if item.check_id == "SUP-DEPENDENCY-004"
    ]


class PythonDependencyTests(unittest.TestCase):
    def test_well_known_distribution_import_aliases(self) -> None:
        aliases = {
            "Pillow": "PIL",
            "PyYAML": "yaml",
            "beautifulsoup4": "bs4",
            "scikit-learn": "sklearn",
            "opencv-python": "cv2",
        }
        for distribution, module in aliases.items():
            with self.subTest(distribution=distribution):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "pyproject.toml").write_text(
                        f'[project]\ndependencies = ["{distribution}"]\n'
                    )
                    (root / "app.py").write_text(f"import {module}\n")
                    self.assertEqual(dependency_candidates(root), [])

    def test_user_alias_and_nearest_monorepo_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package_a = root / "packages" / "a"
            package_b = root / "packages" / "b"
            package_a.mkdir(parents=True)
            package_b.mkdir(parents=True)
            (package_a / "pyproject.toml").write_text(
                '[project]\ndependencies = ["company-sdk"]\n'
            )
            (package_b / "pyproject.toml").write_text(
                '[project]\ndependencies = ["different-sdk"]\n'
            )
            (package_a / "app.py").write_text("import company_api\n")
            options = ScanOptions(
                root=root,
                python_import_aliases=(("company_api", "company-sdk"),),
            )
            self.assertFalse(any(
                item.check_id == "SUP-DEPENDENCY-004"
                for item in scan_report(options).findings
            ))
            (package_a / "app.py").write_text("import different_sdk\n")
            self.assertTrue(dependency_candidates(
                root,
                python_import_aliases=(("different_sdk", "different-sdk"),),
            ))

    def test_user_alias_loads_from_backwards_compatible_local_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".ai-review").mkdir()
            (root / ".ai-review" / "local.json").write_text(
                '{"security_review":{"python_import_aliases":'
                '{"company_api":"company-sdk"}}}'
            )
            (root / "pyproject.toml").write_text(
                '[project]\ndependencies = ["company-sdk"]\n'
            )
            (root / "app.py").write_text("import company_api\n")
            options = options_from_environment(root)
            self.assertEqual(options.python_import_aliases, (("company_api", "company-sdk"),))
            self.assertFalse(any(
                item.check_id == "SUP-DEPENDENCY-004"
                for item in scan_report(options).findings
            ))

    def test_recursive_requirements_cycle_and_missing_include(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text(
                "-r requirements-api.txt\n-r missing.txt\n"
            )
            (root / "requirements-api.txt").write_text(
                "-r requirements.txt\nhttpx[http2]>=0.27; python_version >= '3.11'\n"
            )
            (root / "app.py").write_text("import httpx\n")
            report = scan_report(ScanOptions(root=root))
            self.assertFalse(any(
                item.check_id == "SUP-DEPENDENCY-004" for item in report.findings
            ))
            self.assertFalse(report.complete)
            self.assertTrue(any("missing included requirements" in error for error in report.coverage_errors))

    def test_direct_editable_and_vcs_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text(
                "httpx @ https://example.invalid/httpx.whl\n"
                "-e git+https://example.invalid/repo.git#egg=editable_pkg\n"
                "vcs_pkg @ git+https://example.invalid/vcs.git@main\n"
            )
            (root / "app.py").write_text(
                "import httpx\nimport editable_pkg\nimport vcs_pkg\n"
            )
            self.assertEqual(dependency_candidates(root), [])

    def test_constraints_do_not_declare_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("-c constraints.txt\n")
            (root / "constraints.txt").write_text("httpx==0.28.0\n")
            (root / "app.py").write_text("import httpx\n")
            candidates = dependency_candidates(root)
            self.assertEqual([item.evidence for item in candidates], ["httpx"])

            (root / "requirements.txt").write_text(
                "-r requirements-api.in\n-c constraints.txt\n"
            )
            (root / "requirements-api.in").write_text("httpx[http2]>=0.27\n")
            self.assertEqual(dependency_candidates(root), [])

    def test_nested_requirement_and_constraint_includes_are_separate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text(
                "-r nested/requirements.in\n-c nested/constraints.in\n"
            )
            nested = root / "nested"
            nested.mkdir()
            (nested / "requirements.in").write_text(
                "-r ../requirements.txt\n"
                "-e git+https://example.invalid/editable.git#egg=editable_pkg\n"
                "direct_pkg @ https://example.invalid/direct.whl\n"
            )
            (nested / "constraints.in").write_text(
                "-c ../constraints-extra.txt\nconstraint_only==1\n"
            )
            (root / "constraints-extra.txt").write_text(
                "-c nested/constraints.in\neditable_pkg==2\n"
            )
            (root / "app.py").write_text(
                "import editable_pkg\nimport direct_pkg\nimport constraint_only\n"
            )
            report = scan_report(ScanOptions(root=root))
            self.assertTrue(report.complete, report.coverage_errors)
            candidates = [
                item.evidence for item in report.findings
                if item.check_id == "SUP-DEPENDENCY-004"
            ]
            self.assertEqual(candidates, ["constraint_only"])

    def test_missing_nested_constraint_is_a_coverage_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("-c missing-constraints.txt\n")
            (root / "app.py").write_text("import missing_dependency\n")
            report = scan_report(ScanOptions(root=root))
            self.assertFalse(report.complete)
            self.assertTrue(any(
                "missing included constraint file" in error
                for error in report.coverage_errors
            ))

    def test_local_package_is_allowed_but_hallucinated_neighbor_is_not(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "real_package"
            package.mkdir()
            (package / "__init__.py").write_text("")
            (root / "pyproject.toml").write_text('[project]\ndependencies = []\n')
            (root / "app.py").write_text(
                "import real_package\nimport real_package_typo\n"
            )
            candidates = dependency_candidates(root)
            self.assertEqual([item.evidence for item in candidates], ["real_package_typo"])


if __name__ == "__main__":
    unittest.main()
