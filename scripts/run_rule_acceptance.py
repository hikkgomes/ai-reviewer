#!/usr/bin/env python3
"""Compile and scan the compiler-valid structural rule fixtures."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dissect_checks.anti_slop import orchestrator  # noqa: E402


ACCEPTANCE_ROOT = ROOT / "tests" / "fixtures" / "anti-slop" / "acceptance"
VENDOR_DIR = ROOT / "scripts" / "vendor" / "anti-slop"

CASES: dict[str, dict[str, Any]] = {
    "go": {
        "extension": ".go",
        "positive": "round_trip.go",
        "negative": "negative.go",
        "malformed": "malformed.go",
        "generated": "generated/round_trip.go",
        "rules": {
            "anti-slop-go/no-interface-round-trip": (10, 8),
            "anti-slop-go/no-reflect-interface-round-trip": (14, 8),
        },
    },
    "rust": {
        "extension": ".rs",
        "positive": "round_trip.rs",
        "negative": "negative.rs",
        "malformed": "malformed.rs",
        "generated": "generated/round_trip.rs",
        "rules": {
            "anti-slop-rust/no-same-type-transmute": (4, 13),
            "anti-slop-rust/no-immediate-any-round-trip": (8, 5),
        },
    },
    "c": {
        "extension": ".c",
        "positive": "round_trip.c",
        "negative": "negative.c",
        "malformed": "malformed.c",
        "generated": "generated/round_trip.c",
        "rules": {
            "anti-slop-c/no-void-pointer-round-trip": (6, 12),
        },
    },
    "cpp": {
        "extension": ".cpp",
        "positive": "round_trip.cpp",
        "negative": "negative.cpp",
        "malformed": "malformed.cpp",
        "generated": "generated/round_trip.cpp",
        "rules": {
            "anti-slop-cpp/no-redundant-same-type-cast": (6, 11),
            "anti-slop-cpp/no-void-pointer-cast-chain": (10, 11),
        },
    },
    "java": {
        "extension": ".java",
        "positive": "RoundTrip.java",
        "negative": "Negative.java",
        "malformed": "Malformed.java",
        "generated": "generated/Generated.java",
        "rules": {
            "anti-slop-java/no-object-cast-round-trip": (9, 15),
            "anti-slop-java/no-literal-class-reflection": (13, 15),
        },
    },
    "csharp": {
        "extension": ".cs",
        "positive": "RoundTrip.cs",
        "negative": "Negative.cs",
        "malformed": "Malformed.cs",
        "generated": "generated/Generated.cs",
        "rules": {
            "anti-slop-csharp/no-object-cast-round-trip": (12, 15),
            "anti-slop-csharp/no-literal-type-reflection": (17, 15),
        },
    },
}


def _run(command: list[str], cwd: Path, *, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, env=environment, capture_output=True, text=True, check=False)


def _compiler_available(language: str) -> bool:
    command = {
        "go": "go", "rust": "rustc", "c": "clang", "cpp": "clang++", "java": "javac", "csharp": "dotnet",
    }[language]
    return shutil.which(command) is not None


def _compile(language: str, root: Path) -> tuple[bool, str]:
    if not _compiler_available(language):
        return False, "toolchain_unavailable"
    positive = root / CASES[language]["positive"]
    negative = root / CASES[language]["negative"]
    generated = root / CASES[language]["generated"]
    malformed = root / CASES[language]["malformed"]
    with tempfile.TemporaryDirectory(prefix=f"dissect-{language}-acceptance-") as directory:
        output = Path(directory)
        if language == "go":
            environment = dict(os.environ)
            environment["GOCACHE"] = str(output / "go-cache")
            result = _run(["go", "test", "./..."], root, environment=environment)
            if result.returncode != 0:
                return False, (result.stderr or result.stdout)[-500:]
            malformed_result = _run(["go", "test", "-tags", "acceptance_malformed", "./..."], root, environment=environment)
            if malformed_result.returncode == 0:
                return False, "malformed Go fixture unexpectedly compiled"
        elif language == "rust":
            for source in (positive, negative, generated):
                result = _run(["rustc", "--edition=2021", "--crate-type", "lib", str(source), "-o", str(output / f"{source.stem}.rlib")], root)
                if result.returncode != 0:
                    return False, (result.stderr or result.stdout)[-500:]
            malformed_result = _run(["rustc", "--edition=2021", "--crate-type", "lib", str(malformed), "-o", str(output / "malformed.rlib")], root)
            if malformed_result.returncode == 0:
                return False, "malformed Rust fixture unexpectedly compiled"
        elif language == "c":
            for source in (positive, negative, generated):
                result = _run(["clang", "-std=c11", "-fsyntax-only", str(source)], root)
                if result.returncode != 0:
                    return False, (result.stderr or result.stdout)[-500:]
            malformed_result = _run(["clang", "-std=c11", "-fsyntax-only", str(malformed)], root)
            if malformed_result.returncode == 0:
                return False, "malformed C fixture unexpectedly compiled"
        elif language == "cpp":
            for source in (positive, negative, generated):
                result = _run(["clang++", "-std=c++17", "-fsyntax-only", str(source)], root)
                if result.returncode != 0:
                    return False, (result.stderr or result.stdout)[-500:]
            malformed_result = _run(["clang++", "-std=c++17", "-fsyntax-only", str(malformed)], root)
            if malformed_result.returncode == 0:
                return False, "malformed C++ fixture unexpectedly compiled"
        elif language == "java":
            for source in (positive, negative, generated):
                result = _run(["javac", "-d", str(output), str(source)], root)
                if result.returncode != 0:
                    return False, (result.stderr or result.stdout)[-500:]
            malformed_result = _run(["javac", "-d", str(output), str(malformed)], root)
            if malformed_result.returncode == 0:
                return False, "malformed Java fixture unexpectedly compiled"
        elif language == "csharp":
            result = _run(["dotnet", "build", "--nologo", "--configuration", "Release"], root)
            if result.returncode != 0:
                return False, (result.stderr or result.stdout)[-500:]
        return True, "compiled"


def _scan(language: str, *, vendor_dir: Path = VENDOR_DIR, disabled_rule: str | None = None) -> dict[str, Any]:
    root = ACCEPTANCE_ROOT / language
    config = {"paths": {"generated": ["generated/"]}}
    positive = orchestrator.analyse(root, [CASES[language]["positive"]], config=config, vendor_dir=vendor_dir)
    negative = orchestrator.analyse(root, [CASES[language]["negative"]], config=config, vendor_dir=vendor_dir)
    malformed = orchestrator.analyse(root, [CASES[language]["malformed"]], config=config, vendor_dir=vendor_dir)
    generated = orchestrator.analyse(root, [CASES[language]["generated"]], config=config, vendor_dir=vendor_dir)
    expected = dict(CASES[language]["rules"])
    if disabled_rule is not None:
        expected.pop(disabled_rule, None)
    actual = {
        item["source"]: (
            item["supporting_evidence"][0].get("line"),
            item["supporting_evidence"][0].get("column"),
        )
        for item in positive["candidates"]
    }
    if actual != expected:
        raise AssertionError(f"{language} positive cases differ: expected {expected!r}, got {actual!r}")
    if negative["candidates"]:
        raise AssertionError(f"{language} negative fixture produced candidates")
    if malformed["state"] != "Not verified" or malformed["backends"].get(f"ast-grep-{language}", {}).get("status") not in {"partial", "unavailable"}:
        raise AssertionError(f"{language} malformed fixture was treated as verified")
    if generated["state"] != "Not applicable" or generated["candidates"]:
        raise AssertionError(f"{language} generated fixture was not excluded")
    return {
        "positive": {"state": positive["state"], "candidates": actual},
        "negative": {"state": negative["state"], "candidates": []},
        "malformed": {"state": malformed["state"]},
        "generated": {"state": generated["state"]},
    }


def _disabled_vendor(rule_id: str) -> tempfile.TemporaryDirectory[str]:
    language, short_name = rule_id.removeprefix("anti-slop-").split("/", 1)
    temporary = tempfile.TemporaryDirectory(prefix="dissect-rule-disabled-")
    destination = Path(temporary.name)
    shutil.copytree(VENDOR_DIR / "ast-grep", destination / "ast-grep")
    os.symlink(VENDOR_DIR / "node_modules", destination / "node_modules", target_is_directory=True)
    rule_path = destination / "ast-grep" / "rules" / language / f"{short_name}.yml"
    if not rule_path.is_file():
        temporary.cleanup()
        raise FileNotFoundError(f"rule file not found: {rule_id}")
    rule_path.unlink()
    return temporary


def run(*, languages: Iterable[str] = CASES, require_toolchains: bool = False, disabled_rule: str | None = None) -> dict[str, Any]:
    selected = tuple(languages)
    report: dict[str, Any] = {"schema_version": "1.0", "fixtures": {}}
    disabled_context: tempfile.TemporaryDirectory[str] | None = None
    vendor_dir = VENDOR_DIR
    if disabled_rule:
        disabled_context = _disabled_vendor(disabled_rule)
        vendor_dir = Path(disabled_context.name)
    try:
        for language in selected:
            if language not in CASES:
                raise ValueError(f"unknown acceptance language: {language}")
            compiled, detail = _compile(language, ACCEPTANCE_ROOT / language)
            if not compiled and detail == "toolchain_unavailable" and not require_toolchains:
                report["fixtures"][language] = {"state": "Not verified", "compile": detail}
                continue
            if not compiled:
                raise AssertionError(f"{language} compiler acceptance failed: {detail}")
            report["fixtures"][language] = {"compile": detail, "scan": _scan(language, vendor_dir=vendor_dir, disabled_rule=disabled_rule)}
        if disabled_rule:
            expected_language = next((language for language, values in CASES.items() if disabled_rule in values["rules"]), None)
            if expected_language is None:
                raise ValueError(f"rule is not in the acceptance corpus: {disabled_rule}")
            positive = report["fixtures"].get(expected_language, {})
            candidates = positive.get("scan", {}).get("positive", {}).get("candidates", {})
            if disabled_rule in candidates:
                raise AssertionError(f"disabled rule still produced an acceptance match: {disabled_rule}")
    finally:
        if disabled_context is not None:
            disabled_context.cleanup()
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", action="append", choices=tuple(CASES))
    parser.add_argument("--require-toolchains", action="store_true")
    parser.add_argument("--disable-rule")
    parser.add_argument("--format", choices=("json",), default="json")
    args = parser.parse_args(argv)
    try:
        report = run(languages=args.language or CASES, require_toolchains=args.require_toolchains, disabled_rule=args.disable_rule)
    except (AssertionError, FileNotFoundError, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
