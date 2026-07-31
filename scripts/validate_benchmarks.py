#!/usr/bin/env python3
"""Validate offline benchmark manifests without network or model dependencies."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

REQUIRED = {"schema_version", "id", "intent", "frameworks", "base", "proposed", "expected_findings", "forbidden_findings", "expected_severity", "required_not_verified", "mutations"}


def validate_case(path: Path) -> list[str]:
    errors = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return [f"{path}: {error}"]
    missing = REQUIRED - data.keys()
    errors.extend(f"{path}: missing {key}" for key in sorted(missing))
    if data.get("schema_version") != "1.0":
        errors.append(f"{path}: schema_version must be 1.0")
    if not isinstance(data.get("frameworks"), list) or not data["frameworks"]:
        errors.append(f"{path}: frameworks must be a non-empty array")
    if not isinstance(data.get("mutations"), list) or not data["mutations"]:
        errors.append(f"{path}: mutations must be a non-empty array")
    intent_path = path.parent / "intent.md"
    if not intent_path.exists():
        errors.append(f"{path}: intent.md is required for benchmark provenance")
    for directory in (data.get("base"), data.get("proposed")):
        if not isinstance(directory, str) or not (path.parent / directory).is_dir():
            errors.append(f"{path}: benchmark directory does not exist: {directory}")
        elif len([item for item in (path.parent / directory).rglob("*") if item.is_file()]) < 2:
            errors.append(f"{path}: {directory} must contain at least two files")
    if data.get("corrected") is not None and not (path.parent / str(data["corrected"])).is_dir():
        errors.append(f"{path}: corrected directory does not exist: {data['corrected']}")
    ids = set()
    for finding in data.get("expected_findings", []):
        if not isinstance(finding, dict) or not {"id", "location", "severity"} <= finding.keys():
            errors.append(f"{path}: expected finding needs id, location, severity")
        elif finding["id"] in ids:
            errors.append(f"{path}: duplicate expected finding {finding['id']}")
        else:
            ids.add(finding["id"])
    if not isinstance(data.get("required_not_verified"), list):
        errors.append(f"{path}: required_not_verified must be an array")
    return errors


def validate(root: Path) -> list[str]:
    manifests = sorted(root.glob("**/benchmark.json"))
    if not manifests:
        return [f"{root}: no benchmark.json manifests found"]
    errors = []
    seen = set()
    for path in manifests:
        errors.extend(validate_case(path))
        try:
            identifier = json.loads(path.read_text()) .get("id")
        except (OSError, ValueError):
            identifier = None
        if identifier in seen:
            errors.append(f"{path}: duplicate benchmark id {identifier}")
        seen.add(identifier)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1] / "benchmarks")
    args = parser.parse_args()
    errors = validate(args.root)
    if errors:
        print("\n".join(errors))
        return 1
    print(f"Validated {len(list(args.root.glob('**/benchmark.json')))} benchmark manifests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
