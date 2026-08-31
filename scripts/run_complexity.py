#!/usr/bin/env python3
"""Run bounded function-level complexity analysis."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dissect_checks.complexity.orchestrator import analyse  # noqa: E402
from dissect_checks.redaction import redact_payload, redact_sensitive_text  # noqa: E402
from diff_file_list import DiffEntry, changed_entries, read_diff_entries  # noqa: E402
from dissect_checks.test_integrity.orchestrator import source_maps  # noqa: E402


def _hunk_ranges(diff_text: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for line in diff_text.splitlines():
        if not line.startswith("@@"):
            continue
        marker = line.split("@@", 2)[1].strip().split()[1]
        start_text, _, count_text = marker.removeprefix("+").partition(",")
        start = int(start_text)
        count = int(count_text or "1")
        if count:
            ranges.append((start, start + count - 1))
    return ranges


def _diff_ranges(root: Path, path: str, entries: list[DiffEntry], base: str, text: str) -> list[tuple[int, int]] | None:
    if any(item.source_kind == "untracked" and item.reviewed_path == path for item in entries):
        return [(1, max(1, len(text.splitlines())))]
    commands = [["git", "diff", "--unified=0", base, "--", path]] if base else [
        ["git", "diff", "--unified=0", "--", path],
        ["git", "diff", "--cached", "--unified=0", "--", path],
    ]
    outputs: list[str] = []
    succeeded = False
    for command in commands:
        try:
            result = subprocess.run(command, cwd=root, capture_output=True, text=True, check=False)
        except OSError:
            continue
        if result.returncode == 0:
            succeeded = True
            outputs.append(result.stdout)
    return _hunk_ranges("\n".join(outputs)) if succeeded else None


def _diff_inputs(
    root: Path,
    requested: list[str],
    base: str,
    file_list: Path | None,
) -> tuple[list[str], dict[str, str], dict[str, str], dict[str, list[tuple[int, int]] | None], str]:
    try:
        entries = read_diff_entries(file_list) if file_list is not None else changed_entries(root, base)
    except RuntimeError:
        entries = []
    requested_set = set(requested)
    selected_entries = [item for item in entries if not requested_set or item.reviewed_path in requested_set]
    paths = sorted(set(requested or [item.reviewed_path for item in selected_entries if item.reviewed_path]))
    if not paths and requested:
        paths = sorted(requested_set)
        selected_entries = [
            DiffEntry("M", path, path, (root / path).is_file(), "working-tree")
            for path in paths
        ]
    base_contents, head_contents = source_maps(
        root,
        selected_entries,
        paths,
        base_revision=base,
        head_revision="HEAD",
    )
    changed_ranges = {
        path: _diff_ranges(root, path, selected_entries, base, head_contents.get(path, ""))
        for path in paths
    }
    layers = {item.source_kind for item in selected_entries if not item.status.startswith("D")}
    source_kind = next(
        (layer for layer in ("working-tree", "untracked", "index", "commit") if layer in layers),
        "working-tree",
    )
    return paths, base_contents, head_contents, changed_ranges, source_kind


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--mode", choices=("full", "diff"), default="full")
    parser.add_argument("--base", default="", help="Base revision for diff mode")
    parser.add_argument("--file-list", type=Path, help="Canonical diff-entry file for diff mode")
    parser.add_argument("--file", action="append", default=[])
    parser.add_argument("--format", choices=("json",), default="json")
    args = parser.parse_args(argv)
    try:
        config = {}
        config_path = args.root / ".ai-review" / "local.json"
        if config_path.is_file():
            loaded = json.loads(config_path.read_text(encoding="utf-8"))
            config = loaded if isinstance(loaded, dict) else {}
        if args.mode == "diff":
            paths, base_contents, head_contents, changed_ranges, source_kind = _diff_inputs(
                args.root.resolve(), args.file, args.base, args.file_list,
            )
            result = analyse(
                args.root,
                paths or None,
                mode="diff",
                config=config,
                base_contents=base_contents,
                head_contents=head_contents,
                changed_ranges=changed_ranges,
                source_kind=source_kind,
            )
        else:
            result = analyse(args.root, args.file or None, mode="full", config=config)
        print(json.dumps(redact_payload(result.as_dict()), indent=2, sort_keys=True))
        return 0
    except (OSError, RuntimeError, ValueError) as error:
        print(redact_sensitive_text(str(error)), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
