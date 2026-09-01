#!/usr/bin/env python3
"""Run bounded function-level complexity analysis."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dissect_checks.complexity.orchestrator import analyse  # noqa: E402
from dissect_checks.redaction import redact_payload, redact_sensitive_text  # noqa: E402
from diff_file_list import DiffEntry, changed_entries, read_diff_entries  # noqa: E402
from dissect_checks.test_integrity.orchestrator import _head_source_kinds, source_maps  # noqa: E402


def _hunk_ranges(diff_text: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for line in diff_text.splitlines():
        if not line.startswith("@@"):
            continue
        match = re.search(r"\+(\d+)(?:,(\d+))?", line)
        if match is None:
            continue
        start = int(match.group(1))
        count = int(match.group(2) or "1")
        if count:
            ranges.append((start, start + count - 1))
    return ranges


def _diff_ranges(root: Path, path: str, entries: list[DiffEntry], base: str, text: str) -> list[tuple[int, int]] | None:
    if any(item.source_kind == "untracked" and item.reviewed_path == path for item in entries):
        return [(1, max(1, len(text.splitlines())))]
    if base:
        left = base.split("...", 1)[0] if "..." in base else base
        right = base.split("...", 1)[1] if "..." in base else "HEAD"
        commands = [["git", "diff", "--unified=0", left, right, "--", path]]
    else:
        matching = [item for item in entries if item.reviewed_path == path]
        has_unstaged = any(item.source_kind == "working-tree" for item in matching)
        if has_unstaged:
            try:
                probe = subprocess.run(
                    ["git", "diff", "--quiet", "--", path],
                    cwd=root,
                    capture_output=True,
                    check=False,
                )
                has_unstaged = probe.returncode == 1
            except OSError:
                has_unstaged = False
        if has_unstaged:
            commands = [["git", "diff", "--unified=0", "--", path]]
        elif any(item.source_kind == "index" for item in matching):
            commands = [["git", "diff", "--cached", "--unified=0", "--", path]]
        elif any(item.source_kind == "commit" for item in matching):
            commands = [["git", "diff", "--unified=0", "HEAD^", "HEAD", "--", path]]
        else:
            commands = [["git", "diff", "--unified=0", "--", path]]
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
) -> tuple[list[str], dict[str, str], dict[str, str], dict[str, list[tuple[int, int]] | None], str, dict[str, str]]:
    try:
        committed_range = (
            f"{base}...HEAD"
            if base and "..." not in base
            else base
        )
        entries = read_diff_entries(file_list) if file_list is not None else changed_entries(root, committed_range)
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
        base_revision=base.split("...", 1)[0] if "..." in base else base,
        head_revision=base.split("...", 1)[1] if "..." in base and base.split("...", 1)[1] else "HEAD",
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
    normalized_base = base.split("...", 1)[0] if "..." in base else base
    return paths, base_contents, head_contents, changed_ranges, source_kind, _head_source_kinds(
        selected_entries, paths, normalized_base, root=root,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--mode", choices=("full", "diff"), default="full")
    parser.add_argument("--base", default="", help="Base revision for diff mode")
    parser.add_argument("--file-list", type=Path, help="Canonical diff-entry file for diff mode")
    parser.add_argument("--file", action="append", default=[])
    parser.add_argument("--max-candidates", type=int, help="Override the complexity candidate budget for this evidence run")
    parser.add_argument("--format", choices=("json",), default="json")
    args = parser.parse_args(argv)
    try:
        config = {}
        config_path = args.root / ".ai-review" / "local.json"
        if config_path.is_file():
            loaded = json.loads(config_path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("review configuration must be a JSON object")
            config = loaded
        if args.max_candidates is not None:
            if args.max_candidates < 1:
                raise ValueError("--max-candidates must be positive")
            options = dict(config.get("review_options", {})) if isinstance(config.get("review_options"), dict) else {}
            limits = dict(options.get("analysis_limits", {})) if isinstance(options.get("analysis_limits"), dict) else {}
            limits["complexity_max_candidates"] = args.max_candidates
            options["analysis_limits"] = limits
            config = {**config, "review_options": options}
        if args.mode == "diff":
            paths, base_contents, head_contents, changed_ranges, source_kind, source_kind_by_path = _diff_inputs(
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
                source_kind_by_path=source_kind_by_path,
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
