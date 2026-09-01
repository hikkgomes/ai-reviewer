#!/usr/bin/env python3
"""Run the shared anti-slop orchestrator and print one JSON envelope."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Iterable

if sys.version_info < (3, 11):
    raise SystemExit("Dissect requires Python 3.11 or newer.")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from diff_file_list import DiffEntry, deserialize_entries, read_diff_entries  # noqa: E402
from dissect_checks.anti_slop import orchestrator  # noqa: E402
from dissect_checks.redaction import redact_payload, redact_sensitive_text  # noqa: E402
from language_registry import paths_for_anti_slop  # noqa: E402


VENDOR_DIR = ROOT / "scripts" / "vendor" / "anti-slop"
SCHEMA_VERSION = "anti-slop/2.0"


def _entries_paths(entries: Iterable[DiffEntry]) -> list[str]:
    values = [entry.reviewed_path for entry in entries if entry.exists_in_worktree and entry.reviewed_path]
    return sorted({path for group in paths_for_anti_slop(values).values() for path in group if path})


def _load_config(root: Path) -> dict:
    try:
        value = json.loads((root / ".ai-review" / "local.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except OSError as error:
        raise ValueError(f"could not read review configuration: {error}") from error
    except ValueError as error:
        raise ValueError(f"review configuration is not valid JSON: {error}") from error
    if not isinstance(value, dict):
        raise ValueError("review configuration must be a JSON object")
    return value


def _validated_paths(root: Path, paths: Iterable[str | Path]) -> tuple[str, ...]:
    """Reject explicit paths outside the reviewed checkout."""
    root = root.resolve()
    output: list[str] = []
    for value in paths:
        candidate = Path(value)
        if candidate.is_absolute():
            try:
                relative = candidate.resolve().relative_to(root).as_posix()
            except (OSError, ValueError) as error:
                raise ValueError(f"path escapes target root: {value}") from error
        else:
            if not candidate.parts or ".." in candidate.parts:
                raise ValueError(f"path escapes target root: {value}")
            relative = candidate.as_posix()
            try:
                cwd_path = (Path.cwd() / candidate).resolve()
                relative = cwd_path.relative_to(root).as_posix()
            except (OSError, ValueError):
                try:
                    (root / candidate).resolve().relative_to(root)
                except (OSError, ValueError) as error:
                    raise ValueError(f"path escapes target root: {value}") from error
        output.append(relative)
    return tuple(output)


def _with_timeout(config: dict, timeout: float) -> dict:
    options = config.get("review_options") if isinstance(config.get("review_options"), dict) else {}
    limits = options.get("analysis_limits") if isinstance(options.get("analysis_limits"), dict) else {}
    return {
        **config,
        "review_options": {
            **options,
            "analysis_limits": {**limits, "anti_slop_timeout_seconds": timeout},
        },
    }


def _envelope(result: dict) -> dict:
    """Expose only the canonical anti-slop result shape."""
    return redact_payload({
        "schema_version": SCHEMA_VERSION,
        "tool": "anti-slop",
        "status": result.get("status", "failed"),
        "state": result.get("state", "Not verified"),
        "reason": result.get("reason", "Anti-slop analysis did not complete."),
        "files_scanned": int(result.get("files_scanned", 0) or 0),
        "candidates": result.get("candidates", []),
        "backends": result.get("backends", {}),
        "ambiguous_header_paths": result.get("ambiguous_header_paths", []),
    })


def analyse(
    target_root: Path,
    paths: Iterable[str | Path],
    *,
    timeout: float = 300,
    vendor_dir: Path = VENDOR_DIR,
) -> dict:
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")
    root = target_root.resolve()
    selected_paths = _validated_paths(root, paths)
    result = orchestrator.analyse(
        root,
        selected_paths,
        config=_with_timeout(_load_config(root), timeout),
        vendor_dir=vendor_dir,
    )
    return _envelope(result)


class RunnerArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = RunnerArgumentParser(description=__doc__)
    parser.add_argument("--entries-from", default=None, metavar="FILE|-")
    parser.add_argument("--file", action="append", default=[], dest="files", metavar="PATH")
    parser.add_argument("--target-root", required=True, type=Path)
    parser.add_argument("--format", choices=("json",), default="json")
    parser.add_argument("--timeout", type=float, default=300)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        if args.timeout <= 0:
            raise ValueError("--timeout must be greater than zero")
        if args.entries_from is not None:
            entries = deserialize_entries(sys.stdin.buffer.read()) if args.entries_from == "-" else read_diff_entries(Path(args.entries_from))
            paths = _entries_paths(entries)
        else:
            paths = args.files
        print(json.dumps(analyse(args.target_root, paths, timeout=args.timeout), indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(redact_sensitive_text(str(error)), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
