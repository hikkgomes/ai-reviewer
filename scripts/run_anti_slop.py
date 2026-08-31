#!/usr/bin/env python3
"""Thin CLI and compatibility entry point for anti-slop backends."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys
from typing import Any, Iterable

if sys.version_info < (3, 11):
    raise SystemExit("Dissect requires Python 3.11 or newer.")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from diff_file_list import DiffEntry, deserialize_entries, read_diff_entries  # noqa: E402
from dissect_checks.anti_slop import orchestrator  # noqa: E402
from dissect_checks.anti_slop.oxlint_backend import (  # noqa: E402
    AnalysisSkip,
    PathEscapeError,
    RunnerError,
    _node_version as _backend_node_version,
    _oxlint_path as _backend_oxlint_path,
    detect_effect,
    filter_files,
    parse_diagnostics,
    run_oxlint,
    to_candidates,
)
from dissect_checks.redaction import redact_payload, redact_sensitive_text  # noqa: E402
from file_paths import is_generated_path, is_ignored_path  # noqa: E402
from language_registry import language_for_path, paths_for_anti_slop  # noqa: E402


VENDOR_DIR = ROOT / "scripts" / "vendor" / "anti-slop"
MIN_NODE = (22, 18)
MAX_FILES_PER_INVOCATION = 250


def _node_version(node: str) -> tuple[int, int, int] | None:
    return _backend_node_version(node)


def _oxlint_path(vendor_dir: Path) -> Path:
    return _backend_oxlint_path(vendor_dir)


def preflight(vendor_dir: Path) -> str | None:
    """Compatibility preflight kept patchable for existing integrations."""
    node = shutil.which("node")
    if node is None:
        return "node_unavailable"
    version = _node_version(node)
    if version is None or version[:2] < MIN_NODE:
        return "node_version_unsupported"
    if not _oxlint_path(vendor_dir).is_file():
        return "deps_missing"
    return None


def _analysis_paths(
    target_root: Path,
    paths: Iterable[str | Path],
    config: dict[str, Any],
) -> list[str]:
    """Validate and select every supported structural target for the CLI."""
    root = target_root.resolve()
    selected: dict[str, str] = {}
    for value in paths:
        candidate = Path(value)
        if candidate.is_absolute():
            try:
                relative = candidate.resolve().relative_to(root).as_posix()
            except ValueError as error:
                raise PathEscapeError(f"path escapes target root: {value}") from error
        else:
            if not candidate.parts or ".." in candidate.parts:
                raise PathEscapeError(f"path escapes target root: {value}")
            relative = candidate.as_posix()
        physical = (root / relative).resolve()
        if not physical.is_relative_to(root):
            raise PathEscapeError(f"path escapes target root: {value}")
        spec = language_for_path(relative)
        if (
            spec is None
            or (spec.anti_slop_backend is None and candidate.suffix.lower() != ".h")
            or is_ignored_path(root, relative)
            or is_generated_path(root, physical, config)
            or not physical.is_file()
        ):
            continue
        selected[relative] = relative
    grouped = paths_for_anti_slop(selected)
    supported = {path for values in grouped.values() for path in values}
    return [path for path in sorted(selected) if path in supported]


def _envelope(
    *,
    status: str,
    skip_reason: str | None,
    config_variant: str,
    files_scanned: int,
    candidates: list[dict[str, Any]],
    detail: str = "",
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "tool": "anti-slop",
        "status": status,
        "state": "Checked" if status == "ok" else "Not applicable" if skip_reason in {"no_js_ts_files", "no_supported_files"} else "Not verified",
        "skip_reason": skip_reason,
        "config_variant": config_variant,
        "files_scanned": files_scanned,
        "candidates": candidates,
    }
    if detail:
        payload["detail"] = detail[:500]
    return redact_payload(payload)


def analyse(
    target_root: Path,
    paths: Iterable[str | Path],
    *,
    timeout: float = 300,
    vendor_dir: Path = VENDOR_DIR,
) -> dict[str, Any]:
    """Run the new orchestrator while retaining the documented CLI envelope."""
    target_root = target_root.resolve()
    config: dict[str, Any] = {}
    try:
        value = json.loads((target_root / ".ai-review" / "local.json").read_text(encoding="utf-8"))
        if isinstance(value, dict):
            config = value
    except (OSError, ValueError):
        config = {}
    requested_paths = list(paths)
    files = _analysis_paths(target_root, requested_paths, config)
    config_variant = "effect" if detect_effect(target_root) else "generic"
    if not files:
        return _envelope(
            status="skipped",
            skip_reason="no_js_ts_files" if not requested_paths else "no_supported_files",
            config_variant=config_variant,
            files_scanned=0, candidates=[],
        )
    # Preserve the documented legacy preflight envelope for a JS/TS-only CLI
    # invocation. Mixed and polyglot scopes go through the common orchestrator
    # so one unavailable backend cannot hide successful structural backends.
    only_js_ts = all(
        (language_for_path(path) is not None)
        and language_for_path(path).language_id in {"javascript", "typescript"}
        for path in files
    )
    reason = preflight(vendor_dir) if only_js_ts else None
    if reason is not None:
        return _envelope(
            status="skipped", skip_reason=reason, config_variant=config_variant,
            files_scanned=0, candidates=[],
        )
    options = config.get("review_options") if isinstance(config.get("review_options"), dict) else {}
    configured_limits = options.get("analysis_limits") if isinstance(options.get("analysis_limits"), dict) else {}
    config = {
        **config,
        "review_options": {
            **options,
            "analysis_limits": {
                **configured_limits,
                "anti_slop_timeout_seconds": timeout,
            },
        },
    }
    result = orchestrator.analyse(
        target_root,
        [path for path in files],
        vendor_dir=vendor_dir,
        config=config,
    )
    payload = dict(result)
    payload["legacy_status"] = "ok" if result.get("state") == "Checked" else "skipped"
    payload["skip_reason"] = None if result.get("state") == "Checked" else result.get("backends", {}).get("oxlint-js-ts", {}).get("reason_code") or "analysis_incomplete"
    # Keep the old status only at this compatibility boundary. Context uses
    # ``state`` and backend records from the new envelope.
    payload["status"] = "ok" if result.get("state") == "Checked" else "skipped"
    payload["config_variant"] = config_variant
    return redact_payload(payload)


def _entries_paths(entries: Iterable[DiffEntry]) -> list[str]:
    values = [entry.reviewed_path for entry in entries if entry.exists_in_worktree and entry.reviewed_path]
    return sorted({path for group in paths_for_anti_slop(values).values() for path in group if path})


class RunnerArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise RunnerError(message)


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
            raise RunnerError("--timeout must be greater than zero")
        if args.entries_from is not None:
            entries = deserialize_entries(sys.stdin.buffer.read()) if args.entries_from == "-" else read_diff_entries(Path(args.entries_from))
            paths = _entries_paths(entries)
        else:
            paths = args.files
        payload = analyse(args.target_root, paths, timeout=args.timeout)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    except PathEscapeError as error:
        print(redact_sensitive_text(str(error)), file=sys.stderr)
        return 1
    except (RunnerError, OSError, ValueError) as error:
        print(redact_sensitive_text(str(error)), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
