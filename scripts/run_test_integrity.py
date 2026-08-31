#!/usr/bin/env python3
"""Run bounded static test-integrity analysis and emit JSON evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dissect_checks.redaction import redact_payload, redact_sensitive_text  # noqa: E402
from dissect_checks.test_integrity.orchestrator import analyse  # noqa: E402


def _approval_map(values: list[str]) -> dict[str, str]:
    output: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("approvals must use name=digest")
        name, digest = value.split("=", 1)
        if not name or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("approvals must use a name and lowercase SHA-256 digest")
        if name in output:
            raise ValueError(f"duplicate approval name: {name}")
        output[name] = digest
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--context", type=Path)
    parser.add_argument("--file", action="append", default=[])
    parser.add_argument("--mode", choices=("full", "diff"), default="full")
    parser.add_argument("--format", choices=("json",), default="json")
    parser.add_argument("--approve-matrix", action="append", default=[], metavar="SCENARIO=DIGEST")
    parser.add_argument("--approve-mutation", action="append", default=[], metavar="MUTATION=DIGEST")
    args = parser.parse_args(argv)
    try:
        config = {}
        config_path = args.root / ".ai-review" / "local.json"
        if config_path.is_file():
            loaded = json.loads(config_path.read_text(encoding="utf-8"))
            config = loaded if isinstance(loaded, dict) else {}
        paths = args.file
        if args.context is not None:
            payload = json.loads(args.context.read_text(encoding="utf-8"))
            paths = paths or payload.get("scope", {}).get("files", [])
        result = analyse(
            args.root,
            paths or None,
            config=config,
            mode=args.mode,
            prepare_dynamic_plans=True,
            approved_matrix_digests=_approval_map(args.approve_matrix) if args.approve_matrix else None,
            approved_mutation_digests=_approval_map(args.approve_mutation) if args.approve_mutation else None,
        )
        print(json.dumps(redact_payload(result.as_dict()), indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(redact_sensitive_text(str(error)), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
