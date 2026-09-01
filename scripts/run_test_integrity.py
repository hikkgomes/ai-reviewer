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
from validate_review_context import validate as validate_context  # noqa: E402
from validate_test_evidence import validate as validate_test_evidence  # noqa: E402
from diff_file_list import DiffEntry, changed_entries  # noqa: E402


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
    parser.add_argument("--root", type=Path)
    parser.add_argument("--context", type=Path)
    parser.add_argument("--file", action="append", default=[])
    parser.add_argument("--mode", choices=("full", "diff"))
    parser.add_argument("--base", default="", help="Base revision for diff evidence")
    parser.add_argument("--head", default="", help="Head revision for commit-range evidence")
    parser.add_argument("--intent", default="", help="Explicit task intent used for new-test-file approval")
    parser.add_argument("--new-test-approval", type=Path, help="JSON file containing a path- and revision-bound test-creation approval")
    parser.add_argument("--approve-new-tests", default="", help="Approval digest for --new-test-approval")
    parser.add_argument("--format", choices=("json",), default="json")
    parser.add_argument("--approve-matrix", action="append", default=[], metavar="SCENARIO=DIGEST")
    parser.add_argument("--approve-mutation", action="append", default=[], metavar="MUTATION=DIGEST")
    args = parser.parse_args(argv)
    try:
        context_payload: dict | None = None
        if args.context is not None:
            context_payload = json.loads(args.context.read_text(encoding="utf-8"))
            if not isinstance(context_payload, dict):
                raise ValueError("context must be a JSON object")
        context_scope = context_payload.get("scope") if isinstance(context_payload, dict) and isinstance(context_payload.get("scope"), dict) else {}
        root = args.root or (
            Path(context_scope.get("root"))
            if isinstance(context_scope.get("root"), str) and context_scope.get("root")
            else Path.cwd()
        )
        root = root.resolve()
        config = {}
        config_path = root / ".ai-review" / "local.json"
        if config_path.is_file():
            loaded = json.loads(config_path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("review configuration must be a JSON object")
            config = loaded
        paths = args.file
        entries: list[DiffEntry] = []
        base_revision = args.base
        head_revision = args.head or "HEAD"
        mode = args.mode or "full"
        if context_payload is not None:
            context_errors = validate_context(context_payload)
            if context_errors:
                raise ValueError(f"context is invalid: {context_errors[0]}")
            mode = args.mode or context_payload.get("mode", "full")
            paths = paths or context_scope.get("files", [])
            base_revision = args.base or str(context_scope.get("base", "") or "")
            head_revision = args.head or str(context_scope.get("head", "HEAD") or "HEAD")
            raw_entries = context_scope.get("entries", [])
            if isinstance(raw_entries, list):
                for item in raw_entries:
                    if isinstance(item, dict):
                        entries.append(DiffEntry(**item))
        intent_text = args.intent
        trusted_intent_text = args.intent
        if not intent_text and isinstance(context_payload, dict):
            intent_value = context_payload.get("intent")
            if isinstance(intent_value, dict) and isinstance(intent_value.get("summary"), str):
                intent_text = intent_value["summary"]
            if isinstance(intent_value, dict) and isinstance(intent_value.get("approval_text"), str):
                trusted_intent_text = intent_value["approval_text"]
        approval_scope = None
        if args.new_test_approval is not None:
            approval_scope = json.loads(args.new_test_approval.read_text(encoding="utf-8"))
            if not isinstance(approval_scope, dict):
                raise ValueError("new-test approval must be a JSON object")
        if mode == "diff" and not entries:
            try:
                committed_range = (
                    f"{base_revision}...{head_revision}"
                    if base_revision and "..." not in base_revision
                    else base_revision
                )
                entries = changed_entries(root, committed_range)
            except RuntimeError:
                entries = []
        if mode == "diff" and "..." in base_revision:
            base_revision, range_head = base_revision.split("...", 1)
            if range_head:
                head_revision = range_head
        result = analyse(
            root,
            paths or None,
            entries=entries,
            config=config,
            mode=mode,
            base_revision=base_revision if mode == "diff" else "",
            head_revision=head_revision,
            prepare_dynamic_plans=True,
            approved_matrix_digests=_approval_map(args.approve_matrix) if args.approve_matrix else None,
            approved_mutation_digests=_approval_map(args.approve_mutation) if args.approve_mutation else None,
            intent_text=intent_text,
            trusted_intent_text=trusted_intent_text,
            new_test_approval=approval_scope,
            approval_digest=args.approve_new_tests or None,
        )
        try:
            payload = redact_payload(result.as_dict())
            evidence_errors = validate_test_evidence(payload)
            if evidence_errors:
                raise ValueError(f"test evidence is invalid: {evidence_errors[0]}")
            print(json.dumps(payload, indent=2, sort_keys=True))
        finally:
            result.close()
        return 0
    except (OSError, TypeError, ValueError) as error:
        print(redact_sensitive_text(str(error)), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
