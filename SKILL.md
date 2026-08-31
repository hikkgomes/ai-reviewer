---
name: dissect
description: Adversarial review of AI-assisted code. Use for diff review, universal repository review, and security/correctness review.
---

# Dissect

Use this skill when reviewing AI-assisted code. There are two review modes: dissect-diff for diff review of new changes and dissect-full for existing-code review.

## Review Workflows

Use dissect-diff for diff review. Compare new changes against the branch, PR base, staged/unstaged files, or explicit diff scope named by the user. Review only new behavior, opening surrounding code only for context.

Use dissect-full for whole-repo review or prompt-scoped review of existing code, regardless of whether it changed recently.

All package-relative paths in this skill (including `reference/` and `scripts/`)
resolve from the directory containing this `SKILL.md`, not from the repository
under review. Use the target checkout only for files explicitly described as
review scope or repository-local evidence.

For both modes, use `reference/review-workflow.md` as the canonical semantic
workflow. Load `reference/methodology.md`, `reference/check-families.md`,
`reference/report-template.md`, and only the language/framework packs relevant
to the evidence. Run the matching review script to build context outside the
target checkout. Deterministic and optional-tool output enters the candidate
ledger and must be falsified and verified before it can become a finding.

The operational order is: establish intent; build behavioural units; identify
contracts and invariants; expand scope deliberately; generate candidates;
falsify every candidate; verify survivors; report only verified findings. Use
the concise diff report for pull requests and the fuller coverage ledger only
for full reviews.

## Deterministic tooling

Optional anti-slop analysis uses skill-local Oxlint for JavaScript and
TypeScript, Python's standard-library AST, and pinned ast-grep packs for Go,
Rust, C, C++, Java, and C#. Comment-slop uses the canonical language registry.
Both are structural candidate generators only. No match is a finding without
falsification and semantic verification.

Test-integrity analysis inventories tests, fixtures, helpers, configuration, CI
commands, production subjects, and their evidence-backed relations. It detects
only high-signal weakening or bypass patterns. Static matches remain
candidates. The base/head matrix, targeted changed-code mutation, and proof-test
workflow require exact approval before repository tests execute. Complexity
uses repository thresholds first and skill-local Lizard 1.24.0 second. It is a
review signal, not an LLM-authorship check or an automatic defect.

No applicable backend is `Not applicable`. Disabled, missing, malformed,
ambiguous, timed-out, or budget-limited applicable work is `Not verified`.
Generated files are excluded only by explicit `paths.generated` patterns.
Unknown `.h` language is reported as `ambiguous_header_language` for the
affected C/C++ backend. See `reference/anti-slop-rule-contract.md` and
`reference/review-context-schema.json` for rule and coverage contracts.

## Setup

Install this as a machine-level skill for Claude Code or Codex. Keep long-form methodology in `reference/`; this file is the native skill entrypoint.
