---
name: ai-reviewer
description: Adversarial review of AI-assisted code. Use for diff review, universal repository review, and security/correctness review.
---

# AI Reviewer

Use this skill when reviewing AI-assisted code. There are two review modes: ai-review for diff review of new changes and ai-review-universal for existing-code review.

## Review Workflows

Use ai-review for diff review. Compare new changes against the branch, PR base, staged/unstaged files, or explicit diff scope named by the user. Review only new behavior, opening surrounding code only for context.

Use ai-review-universal for whole-repo review or prompt-scoped review of existing code, regardless of whether it changed recently.

For both modes:

1. Read `reference/methodology.md`.
2. Read `reference/risk-weights.md` and `reference/report-template.md`.
3. Read the target repository's `.ai-review/local.json` if present.
4. Detect languages in scope and read matching modules in `reference/lang/`.
5. Run `scripts/review_changed.sh <base>` for diff review, or `scripts/review.sh` for universal review.
6. Apply the six-layer adversarial review and report findings first, ordered by severity.

## Setup

Install this as a machine-level skill for Claude Code or Codex. Keep long-form methodology in `reference/`; this file is the native skill entrypoint.
