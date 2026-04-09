# Universal AI reviewer for Codex

This repository contains a universal drop-in reviewer.

## Trigger keywords

Use the reviewer workflow when the user asks for:

- review
- review code
- ai review
- review staged
- full review
- scan for issues

## Normal review behaviour

When the user asks for a code review:

1. Read `.ai-review/SKILL.md`.
2. Read `.ai-review/local.json` if it exists.
3. Prefer reviewing changed files first.
4. Run `.ai-review/scripts/review_changed.sh` first when the request is about current changes.
5. If there are no relevant changes or the user asks for a broader review, run `.ai-review/scripts/review.sh`.
6. Use `.ai-review/templates/review-report.md` as the output structure.
7. Report:
   - findings by severity
   - what commands were run
   - what could not be verified
   - uncertainty explicitly

## Workflow: Changed-file review

1. Read `.ai-review/SKILL.md`.
2. Read `.ai-review/local.json` if it exists.
3. Run `.ai-review/scripts/review_changed.sh`.
4. Review changed files first and expand scope only if needed.
5. Return the report using `.ai-review/templates/review-report.md`.

## Workflow: Full review

1. Read `.ai-review/SKILL.md`.
2. Read `.ai-review/local.json`.
3. Run `.ai-review/scripts/review.sh`.
4. Review the command output and heuristic scan results together.
5. Return the report using `.ai-review/templates/review-report.md`.

## Workflow: Bootstrap

1. Follow `.ai-review/bootstrap/CODEX.md`.
2. Read `.ai-review/bootstrap/COMMON.md`.
3. Run detection, architecture, install, and verification steps.
4. Update `.ai-review/local.json` with repo-specific details.
5. Finish with the cleanup step from the bootstrap instructions.

## Bootstrap behaviour

If the user explicitly asks to set up or bootstrap this reviewer for the repository:

1. Follow `.ai-review/bootstrap/CODEX.md`.
2. Do not replace permanent reviewer files.
3. Only create or update `.ai-review/local.json` and other repo-local settings needed for review execution.

## Review principles

- Do not invent APIs, flags, packages, or file paths.
- Prefer minimal, evidence-based claims.
- Treat security, data loss, auth, payments, migrations, secrets, destructive shell commands, and public interfaces as high-risk.
- Check for common AI code failures: hallucinated APIs, broken syntax or imports, subtle logic bugs, bad edge-case handling, weak tests, duplicate logic, bad async usage, injection risks, poor error handling, performance cliffs, hidden placeholder values, and incomplete integration work.
- Be explicit when a command was not available or a result could not be verified.
