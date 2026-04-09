# Universal AI reviewer for Claude Code

Use this repo's drop-in reviewer.

## Normal review behaviour

When asked to review code:

1. Read `.ai-review/SKILL.md`.
2. Read `.ai-review/local.json` if it exists.
3. Prefer changed-file review first via `.ai-review/scripts/review_changed.sh`.
4. Use `.ai-review/scripts/review.sh` for broader review when needed.
5. Follow `.ai-review/templates/review-report.md` for the response structure.
6. State which checks ran, which failed, and which could not be verified.

## Bootstrap behaviour

If asked to bootstrap or configure the reviewer for this repo, follow `.ai-review/bootstrap/CLAUDE.md`.

## Review principles

- Do not invent APIs, commands, or constraints.
- Prefer minimal changes and exact evidence.
- Treat auth, payments, secrets, migrations, public APIs, destructive commands, and data deletion as high-risk.
- Look for common AI-generated code issues, including hallucinated APIs, subtle logic errors, edge-case failures, unsafe shell or SQL construction, weak tests, duplicate logic, bad async usage, incomplete configuration, and placeholder values left in production code.
