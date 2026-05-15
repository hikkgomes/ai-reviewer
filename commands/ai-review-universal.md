Review the whole repository, or the repo areas named in the prompt, regardless of whether the code is new.

Use this command for baseline audits, focused subsystem reviews, security sweeps, architecture reviews, or review of a path/module that may not be part of a current diff.

Workflow:

1. Locate the installed skill directory at `.claude/skills/ai-reviewer` in the target project or `~/.claude/skills/ai-reviewer`.
2. Read `reference/methodology.md`, `reference/risk-weights.md`, and `reference/report-template.md` from that skill directory.
3. Read the target repository's `.ai-review/local.json` if present.
4. Determine scope from the prompt:
   - Whole repo if no narrower scope is requested.
   - Specific paths, modules, features, languages, or risk domains if named.
5. Detect languages in the selected scope and read matching modules under `reference/lang/`.
6. Run `scripts/review.sh` from the skill directory with the target repository as the working directory.
7. Apply all six review layers to the selected existing code, not just new changes.
8. Return the report using `reference/report-template.md`.

Prioritize correctness, security, API/schema validity, system integration, and meaningful tests over style.
