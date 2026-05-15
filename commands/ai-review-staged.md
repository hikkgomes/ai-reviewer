Review only staged and modified files for pre-commit validation.

Scope constraints:
- Include `git diff --cached` (staged changes).
- Include `git diff` (modified unstaged changes).
- Do not include untracked files.
- Do not run full branch or repository review.

Workflow:
1. Locate the installed skill directory and read `reference/methodology.md`, `reference/risk-weights.md`, and `reference/report-template.md`.
2. Read `.ai-review/local.json` in the target repository when present.
3. Collect changed files from staged and modified diffs only.
4. Detect languages in those files and load matching modules in `reference/lang/`.
5. Run `scripts/review_changed.sh` using staged/modified scope if available; otherwise run equivalent checks manually.
6. Review only changed behavior, opening surrounding code only when needed for contracts or invariants.
7. Apply all six layers and return the report using `reference/report-template.md`.

Report evidence-backed findings first. If uncertain, classify as residual risk.
