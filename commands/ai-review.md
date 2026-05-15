Review only new changes against a base branch, PR base, or explicitly requested diff scope.

This is the default command for change review. It must not review the whole repository except as needed to understand the changed code.

Workflow:

1. Locate the installed skill directory at `.claude/skills/ai-reviewer` in the target project or `~/.claude/skills/ai-reviewer`.
2. Read `reference/methodology.md`, `reference/risk-weights.md`, and `reference/report-template.md` from that skill directory.
3. Read the target repository's `.ai-review/local.json` if present.
4. Determine the diff scope from the prompt:
   - If the user names a branch, compare against that branch.
   - If reviewing a PR, compare against the PR base branch.
   - If no base is named, infer the upstream/base branch from git.
   - Include staged, unstaged, and untracked files in addition to committed branch diff changes.
5. Detect languages in the changed files and read matching modules under `reference/lang/`.
6. Run `scripts/review_changed.sh <base-branch>` from the skill directory when a base branch is known; otherwise run it without an argument.
7. Review only the changed/new behavior. Open surrounding code only to understand contracts, callers, and invariants.
8. Apply all six review layers to the diff:
   - Requirement Fidelity
   - Logic and Edge Cases
   - API and Dependency Integrity
   - Security Patterns
   - System Awareness
   - Test Quality
9. Return the report using `reference/report-template.md`.

Report only evidence-backed findings. If a risk is plausible but unverified, label it as residual risk or an open question.
