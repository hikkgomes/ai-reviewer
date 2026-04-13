# AI Reviewer Template

A repo-local review setup for AI-assisted coding. It gives Claude Code and Codex a shared review workflow, local project context, fast changed-file checks, and a consistent report format.

The template is meant to be copied into a repository, bootstrapped once, and committed with that repository so every contributor gets the same reviewer behavior.

## Install

1. Drop this folder into the repo root.
2. Run one or both bootstrap prompts from `FIRST_RUN.txt`.
3. Let the selected tool run `.ai-review/scripts/install_config.py`.
4. Review and refine `.ai-review/local.json`.
5. Run the cleanup step from the bootstrap instructions.

Bootstrap merges reviewer instructions into `CLAUDE.md` and `AGENTS.md` using sentinel markers, adds Claude commands and agent files, adds VS Code tasks, and fills `.ai-review/local.json` with auto-detected commands, stack, workspace, and architecture context where possible.

If the repository will use only Claude or only Codex, set `bootstrap.single_tool = true` in `.ai-review/local.json` before running cleanup.

## What Stays

After bootstrap, the permanent reviewer files are:

- `.ai-review/SKILL.md`
- `.ai-review/local.json`
- `.ai-review/rules.yaml`
- `.ai-review/templates/review-report.md`
- `.ai-review/scripts/review.sh`
- `.ai-review/scripts/review_changed.sh`
- `.ai-review/scripts/detect_commands.py`
- `.ai-review/scripts/detect_architecture.py`
- `.ai-review/scripts/scan_ai_gotchas.py`
- `.claude/commands/ai-review.md`
- `.claude/commands/ai-review-staged.md`
- `.claude/agents/universal-code-reviewer.md`
- `.claude/settings.json`
- `.vscode/tasks.json`
- reviewer sections inside `CLAUDE.md` and `AGENTS.md`

Bootstrap-only files are removed after cleanup.

## Use

In Claude Code:

- `/ai-review` reviews the current repository changes.
- `/ai-review-staged` focuses on staged, modified, and untracked files.
- The `universal-code-reviewer` agent can be used for focused reviews of AI-written code.

In Codex, ask for an AI review and the reviewer instructions in `AGENTS.md` will direct the workflow.

From a shell:

```bash
bash .ai-review/scripts/review_changed.sh
```

or:

```bash
bash .ai-review/scripts/review.sh
```

`review_changed.sh` runs configured lint and typecheck commands from `.ai-review/local.json`, then runs heuristic gotcha scanning. `review.sh` can run the broader configured command set.

## Update

Re-run the bootstrap prompts after updating this template. The installer replaces only sentinel-managed reviewer sections in `CLAUDE.md` and `AGENTS.md`, keeps existing user config keys, and appends missing VS Code tasks by label.

After updating, review `.ai-review/local.json` again. Auto-detection fills empty fields but does not overwrite non-empty commands, paths, architecture notes, or user-maintained ignore lists.

## Multi-Root Workspaces

Workspace detection finds packages inside the same repository root, such as `apps/*`, `packages/*`, or language-specific workspace members.

For a VS Code multi-root workspace where the backend and frontend are separate git repositories, install and bootstrap this template in each repository separately. The scripts do not cross repository boundaries.

## Remove

To remove the reviewer:

1. Delete `.ai-review/`.
2. Delete `.claude/commands/ai-review.md`.
3. Delete `.claude/commands/ai-review-staged.md`.
4. Delete `.claude/agents/universal-code-reviewer.md`.
5. Remove the sentinel-managed reviewer blocks from `CLAUDE.md` and `AGENTS.md`.
6. Remove reviewer tasks from `.vscode/tasks.json` if they are no longer wanted.

Keep `.ai-review/` and related config committed if the reviewer should remain available to the team.
