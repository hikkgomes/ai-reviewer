# Bootstrap common steps

Goal: configure the universal reviewer for this repository without replacing user config files and without asking for long follow-up prompts.

## What to do

1. Inspect the repo layout and identify whether this is a single repo, a multi-package monorepo, or a workspace with multiple subprojects.
2. Verify and refine the auto-detected commands, stack, package managers, and workspace roots in `.ai-review/local.json` against the actual repo files.
3. Run `.ai-review/scripts/detect_commands.py` only if you need to compare against fresh detection output.
4. Verify and refine the auto-detected architecture details in `.ai-review/local.json`.
5. Run `.ai-review/scripts/detect_architecture.py` only if you need to compare against fresh architecture output, then address anything listed in `architecture.ai_refinement_needed`.
6. If only one AI tool, not both Claude and Codex, will be used for this repo, set `bootstrap.single_tool = true` in `.ai-review/local.json` before the cleanup step.
7. Update `.ai-review/local.json` with any missing or corrected:
   - project stack
   - package managers
   - `review_options.run_install_on_review`
   - root-level commands
   - root-level generated, ignored, and critical paths
   - risk-sensitive areas
   - architecture details
   - workspace entries when present
   - notes and uncertainty
8. Run the selected safe verification commands.
9. If a configured command fails because it is wrong, correct `.ai-review/local.json`.
10. Keep changes minimal and repo-local.
11. Do not rewrite permanent reviewer logic unless necessary.
12. Do not delete permanent reviewer files.
13. After finishing, run the cleanup script for the current tool.

## Safe command policy

Allowed:
- read-only inspection
- lint
- typecheck
- test
- build
- format-check
- validate
- dependency install only when required to verify the repo safely and only if it stays local

Not allowed:
- deploy
- publish
- migration apply against real environments
- destructive database operations
- secret rotation
- remote environment changes

## Required output at the end

Report briefly:
- detected stack and workspace layout
- commands written to `.ai-review/local.json`
- config files merged during install
- commands verified
- commands that failed
- remaining uncertainty
