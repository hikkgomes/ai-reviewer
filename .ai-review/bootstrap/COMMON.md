# Bootstrap common steps

Goal: configure the universal reviewer for this repository without replacing user config files and without asking for long follow-up prompts.

## What to do

1. Inspect the repo layout and identify whether this is a single repo, a multi-package monorepo, or a workspace with multiple subprojects.
2. Run `.ai-review/scripts/detect_commands.py`.
3. Verify the detected commands, stack, package managers, and workspace roots against the actual repo files.
4. Run `.ai-review/scripts/detect_architecture.py`.
5. Review the architecture output, refine what the script got right, and fill in anything listed in `architecture.ai_refinement_needed`.
6. Update `.ai-review/local.json` with:
   - project stack
   - package managers
   - `review_options.run_install_on_review`
   - root-level commands
   - root-level generated, ignored, and critical paths
   - risk-sensitive areas
   - architecture details
   - workspace entries when present
   - notes and uncertainty
7. Run the selected safe verification commands.
8. If a configured command fails because it is wrong, correct `.ai-review/local.json`.
9. Keep changes minimal and repo-local.
10. Do not rewrite permanent reviewer logic unless necessary.
11. Do not delete permanent reviewer files.
12. After finishing, run the cleanup script for the current tool.

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
