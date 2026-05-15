# AI Reviewer

A shared AI-assisted code review methodology packaged as machine-level skills for Claude Code and Codex. Codex gets separate `ai-review` and `ai-review-universal` skills so both review modes are directly selectable.

## Install

Run the installer from this repository:

```bash
python3 scripts/install.py
```

The installer detects supported AI agents on your machine and opens an interactive selector. Use arrow keys to move, Space to toggle an option, Enter to install, `a` to toggle all, and `q` to cancel.

Supported machine-level skill installs:

- Claude Code: `~/.claude/skills/ai-reviewer`
- Codex: `~/.codex/skills/ai-review` and `~/.codex/skills/ai-review-universal`

After installation, restart the installed AI editors so they reload skills.

### Review Modes

Use these review modes in any supported editor:

- `ai-review`: diff review against a branch, PR base, staged/unstaged changes, or any explicit diff scope
- `ai-review-universal`: whole-repo review or prompt-scoped review of existing code

Examples:

```text
Use the ai-reviewer skill to run ai-review against origin/main
Use the ai-reviewer skill to run ai-review-universal on the auth module
```

### Non-Interactive Install

For automation, pass install keys directly:

```bash
python3 scripts/install.py --install codex
python3 scripts/install.py --install claude,codex
python3 scripts/install.py --install all
```

Available keys:

- `claude`
- `codex`


## Review Methodology

The core methodology lives in `reference/methodology.md`:

1. Requirement Fidelity
2. Logic and Edge Cases
3. API and Dependency Integrity
4. Security Patterns
5. System Awareness
6. Test Quality

Reference materials include human and AI error taxonomies, empirical risk weights, a report template, and language modules for TypeScript, JavaScript, Python, SQL, Java/C#, Go, Rust, C++, and PHP.

## Scripts

Scripts are designed to run from the target repository:

```bash
bash /path/to/skill/scripts/review_changed.sh origin/main
bash /path/to/skill/scripts/review.sh
python3 /path/to/skill/scripts/scan_ai_gotchas.py
```

`review_changed.sh` reviews the diff against a base branch when provided, plus staged, unstaged, and untracked files. It runs configured lint/typecheck commands from `.ai-review/local.json`, prints detected languages, and runs the heuristic gotcha scanner only on the diff file list. `review.sh` runs broader configured commands and the scanner for universal review.

## Files

- `commands/`: Claude Code slash commands
- `SKILL.md`: installable skill entrypoint
- `agents/`: Claude Code agent definition
- `reference/`: review methodology, taxonomies, risk weights, report template, language modules
- `scripts/`: detection, review runners, gotcha scanner
- `config/`: rules and local config template
