# Codex bootstrap

1. Run the install script to place reviewer files at the repo root:
   ```bash
   python3 .ai-review/scripts/install_config.py
   ```
   After this step, all `.ai-review/` paths refer to the repo root.
2. Read `.ai-review/bootstrap/COMMON.md` at the repo root and complete the bootstrap.
3. Update `.ai-review/local.json`.
4. Set:
   - `bootstrap.codex_done = true`
   - `bootstrap.last_bootstrapped_by = "codex"`
5. Ask the user: "Will this repo be used with both Claude and Codex, or just one of them?" If the answer is one tool only, set `bootstrap.single_tool = true` in `.ai-review/local.json`.
6. Set `bootstrap.bootstrapped_at` to an ISO-like timestamp if you can; otherwise leave it blank.
7. Run the selected safe verification commands.
8. Run:
   ```bash
   python3 .ai-review/bootstrap/cleanup.py codex
   ```
9. End with a short summary only.
