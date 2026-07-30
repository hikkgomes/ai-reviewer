# Dissect

An evidence-first AI-assisted code review methodology packaged as machine-level
skills for Claude Code, Codex, and Cursor. Dissect combines semantic/correctness
review, application-security review, production-readiness review, and optional
deterministic checks. Codex keeps separate `dissect-diff` and `dissect-full`
skills so both review modes remain directly selectable.

## Install

Run the installer from this repository:

```bash
python3 scripts/install.py
```

The installer detects supported AI agents on your machine and opens an interactive selector. Use arrow keys to move, Space to toggle an option, Enter to install, `a` to toggle all, and `q` to cancel.

Supported machine-level skill installs:

- Claude Code: `~/.claude/skills/dissect`
- Codex: `~/.agents/skills/dissect-diff` and `~/.agents/skills/dissect-full`

After installation, restart the installed AI editors so they reload skills.

### Review Modes

Use these review modes in any supported editor:

- `dissect-diff`: diff review against a branch, PR base, staged/unstaged changes, or any explicit diff scope
- `dissect-full`: whole-repo review or prompt-scoped review of existing code

Examples:

```text
Use the dissect skill to run dissect-diff against origin/main
Use the dissect skill to run dissect-full on the auth module
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

The six layers remain the primary reasoning model. Stable coverage families in
`reference/check-families.md` make secrets, authentication, authorisation/tenant
isolation, database/RLS, sensitive routes, browser/transport, payments,
sensitive data, deployment exposure, dependencies, observability, recovery,
destructive actions, regression protection, governance, and brand abuse
explicit.

Every applicable family ends in one evidence state:

- **Finding:** concrete evidence demonstrates a problem.
- **Checked:** sufficient evidence was inspected and no problem was found.
- **Not applicable:** the technology or control is absent.
- **Not verified:** runtime access, configuration, credentials, or operational
  proof is missing.

Not verified is not safe, and missing evidence alone is not a vulnerability. A
clean static review is not proof that a production system is secure or
compliant.

## Automated and Human Coverage

The deterministic scanner handles high-signal syntactic evidence such as
credential shapes, privileged browser environment names, unconditional RLS
policies, credentialed wildcard CORS, unsafe dependency sources, and broad
destructive commands. It emits stable check IDs, evidence locations,
confidence, explanation, and remediation. Secret evidence is centrally redacted
to a safe prefix and fingerprint before text or JSON output is produced.

The modular scanner also preserves the complete pre-existing heuristic baseline.
`tests/test_rules.py` contains an explicit expected-ID set so deleting a legacy
detector cannot silently reduce coverage.

Dissect supports Python 3.11 through 3.14. CI runs the complete offline suite on
the minimum, an intermediate release, and the newest supported release.

Authentication correctness, effective route protection, ownership and tenant
isolation, payment semantics, governance, backup restoration, and production
reachability require human, runtime, or operational evidence. Scanner candidates
for these areas must be confirmed against surrounding configuration and code.

Static/local review is the default. Dissect does not probe public applications,
bypass authentication, create production accounts, retrieve private data,
trigger payments, or perform destructive/recovery operations. Runtime checks
require explicit authorisation, an approved URL, credentials, and an entry in
`security_review.allowed_runtime_checks`.

## Configuration

Copy `config/local.json.template` to `.ai-review/local.json`. Existing
configuration remains valid except legacy `security_review.tool_commands`
shell-command strings, which are deliberately rejected; migrate those entries
to the argument-array form below. Optional fields describe public and critical
routes, auth/sensitive/payment/infra paths, tenant identifiers, generated
bundles, screenshot-critical pages, operational evidence, payment providers,
known origins, approved production URLs, allowed runtime checks, and explicit
tool commands.

Generated bundles and recent Git history are disabled by default:

```json
{
  "security_review": {
    "scan_generated_bundles": true,
    "scan_git_history": true,
    "git_history_depth": 20,
    "python_import_aliases": {
      "company_api": "company-sdk"
    },
    "tool_commands": {
      "gitleaks": {
        "argv": ["gitleaks", "detect", "--no-banner", "--redact"],
        "finding_exit_codes": [1]
      }
    }
  }
}
```

Installed tools are detected but never execute from repository configuration
alone. Tool entries must use argument arrays (shell command strings are
rejected). First generate and inspect the redacted canonical plan:

```bash
python3 scripts/tool_integrations.py --format json
```

The plan includes the configuration name, fully resolved symlink target,
executable SHA-256, complete argv, working directory, and finding exit codes.
Its approval digest is calculated over the unredacted canonical plan. A trusted
local caller can execute that one plan:

```bash
python3 scripts/tool_integrations.py --approve-plan <approval-digest>
```

The configuration is reloaded and the path, bytes, argv, directory, and exit
semantics are revalidated immediately before execution. A tool-like filename or
PATH entry conveys no trust. Changing any execution-affecting field invalidates
approval. `AI_REVIEW_APPROVED_PLANS` is available to trusted local automation;
it contains comma-separated exact plan digests and must not be sourced from the
reviewed repository.

External stdout and stderr are centrally redacted before they enter text or JSON
results. Reports include whether each tool was detected, its argument array,
exit code, relevant redacted output, and separate fields for execution
completion, pass/fail, finding-producing exits, and coverage completeness.

The main review scripts use the same two-phase model for exact install, lint,
typecheck, test, build, and format shell plans. Run `review_commands.py --scope
full --format json`, inspect each plan, then pass its digest with
`--approve-plan` or `AI_REVIEW_APPROVED_PLANS`. Approval of a category name or
an earlier command string is never sufficient.

`python_import_aliases` maps import name to declared distribution name. Dissect
also uses installed package metadata and a tested built-in map for common names
such as `PIL`/`Pillow`, `yaml`/`PyYAML`, `bs4`/`beautifulsoup4`,
`sklearn`/`scikit-learn`, and `cv2`/`opencv-python`; it never queries a network.
Requirement and constraint graphs are resolved separately and recursively
within the repository, with cycles deduplicated and missing includes reported as
coverage errors. A constraint can pin a declared requirement but never counts as
an install declaration by itself.

Git history is parsed with NUL-delimited status records. Rename ancestry follows
the old path backward while findings retain the reviewed path. Copies follow
the detected source ancestry only when the copied destination is in scope.
Merge commits inspect every parent. Rename aliases share a canonical logical
lineage, while copy ancestry stays separate. Occurrences carry match,
surrounding-code, and stable occurrence fingerprints. History is attached only
when correlation is unique; ambiguous evidence remains a separate history-only
finding. Working-tree evidence remains primary, and historical paths, commits,
lines, provenance types, and fingerprints are attached in
`historical_sources`.

Self-review fixture handling is never automatic. An installed skill first emits
a trusted plan bound to its versioned full fixture-owner manifest, the target
checkout identity, and every fixture-owning file:

```bash
python3 /trusted/skill/scripts/scan_ai_gotchas.py --plan-self-review
python3 /trusted/skill/scripts/scan_ai_gotchas.py \
  --approve-self-review <approval-digest> --format json
```

Only exact manifest-owned AST nodes are masked. Copied public anchors, copied
fixture files, repository configuration, comments, and target-controlled
environment cannot enable the mode. Changes outside an owned node do not
broaden masking; changes inside one make that node ineligible. Approval is also
bound to the canonical checkout and its Git marker.

Diff scope uses one canonical NUL-delimited file list from Git through display,
language detection, and scanning. Human output JSON-quotes paths so tabs and
newlines cannot impersonate additional files.

## CI and JSON Output

The default exit status remains non-failing. Opt into CI enforcement with a
threshold:

```bash
python3 scripts/scan_ai_gotchas.py --format json --fail-on high > dissect.json
```

Or configure `review_options.deterministic_output` and
`review_options.fail_on_severity`. Exit code `2` means at least one finding met
the threshold. JSON schema `3.0` adds occurrence fingerprints and richer
structured `historical_sources`, making current-versus-historical evidence
explicit. The contract is versioned with `schema_version`. Its `complete` flag
becomes false and `coverage_errors` explains the gap when files, commits, or
dependency manifests could not be inspected.

Run the offline regression suite with:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/sync_adapters.py --check
```

## Extending Dissect

Add a new family once in `reference/check-families.md` and map it in
`config/rules.yaml`. Add deterministic rules only for reliable syntactic
evidence, with a stable ID, severity, confidence, explanation, remediation, and
positive/negative fixtures. Then regenerate adapters:

```bash
python3 scripts/sync_adapters.py
```

CI verifies that embedded adapters match the canonical methodology and family
catalog, preventing silent Claude/Codex/Cursor drift.

## Scripts

Scripts are designed to run from the target repository:

```bash
bash /path/to/skill/scripts/review_changed.sh origin/main
bash /path/to/skill/scripts/review.sh
python3 /path/to/skill/scripts/scan_ai_gotchas.py
```

`review_changed.sh` reviews the diff against a base branch when provided, plus
staged, unstaged, and untracked files. Language detection and deterministic
scanning both consume the same generated file list, so clean committed branch
changes, deletions, and renames remain in scope. It runs configured
lint/typecheck commands from `.ai-review/local.json`. `review.sh` runs broader
configured commands and the scanner for universal review.

## Files

- `commands/`: Claude Code slash commands
- `SKILL.md`: installable skill entrypoint
- `agents/`: Claude Code agent definition
- `reference/`: review methodology, taxonomies, risk weights, report template, language modules
- `scripts/`: detection, review runners, gotcha scanner
- `config/`: rules and local config template
