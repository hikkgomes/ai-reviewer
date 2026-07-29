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
rejected), and a trusted local caller must approve execution explicitly:

```bash
python3 scripts/tool_integrations.py --allow-tool gitleaks
```

External stdout and stderr are centrally redacted before they enter text or JSON
results. Reports include whether each tool was detected, its argument array,
exit code, relevant redacted output, and separate fields for execution
completion, pass/fail, finding-producing exits, and coverage completeness.

The main review scripts likewise do not run commands discovered from the
repository unless a trusted local caller names command categories in
`AI_REVIEW_ALLOWED_COMMANDS`, for example `lint,typecheck`. Unapproved commands
are displayed but remain inert. This allow-list cannot be enabled by repository
configuration.

`python_import_aliases` maps import name to declared distribution name. Dissect
also uses installed package metadata and a tested built-in map for common names
such as `PIL`/`Pillow`, `yaml`/`PyYAML`, `bs4`/`beautifulsoup4`,
`sklearn`/`scikit-learn`, and `cv2`/`opencv-python`; it never queries a network.
Requirements includes and constraints are resolved recursively within the
repository, with cycles deduplicated and missing includes reported as coverage
errors.

Git history is parsed with NUL-delimited status records. Rename ancestry follows
the old path backward while findings retain the reviewed path. Copies follow
the detected source ancestry only when the copied destination is in scope.
Merge commits inspect every parent for the scoped lineage, and duplicate blobs
reached through aliases or parents are deduplicated.

## CI and JSON Output

The default exit status remains non-failing. Opt into CI enforcement with a
threshold:

```bash
python3 scripts/scan_ai_gotchas.py --format json --fail-on high > dissect.json
```

Or configure `review_options.deterministic_output` and
`review_options.fail_on_severity`. Exit code `2` means at least one finding met
the threshold. The JSON contract is versioned with `schema_version`. Its
`complete` flag becomes false and `coverage_errors` explains the gap when files,
commits, or dependency manifests could not be inspected.

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

`review_changed.sh` reviews the diff against a base branch when provided, plus staged, unstaged, and untracked files. It runs configured lint/typecheck commands from `.ai-review/local.json`, prints detected languages, and runs deterministic checks only on the diff file list. `review.sh` runs broader configured commands and the scanner for universal review.

## Files

- `commands/`: Claude Code slash commands
- `SKILL.md`: installable skill entrypoint
- `agents/`: Claude Code agent definition
- `reference/`: review methodology, taxonomies, risk weights, report template, language modules
- `scripts/`: detection, review runners, gotcha scanner
- `config/`: rules and local config template
