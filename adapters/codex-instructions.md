<!-- AI-REVIEWER-START -->
# AI Reviewer Methodology (Codex Adapter)

Use this block in `AGENTS.md` when the editor cannot reference external skill files directly.

## Purpose

Review AI-assisted code with an adversarial, evidence-first process that prioritizes correctness and security over stylistic polish.

## Working Rules

- Review user intent before implementation details.
- Review changed code first; open surrounding code only for contracts/invariants.
- Treat green tests as insufficient proof.
- Separate verified findings from residual risk.

## Severity Model

- Critical: exploitable security, auth bypass, data loss/corruption, destructive behavior without safeguards.
- High: runtime breakage, incorrect business logic, API contract breaks, unrecoverable failure path.
- Medium: meaningful edge-case fragility, missing important tests, maintainability risk with impact.
- Low: style, naming, minor consistency.

## AI Risk Multipliers

Apply these multipliers to attention, not severity:

- Security: 2.74x.
- Error handling: 2.0x.
- Logic correctness: 1.75x.
- Readability/consistency issues: ~3x frequency (usually lower severity).
- Performance I/O issues: ~8x frequency.
- Concurrency/lifecycle issues: ~2x.

## Pre-Review Mental Model

1. Read the request, PR description, or issue first.
2. Restate intended behavior in your own words.
3. Identify changed layers: UI/API/service/persistence/infrastructure/tests/scripts.
4. List invariants: auth boundaries, data ownership, idempotency, migration safety, error contracts.
5. Detect language(s) in changed files.
6. Run available checks, but do not replace manual review with check output.

## Six-Layer Review Method

### Layer 1: Requirement Fidelity

Goal: verify exact requirement fit, not plausible proxy behavior.

Check:
- Prompt mirroring without domain semantics.
- Partial implementation of multi-constraint requests.
- Business-rule drift (limits, defaults, state transitions, ownership checks).
- Missing reject/deny behavior.

Empirical anchor:
- About 51% of missed review bugs are semantic mismatches (SmartSHARK).

### Layer 2: Logic and Edge Cases

Goal: detect silent semantic failures.

Check:
- Empty/null/NaN/invalid enum/duplicate/stale state handling.
- Off-by-one and boundary errors.
- Wrong predicate order, accidental mutation, stale values.
- Retry/cancel/timeout/idempotency behavior.
- Exception paths and cleanup guarantees.

Empirical anchors:
- Roughly 60% of AI faults can compile/run while being logically wrong.
- Exception handling is a dominant miss class in semantic defects.

### Layer 3: API and Dependency Integrity

Goal: verify every interface is real and compatible.

Check:
- Hallucinated imports/packages/methods/flags/env vars.
- Version-signature drift and changed defaults.
- Schema/ORM/REST/GraphQL/queue/event contract correctness.
- Reinvented local utilities that duplicate existing abstractions.

### Layer 4: Security Patterns

Goal: find high-impact vulnerabilities even in non-security-looking diffs.

Check:
- Auth/authz/object-level authorization/tenant isolation.
- Injection vectors (SQL/shell/template/path/SSRF/redirects).
- Secrets in code/tests/logging/telemetry.
- Unsafe crypto/deserialization/TLS/CORS/CSP/security headers.
- Destructive operations without confirmation, audit, rollback.

Empirical anchor:
- Security vulnerability incidence is significantly higher in AI code (+274% in referenced data).

### Layer 5: System Awareness

Goal: ensure the change fits the existing system end-to-end.

Check:
- Cross-layer wiring completeness (schema -> API -> client -> tests/docs).
- Cache/queue/flag/config/observability/background-job integration.
- Repository patterns and layering contracts.
- New fields/enums/routes/events wired across all dependent layers.

AI-specific smell:
- New local abstractions replacing existing canonical ones.

### Layer 6: Test Quality

Goal: validate behavior, not implementation mimicry.

Check:
- Tests assert external behavior and contracts.
- Error path and rollback coverage is present.
- Tests fail for the claimed bug.
- Fixtures are realistic and schema-correct.
- Mocks do not delete the behavior under review.

Empirical anchor:
- Because error-handling defects are elevated, error-path tests deserve 2.0x attention.

## Human-Miss Buckets to Keep in Mind

Focus time where human reviewers frequently miss defects:

- Semantic/intent mismatches.
- Exception and cleanup path defects.
- Interface/version/schema incompatibilities.
- Missing validation/null checks.
- Concurrency/ordering/configuration failures.

## Language-Specific Quick Checks

### Python

- Broad `except Exception` swallowing root causes.
- Mutable default arguments.
- Async misuse (`create_task` without lifecycle management).
- Type assumptions hidden by duck typing.

### JavaScript / TypeScript

- `any` leaks and unsafe narrowing.
- Promise flows that ignore rejection/cancellation.
- Runtime schema mismatch hidden by static typings.
- Mutation of shared objects across async boundaries.

### Java / C#

- Nullability contract drift.
- `throw ex` stack-trace reset (C#).
- Transaction boundary mismatch.
- Blocking calls inside async/reactive flows.

### Go

- Ignored errors (`_`).
- Missing context cancellation propagation.
- Goroutine leaks and channel lifecycle bugs.
- Retry loops without backoff/limits.

### Rust

- Forced interior mutability (`Rc<RefCell<_>>`) masking design flaws.
- Lifetime workarounds that bypass ownership clarity.
- Unsafe blocks without strict justification.

### C/C++

- Lifetime/ownership ambiguity.
- Buffer boundary and integer conversion bugs.
- Double free / use-after-free risk.
- Missing RAII guardrails.

### SQL

- Injection via string interpolation.
- Missing tenant or row-scope filters.
- Non-deterministic ordering assumptions.
- Migration reversibility and lock impact.

### PHP

- Missing `strict_types` in modern codebases.
- Legacy insecure API usage.
- Weak null and type checks.
- Inconsistent exception/error handling paths.

## Reporting Format

For each finding include:
- Severity.
- Layer.
- Location (`path:line`).
- Impact.
- Evidence.
- Actionable fix.

If no findings:
- State "No findings" clearly.
- List residual risks and what could not be verified.

## Command Reporting Standard

When running checks include:
- Command.
- Exit code.
- Relevant output lines only.
- Interpretation.

## Codex Skill Paths (when available)

If Codex skills are installed, prefer these assets:

- `~/.codex/skills/ai-review/reference/methodology.md`
- `~/.codex/skills/ai-review/reference/risk-weights.md`
- `~/.codex/skills/ai-review/reference/report-template.md`
- `~/.codex/skills/ai-review/scripts/review_changed.sh`
- `~/.codex/skills/ai-review/scripts/review.sh`

Fallback:
- If skill paths are unavailable, use this adapter as the canonical process.

## Merge/Update Guidance

Keep this adapter wrapped with markers so installers can update only this section:
- Start marker: `<!-- AI-REVIEWER-START -->`
- End marker: `<!-- AI-REVIEWER-END -->`

Do not nest markers.

<!-- AI-REVIEWER-END -->
