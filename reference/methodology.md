# Six-Layer Adversarial Review Methodology

This is the canonical review workflow for AI-assisted code. Use it to review changed files first, then expand only when the change cannot be understood safely from the diff.

## Pre-Review: Build the Mental Model

1. Read the PR description, issue, task text, or user request before reading implementation details.
2. Load the target repository's `.ai-review/local.json` when present.
3. Identify modified architectural layers: UI, API, service, persistence, infrastructure, tests, scripts, data migrations, generated assets.
4. State the intended behavior in your own words before inspecting line-level code.
5. Identify invariants that must remain true: auth boundaries, data ownership, persistence rules, idempotency, API compatibility, migrations, error contracts, performance budgets.
6. Detect languages in changed files and load the matching `reference/lang/*.md` modules.
7. Run configured checks when available, but do not let passing checks replace manual review.

Review evidence in this order: user intent, repo-local instructions, actual code, executed command output, external documentation only when needed.

## Layer 1: Requirement Fidelity

Ask whether the code solves the exact requirement or a generic proxy. AI-generated code often mirrors prompt wording while missing domain semantics.

Check for:
- Prompt-mirroring: names and comments match the task, but behavior is generic.
- "God Prompt" probability decay: many independent requested constraints implemented partially or inconsistently.
- Business-rule drift: defaults, thresholds, currencies, permissions, ownership, status transitions, or retention rules that differ from existing code.
- Missing negative behavior: what the code must reject, preserve, or refuse to mutate.

Empirical anchor: semantic intent/execution mismatches dominate missed review bugs; treat requirement fidelity as the highest-leverage layer (51% of bugs missed in review are semantic mismatches, SmartSHARK dataset).

## Layer 2: Logic and Edge Cases

Trace the code manually through normal, boundary, and failure paths. A large share of AI faults compile and run but are logically wrong (about 60% in DeepSeek-Coder and Qwen-Coder studies).

Check for:
- Off-by-one, empty input, null/undefined/None, NaN, invalid enum, duplicate, missing, and partially loaded states.
- Incorrect branching, inverted predicates, wrong sort/filter order, stale values, accidental mutation, shared mutable state.
- Async ordering, retries, cancellation, timeouts, idempotency, and race conditions.
- Exception handling paths, especially where user-visible behavior or data integrity depends on them.

Risk weighting: apply 1.75x attention to logic errors (+75% in AI code) and 2.0x to error handling (36% of all missed semantic bugs are exception-handling related).

## Layer 3: API and Dependency Integrity

Verify every external and internal interface instead of trusting plausible names.

Check for:
- Slopsquatting or hallucinated packages, imports, methods, parameters, environment variables, endpoints, CLI flags, and config keys.
- Version-specific API signatures and changed defaults.
- Database schema, ORM model, GraphQL field, REST payload, queue message, and event contract correctness.
- Reinvented internal utilities, validators, clients, hooks, or error types.

When uncertain, inspect local definitions or official docs. Do not report guessed API findings as facts.

## Layer 4: Security Patterns

AI code has elevated risk for old vulnerability patterns and permissive defaults. Review security even when the change does not look security-related.

Check for:
- Auth/authz bypass, object-level authorization, tenant isolation, role escalation, session handling.
- Injection: SQL, shell, template, LDAP, path traversal, SSRF, unsafe redirects.
- Secrets in code, logs, tests, fixtures, telemetry, or error messages.
- Unsafe deserialization, weak crypto, TLS disabled, permissive CORS/CSP, missing security headers.
- Destructive operations without confirmation, authorization, audit, transactionality, or rollback path.

Risk weighting: apply 2.74x attention to security-sensitive AI code (+274% security vulnerabilities vs human code).

## Layer 5: System Awareness

Check whether the change fits the existing system rather than working as an isolated snippet.

Check for:
- Cross-layer consistency: DB schema, migrations, API contracts, client types, validation, docs, tests.
- Global state, caches, queues, feature flags, configuration, observability, background jobs, and lifecycle hooks.
- Repository conventions: naming, layering, error model, dependency boundaries, transaction handling, generated-code ownership.
- Multi-file completeness: every new field, route, enum, event, permission, and error code is wired through all required layers.

AI-specific symptoms: duplicated local abstractions, inconsistent naming, defensive code that hides impossible states, and missing integration points.

## Layer 6: Test Quality

Treat tests generated alongside AI code as untrusted until they prove behavior from the outside.

Check for:
- Tests assert public behavior, not implementation details copied from the code.
- Edge cases and error paths are covered, especially validation, denied access, missing dependencies, retries, and rollback.
- Tests fail for the bug they claim to prevent.
- Fixtures represent realistic data and do not encode hallucinated schemas.
- Mocks do not remove the behavior under review.

Risk weighting: because AI code produces about 2x more error-handling issues, error-path tests deserve 2.0x attention.

## Severity Classification

- Critical: exploitable security issue, data loss/corruption, auth bypass, payments, unsafe migration, destructive behavior, secret exposure.
- High: broken runtime behavior, incorrect business logic, public API breakage, unrecoverable failure path, serious integration mismatch.
- Medium: meaningful maintainability risk, missing important tests, performance cliff, fragile edge case without immediate production breakage.
- Low: style, small duplication, naming, minor consistency issue, low-risk cleanup.

Prefer fewer, stronger findings. Every finding needs file/line evidence, impact, and an actionable fix.

## AI-Specific Risk Weighting

When code is AI-generated or likely AI-assisted, bias attention using these multipliers:

| Category | Multiplier | Review implication |
| --- | ---: | --- |
| Security | 2.74x | Inspect even indirect trust boundaries and defaults. |
| Error handling | 2.0x | Trace exceptions, retries, fallbacks, cleanup, and user-visible errors. |
| Logic | 1.75x | Manually execute boundary and semantic cases. |
| Readability/consistency | 3.0x frequency | Usually lower severity, but watch for misleading abstraction. |
| Performance I/O | 8.0x frequency | Check loops, queries, fanout calls, sync I/O, and repeated serialization. |
| Concurrency | 2.0x | Review lifecycle, shared state, cancellation, and resource leaks. |

## Review Discipline

- Do not claim code is safe or correct unless evidence supports that conclusion.
- Separate verified findings from risks or questions.
- Mention commands run, their exit status, and important warnings.
- State which language modules were activated.
- If no findings are found, say that clearly and list residual unverified risk.
