# Evidence-first semantic review workflow

This is the canonical operational workflow for Dissect. It is shared by diff
reviews, full reviews, the installed agent entrypoints, and generated editor
adapters. Evidence collection prepares context; it does not declare a semantic
vulnerability. Deterministic and external-tool output is candidate evidence,
not a final finding.

## Phase 1 — Establish intent

Read the strongest available sources in this order: user request, PR title and
description, linked issue or ticket, repository-local task or design documents,
then existing public contracts and tests. Record the intended outcome,
constraints, acceptance criteria, required negative behaviour, compatibility
expectations, and unresolved ambiguities. If authoritative intent is absent,
continue with correctness, contract, regression, and security review; mark
requirement fidelity **Not verified** and never invent a requirement.

## Phase 2 — Build behavioural units

Review behaviour rather than files. Group the scope into endpoints or server
actions, state transitions, validation rules, migrations, jobs, retry/queue
flows, permission changes, payment operations, UI interactions,
configuration/deployment changes, dependency/API changes, and refactors that
claim unchanged behaviour. For every unit record entry points, changed symbols,
inputs, outputs, state read and modified, side effects, error paths, callers,
downstream consumers, configuration, tests, and before/after behaviour. A unit
may span files and a file may participate in several units.

## Phase 3 — Identify contracts and invariants

Derive contracts from intent, code, interfaces, schemas, tests, migrations,
callers, documentation, and established repository conventions. Check identity
and ownership before dependent work, server-side authority for identity/role/
price/entitlement, atomic failure behaviour, retry idempotency, cancellation,
API shape compatibility, populated-data migration safety, tenant-safe caches,
webhook verification before mutation, and documented error behaviour. Do not
turn a preferred design choice into a finding.

## Phase 4 — Expand scope deliberately

Trace each changed symbol or contract through direct callers and callees,
interfaces and schemas, persistence and migrations, validators and serializers,
auth middleware, event producers/consumers, generated clients/types,
configuration, tests, and repository-pattern equivalents. Expand only along a
credible behavioural, contractual, or data-flow relationship. Diff reviews do
not become whole-repository audits by default.

When architecture evidence identifies Next.js, Express, Supabase, PostgreSQL,
Prisma, Stripe, FastAPI, or SQLAlchemy, load the matching pack under
`reference/frameworks/`. The pack selects entry points, companion files,
negative tests, and verification sources; it never makes a framework pattern
an automatic finding.

## Phase 5 — Generate candidate findings

Every candidate records an exact claim, allegedly violated contract or
invariant, triggering path, impact, supporting evidence, evidence still needed,
and a verification plan. Candidates may come from semantic tracing,
deterministic checks, compiler/linter/test output, schema comparison,
dependency verification, historical behaviour, missing wiring, or suspicious
tests. The candidate ledger is internal reasoning state and is not dumped in a
routine report.

## Phase 6 — Falsify every candidate

Actively search for validation elsewhere, wrappers and middleware, caller
guarantees, transaction boundaries, framework behaviour, generated code,
feature flags, unreachable paths, compensating controls, negative tests, and
documented intent. Record supporting and contradicting evidence. Candidate
statuses are `candidate`, `verified`, `disproved`, `not_verifiable`, and
`duplicate`. Disproved and duplicate candidates are discarded.

## Phase 7 — Verify surviving candidates

A finding needs an evidence chain: affected behaviour, violated contract,
concrete trigger, impact, and evidence that no existing control prevents it.
Prefer targeted tests or reproductions, focused benchmark tests, compiler or
linter output, static control/data-flow proof, schema comparison,
before/after comparison, local definitions, and official version-specific
documentation. For API, framework, dependency, and CLI claims inspect the
declared or installed version first; never rely on a remembered signature.
Missing tests are reportable only when a concrete unprotected regression path
has been demonstrated.

## Phase 8 — Report only verified findings

Separate verified findings from material open questions, Not verified areas,
and residual risk. Reports must not contain generic best practices, style
preferences, unreachable attack ideas, documentation-only findings, or scanner
matches that were not contextually confirmed. Routine diff reviews lead with
concise findings and include only relevant coverage; full reviews may include a
complete coverage ledger and system model.

## Evidence state

Each applicable family receives exactly one of `Finding`, `Checked`, `Not
applicable`, or `Not verified`. A clean static scan is not proof of production
safety. Runtime and operational checks remain explicit, authorised, and
optional.
