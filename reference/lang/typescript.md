# TypeScript Review Module

Activate for `.ts` and `.tsx`.

## Highest-Impact Checks

- Type escape hatches: repeated `as`, `as any`, non-null assertions, broad generics, unsafe casts at API boundaries.
- Optional-everything modeling: optional fields replacing discriminated unions or explicit state machines.
- Exhaustiveness: missing `never` checks for unions, status enums, reducers, and switch statements.
- Runtime validation: external JSON typed without parsing or validation.
- Async/react lifecycle: stale closures, dependency arrays, race conditions, unhandled promises.

## AI-Specific Failures

- Invented fields on generated API types.
- Type assertions used to silence real mismatches.
- Interfaces duplicated instead of importing source-of-truth types.
- Tests compile because mocks are typed as `any`.

## Prefer

- `satisfies` for structural checking of object literals.
- Discriminated unions for stateful flows.
- Schema validators at untrusted boundaries.

## Common False Positives

- Intentional casts around well-contained framework limitations.
- Generated client types with awkward optional fields.

## Anti-slop patterns (deterministic candidates)

Strong candidates, report only when semantically confirmed:

- Chained type assertions, widen-then-assert flows, and known-value widening.
- Unsafe dictionary types.
- `unknown` in parameters, returns, or aliases without narrowing.
- Type assertions without a specific safety justification.

Weak signals, context only and never findings alone:

- Module mocking, `Reflect` usage, runtime `typeof`, object-bag parameters, and
  symbol-naming rules.

Effect rules apply only when the project depends on `effect`. An anti-slop
diagnostic proves that a pattern occurred, not that behaviour is wrong. Verify
the concrete contract violated or the evidence gap before reporting it.

The backend also covers `.mts` and `.cts` files. It uses the skill-local
Oxlint `1.78.0` runtime and never downloads rules during a review.
# Operational tracing playbook

Inspect task/PR intent, public types, schemas, generated API clients, route
callers, server/client boundaries, tests, and the package version before making
an API claim. Trace values from runtime input through validation, persistence,
serialization, and UI consumption. Check React lifecycle/stale state,
Next.js routes and server actions, promise rejection/cancellation, exhaustive
state machines, date/number serialization, and static types that do not exist
at runtime. Verify APIs against local definitions or the installed package.
Useful checks are the repository's typecheck, focused test, and a minimal
runtime reproduction; never treat a clean TypeScript compile as runtime
validation. Avoid false positives when a shared validator, middleware, or
generated type supplies the control.
