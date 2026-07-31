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
