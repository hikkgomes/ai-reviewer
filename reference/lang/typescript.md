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
