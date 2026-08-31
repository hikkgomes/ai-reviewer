# JavaScript Review Module

Activate for `.js`, `.jsx`, `.mjs`, and `.cjs`.

## Highest-Impact Checks

- Missing `await`, unhandled promises, lost errors in `.then()` chains.
- `this` binding errors in callbacks and class methods.
- Loose equality, truthiness bugs, `NaN`, `0`, empty string, and nullish confusion.
- `var` scope and hoisting surprises.
- Prototype pollution and unsafe object merging.

## AI-Specific Failures

- Plausible package APIs imported without local precedent.
- Defensive defaults that hide invalid inputs.
- Browser/server runtime confusion.
- Callback and promise styles mixed incorrectly.

## Common False Positives

- Loose equality used intentionally for nullish checks when local style permits it.
- Framework-generated globals in legacy code.

## Structural anti-slop backend

The optional skill-local Oxlint backend covers `.js`, `.jsx`, `.mjs`, and
`.cjs`. It reports the pinned anti-slop rules as structural candidates only.
Runtime type checks, reflection, mocks, broad object types, and assertions
require semantic review before they become findings.
# Operational tracing playbook

Read route/bootstrap files, validators, callers, tests, package manifests and
the runtime version. Follow untrusted values across server/client boundaries,
serialization, async error paths, React effects and cache state. Check promise
rejection, cancellation, stale closures, unsafe HTML, redirects, filesystem
paths, generated clients, and package-version signatures. Verify with local
definitions and focused lint/test commands when approved. A suspicious token
is only a candidate until wrappers, middleware, validators, and reachability
are inspected.
