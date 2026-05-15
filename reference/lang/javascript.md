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
