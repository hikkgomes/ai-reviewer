# Rust Review Module

Activate for `.rs`.

## Highest-Impact Checks

- Lifetime misconceptions: `T: 'static` confused with `&'static T`.
- Over-annotated lifetimes that hide ownership design issues.
- `Rc<RefCell<T>>` overuse where ownership can be simpler.
- `unwrap`/`expect` in non-boundary code.
- Clone-heavy fixes that mask borrowing mistakes and performance costs.
- Async locking across `.await`.

## AI-Specific Failures

- Trait bounds copied from examples without need.
- Interior mutability used as an escape hatch.
- Error types erased into strings too early.

## Common False Positives

- `expect` in tests and setup code.
- `Rc<RefCell<T>>` in single-threaded graph/tree structures where mutation is explicit.
