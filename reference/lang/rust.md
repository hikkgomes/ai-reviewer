# Rust Review Module

Activate for `.rs`.

## Structural anti-slop backend

The optional ast-grep backend reports textually identical `transmute` source
and destination types, and an explicit same-expression `Box<dyn Any>`
construction followed by downcast. These are structural candidates only. The
rules do not ban `unsafe`, trait objects, dynamic registries, or justified
type-erasure boundaries.

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
# Operational tracing playbook

Inspect trait contracts, callers, error types, async task cancellation,
ownership/lifetimes, serialization, feature flags and tests. Trace external
input into unsafe code, SQL, paths and network clients; verify crate versions
from Cargo metadata. Use focused tests or compiler output when approved and
distinguish an intentional `unsafe`/interior-mutability boundary from a bug.
