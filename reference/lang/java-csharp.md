# Java and C# Review Module

Activate for `.java` and `.cs`.

## Highest-Impact Checks

- Exception propagation: in C#, `throw ex` resets stack traces; prefer `throw`.
- Blocking async code: `.Result`, `.Wait()`, synchronous calls inside async request paths.
- Resource management: `using`, try-with-resources, stream disposal.
- Multiple enumeration of `IEnumerable`.
- Nullability annotations ignored or silenced.
- High cyclomatic complexity hidden inside service methods.

## AI-Specific Failures

- Framework annotations or attributes from the wrong version.
- DTOs duplicated instead of using existing contracts.
- Repository/service abstractions invented without matching dependency injection configuration.

## Common False Positives

- Boundary adapters that intentionally translate exceptions.
- Enumerables materialized deliberately to avoid repeated database queries.
