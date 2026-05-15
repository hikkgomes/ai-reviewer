# Python Review Module

Activate for `.py`.

## Highest-Impact Checks

- Mutable default arguments: `def f(items=[])`.
- `is` versus `==` for value comparison.
- Broad `except Exception` and bare `except`, especially with `pass`.
- Late-binding closures in loops.
- Iterator exhaustion and one-shot generators reused.
- Sync I/O inside async functions.
- Interface drift from protocols, dataclasses, Pydantic models, or ORM schemas.

## AI-Specific Failures

- Unused args added to match a guessed interface.
- Exception handlers that return generic fallbacks instead of preserving failure semantics.
- Dict-shaped data where typed models already exist.
- Imports from nonexistent internal modules.

## Common False Positives

- Sentinel defaults using `None` with explicit initialization.
- Broad exceptions at process boundaries that log and re-raise or convert to a documented error.
