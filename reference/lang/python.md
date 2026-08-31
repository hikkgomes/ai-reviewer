# Python Review Module

Activate for `.py` and `.pyi`.

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

## Structural anti-slop backend

The optional standard-library AST backend reports candidate evidence for an
immediate `typing.cast` widening and narrowing, and for literal `getattr`
without a default outside recognised dynamic protocols. It honours Python
source encodings and reports syntax errors as incomplete coverage. It does not
ban `Any`, reflection, or normal API-boundary casts.
# Operational tracing playbook

Inspect task intent, import declarations, callers, schemas, settings,
transaction/session dependencies, tests and deployment configuration. Trace
async cancellation and task lifecycle, context-manager cleanup, FastAPI/
Pydantic or Django validation, exception translation, mutable defaults, and
runtime/type mismatches. Confirm dependency declarations and import aliases in
the nearest manifest. Use focused pytest/unittest, typechecker, or linter
commands only when approved. Do not report an unhandled-looking exception when
an outer boundary intentionally translates it; verify the complete call path.
