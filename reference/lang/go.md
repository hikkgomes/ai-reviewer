# Go Review Module

Activate for `.go`.

## Highest-Impact Checks

- Ignored errors via `_`, overwritten errors, or returned nil errors after failure.
- Missing `%w` wrapping when caller needs to inspect cause.
- Goroutine leaks, missing context cancellation, unbounded channels.
- `panic`/`recover` used for business logic instead of process boundaries.
- Pointer/value receiver inconsistency.
- Data races around maps, slices, and shared structs.

## AI-Specific Failures

- Error handling that logs and continues incorrectly.
- Context accepted but not passed downstream.
- Interfaces introduced before multiple implementations exist.

## Common False Positives

- Deliberately ignored close errors on read-only cleanup when documented.
- Panics in initialization for unrecoverable configuration failures.
