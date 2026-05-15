# AI Review Report

## Mental Model

- Intent:
- Modified layers:
- Invariants:
- Language modules:
- Risk weighting:

## Findings by Layer

Report findings grouped by methodology layer first, then by severity within each layer.

### Layer 1: Requirement Fidelity

- No issues found in this layer.

### Layer 2: Logic and Edge Cases

- No issues found in this layer.

### Layer 3: API and Dependency Integrity

- No issues found in this layer.

### Layer 4: Security Patterns

- No issues found in this layer.

### Layer 5: System Awareness

- No issues found in this layer.

### Layer 6: Test Quality

- No issues found in this layer.

When a finding exists, use this exact shape:

### [Severity] Title

- Layer:
- Location: `path:line`
- Impact:
- Evidence:
- Fix:

## Example Finding

### [High] Retry Loop Ignores Cancellation Signal

- Layer: Layer 2: Logic and Edge Cases
- Location: `services/sync_worker.py:148`
- Impact: Worker can continue issuing external writes after caller cancellation, causing duplicate side effects and delayed shutdown.
- Evidence: `while True` loop catches timeout exceptions and retries without checking `ctx.cancelled` or equivalent cancellation token.
- Fix: Check cancellation state at top of loop and before each retry; propagate cancellation error instead of retrying.

## Verification

Use this structure for automated checks and manual commands:

- Command: `<command text>`
- Exit code: `<numeric code>`
- Relevant output: `<only the lines that matter>`
- Interpretation: `<what this means for correctness/risk>`

Also include:

- Not run / not verified:

## Residual Risk

Mention remaining uncertainty, missing tests, or areas that need human product/security confirmation.

## Guidance Notes

- Tone: direct, evidence-based, and non-speculative.
- Length: concise; prefer fewer high-signal findings over many weak findings.
- Residual risk vs finding:
  - Use a finding only when you have concrete file/line evidence and credible impact.
  - Use residual risk when the concern is plausible but unverified due to missing context, missing runtime access, or missing tests.
