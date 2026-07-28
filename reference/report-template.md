# AI Review Report

## Mental Model

- Intent:
- Modified layers:
- Invariants:
- Language modules:
- Risk weighting:

## Review Scope

- Included:
- Excluded:
- Runtime authorisation:

## Commands and Tools Executed

For each tool record detection, command, exit code, relevant output, and whether
the result was complete. Configured checks must never be silently skipped.

## Findings by Severity

Order findings Critical, High, Medium, then Low. Every finding uses:

### [Severity] [CHECK-ID] Title

- Confidence:
- Methodology layer:
- Location or command evidence:
- Impact:
- Exploit or failure scenario:
- Recommended fix:
- Verification guidance:

## Coverage Ledger

Assign exactly one state to every applicable family: Finding, Checked, Not
applicable, or Not verified.

| Check family | State | Evidence / reason |
| --- | --- | --- |
| SEC-SECRETS |  |  |
| SEC-AUTHN |  |  |
| SEC-AUTHZ |  |  |
| SEC-DATABASE |  |  |
| SEC-ROUTES |  |  |
| SEC-BROWSER |  |  |
| SEC-PAYMENTS |  |  |
| SEC-DATA |  |  |
| SEC-DEPLOY |  |  |
| SUP-DEPENDENCY |  |  |
| OPS-OBSERVABILITY |  |  |
| OPS-RECOVERY |  |  |
| OPS-DESTRUCTIVE |  |  |
| GOV-REGRESSION |  |  |
| GOV-AUDIT |  |  |
| ABUSE-BRAND |  |  |

## Operational Controls and Evidence

- Static configuration observed:
- Runtime/operational proof observed:

## Not Applicable

List families and the evidence that the technology/control is absent.

## Not Verified

List families, why verification was impossible, and the exact evidence needed.

## Example Finding

### [High] [COR-RETRY-001] Retry Loop Ignores Cancellation Signal

- Confidence: High
- Methodology layer: Layer 2 — Logic and Edge Cases
- Location or command evidence: `services/sync_worker.py:148`
- Impact: Worker can continue issuing external writes after caller cancellation, causing duplicate side effects and delayed shutdown.
- Exploit or failure scenario: A cancelled request times out repeatedly and keeps mutating external state.
- Recommended fix: Check cancellation state at top of loop and before each retry; propagate cancellation error instead of retrying.
- Verification guidance: Add a test that cancels during a timeout and asserts no later write occurs.

## Residual Risk

Mention remaining uncertainty, missing tests, or areas that need human product/
security confirmation. A clean static review is not proof of production safety.

## Remediation Priorities

List a concise, ordered set of next actions.

## Guidance Notes

- Tone: direct, evidence-based, and non-speculative.
- Length: concise; prefer fewer high-signal findings over many weak findings.
- Residual risk vs finding:
  - Use a finding only when you have concrete file/line evidence and credible impact.
  - Use residual risk when the concern is plausible but unverified due to missing context, missing runtime access, or missing tests.
