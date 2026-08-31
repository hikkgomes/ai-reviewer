# Test-integrity rule contract

`GOV-TESTS` reports static evidence about test changes. A match is a candidate,
not a finding and never a test-removal decision.

The machine-readable contract is `reference/test-integrity-rule-manifest.json`.
The validator requires a concrete failure model, exact locations, valid fixture
evidence, positive and negative cases, a reviewed sample, and a negative
control for every default-enabled rule. Rules without that evidence remain
experimental.

Each default-enabled rule also records malformed-source, generated-code,
framework, suppression, location, and reviewed manual-precision evidence in the
machine-readable manifest. Calibration decisions are stored in
`reference/test-integrity-calibration.json`; CI validates the counts, decisions,
and measured precision instead of accepting a Markdown claim.

The rules do not prove that a test fails, reaches its focal subject, uses an
independent oracle, or protects unique behaviour. Those claims require the
approval-bound matrix, mutation, or proof-test workflows.

The initial high-signal rules are:

- `GOV-TESTS-001`: disabled, deleted, or bypassed test discovery.
- `GOV-TESTS-002`: weakened assertion or exception contract.
- `GOV-TESTS-003`: implementation-derived or circular oracle.
- `GOV-TESTS-004`: focal behaviour mocked or bypassed.
- `GOV-TESTS-005`: tautological or non-failing test.
- `GOV-TESTS-006`: test-only behaviour in production code.
- `GOV-TESTS-007`: invalid fixture presented as behavioural proof.
- `GOV-TESTS-008`: subject reachability concern, only with dynamic evidence.
- `GOV-TESTS-009`: flakiness, only after repeated identical approved runs.

The four evidence scenarios are `base-code-base-tests`, `base-code-head-tests`,
`head-code-base-tests`, and `head-code-head-tests`. A passing test proves only
the exact behaviour it distinguishes. A surviving mutant is evidence that one
fault was not detected, not proof that the test has no value.
