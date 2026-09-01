# Test-integrity rule contract

`GOV-TESTS` reports static evidence about test changes. A match is a candidate,
not a finding and never a test-removal decision.

The machine-readable contract is `reference/test-integrity-rule-manifest.json`.
The validator requires a concrete failure model, exact locations, valid fixture
evidence, positive and negative cases, a reviewed acceptance sample, and a negative
control for every default-enabled rule. Rules without that evidence remain
experimental.

Each default-enabled rule also records malformed-source, generated-code,
framework, suppression, location, and reviewed acceptance evidence in the
machine-readable manifest. Acceptance decisions are stored in
`reference/test-integrity-rule-acceptance-evidence.json`; CI validates the
counts and decisions. This is acceptance testing and does not establish
real-world precision.

The rules do not prove that a test fails, reaches its focal subject, uses an
independent oracle, or protects unique behaviour. Those claims require the
approval-bound matrix, mutation, or proof-test workflows.

Production code which inventories, validates, or runs tests is classified as
`test tooling`, not as a test artefact. Python test classification uses AST
declarations and requires test layout or filename evidence with a real test
declaration.

The initial high-signal rules are:

- `GOV-TESTS-001`: disabled, deleted, or bypassed test discovery.
- `GOV-TESTS-002`: weakened assertion or exception contract.
- `GOV-TESTS-003`: implementation-derived, source-text, or circular oracle.
- `GOV-TESTS-004`: focal behaviour mocked or bypassed.
- `GOV-TESTS-005`: tautological or non-failing test.
- `GOV-TESTS-006`: test-only behaviour in production code.
- `GOV-TESTS-007`: invalid fixture presented as behavioural proof.
- `GOV-TESTS-008`: subject reachability concern, only with dynamic evidence.
- `GOV-TESTS-009`: flakiness, only after repeated identical approved runs.
- `GOV-TESTS-010`: new test file or test-only helper/fixture added without explicit creation approval.

`GOV-TESTS-010` treats a file as approved only when caller-provided intent or an
external trusted intent file explicitly requests or approves its creation, or
when an explicit, digest-bound `review_options.test_integrity_new_test_approval`
matches it. The approval binds repository-relative path patterns, artefact
roles, a maximum count, production subject IDs, and the reviewed base and head
revisions. Generic requests to
implement, fix, test, or verify do not satisfy this requirement. Existing test
files may be changed; this rule is limited to newly added test artefacts.

The four evidence scenarios are `base-code-base-tests`, `base-code-head-tests`,
`head-code-base-tests`, and `head-code-head-tests`. A passing test proves only
the exact behaviour it distinguishes. A surviving mutant is evidence that one
fault was not detected, not proof that the test has no value.
