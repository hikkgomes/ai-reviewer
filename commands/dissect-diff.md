Review only new changes against a base branch, PR base, or explicitly requested diff scope.

This is the default command for change review. It must not review the whole repository except as needed to understand the changed code.

Workflow:

1. Read `reference/review-workflow.md`, the report template, and relevant language/framework packs.
2. Establish intent from the user request, PR, issue, local task documents, contracts, and tests; record unavailable intent as Not verified.
3. Run `scripts/review_changed.sh <base-branch>` to create context outside the target checkout, including NUL-safe changed scope and architecture evidence.
4. Build behavioural units, identify contracts/invariants, and trace direct callers, callees, schemas, persistence, middleware, configuration, and tests only along credible relationships.
5. Generate semantic and deterministic candidates in the ledger. Falsify every candidate, record contradicting evidence, and discard disproved or duplicate candidates.
6. Verify surviving candidates with focused tests, local definitions, control/data-flow proof, or authoritative version-specific evidence. Only verified candidates are findings.
7. Report findings first using `reference/report-template.md`; include concise open questions, verification performed, and scope/residual risk. Do not report unrelated pre-existing defects or generic security boilerplate.

Report only evidence-backed findings. If a risk is plausible but unverified, label it as residual risk or an open question.
