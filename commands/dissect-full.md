Review the whole repository, or the repo areas named in the prompt, regardless of whether the code is new.

Use this command for baseline audits, focused subsystem reviews, security sweeps, architecture reviews, or review of a path/module that may not be part of a current diff.

Workflow:

1. Read `reference/review-workflow.md`, the report template, and relevant language/framework packs.
2. Establish intent and scope from the prompt, local instructions, public contracts, schemas, and tests; record unavailable requirements as Not verified.
3. Run `scripts/review.sh` to build a complete context outside the target checkout and activate the architecture detector.
4. Group the repository or selected subsystem into behavioural/system units. Identify contracts and invariants, then trace their credible callers, callees, persistence, routes, middleware, configuration, operations, and tests.
5. Generate candidates from semantic tracing, deterministic checks, and approved external tools. Falsify every candidate and verify survivors with concrete evidence.
6. Use the full report format when useful: system model, relevant coverage ledger, Not applicable and Not verified controls, operational evidence, and remediation priorities. Report only verified findings, material open questions, and honest residual risk.

Prioritize correctness, security, API/schema validity, system integration, and meaningful tests over style.
