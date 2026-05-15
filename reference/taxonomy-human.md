# Human Error Taxonomy

Use this taxonomy to avoid overfitting review to AI-specific issues. Human-authored code still fails through well-known defect classes.

## SmartSHARK Attribution and Data Scope

This taxonomy is anchored in empirical review-miss data from SmartSHARK research:
- Dataset: 16,779 merged pull requests.
- Projects: 77 open-source repositories.
- Candidate PRs for review-miss analysis: 3,261.
- Research question: which bugs escape human code review and are found post-merge.

Use these numbers as review-priority guidance, not severity by themselves.

## Classic Vulnerability Classes

- Boundary overflow: buffer overrun, integer overflow, length miscalculation, truncation.
- Malformed input: parser confusion, invalid encoding, partial payload, unexpected file type, duplicate fields.
- Format string and interpolation bugs: unsafe formatting, template injection, locale-sensitive formatting.
- Exceptional condition handling: cleanup skipped, partial write committed, retry storm, swallowed failure.
- Access control: missing object-level checks, role mismatch, confused deputy, tenant boundary leak.

## ODC Defect Classes

- Assignment: wrong value, stale variable, incorrect initialization, accidental mutation.
- Checking: missing validation, inverted condition, wrong comparison, incomplete guard.
- Algorithm: wrong sequence, off-by-one, incorrect data structure, incomplete state transition.
- Interface: wrong parameter, return value, schema, protocol, unit, or ownership contract.
- Timing/serial: race condition, ordering dependency, deadlock, reentrancy, lifecycle bug.

## Missed Review Bug Distribution

Empirical studies of review misses show semantic bugs are hard to catch without intent modeling. Use these buckets while reading:

- Semantic bugs: 51.34%.
- Build bugs: 15.50%.
- Analysis checks: 9.09%.
- Compatibility bugs: 7.49%.
- Concurrency and configuration: 8.56%.
- GUI, API, security, and memory buckets are each below 8%.

These percentages indicate where manual review depth pays off most.

## Sub-Categories and Review Triggers

### 1) Semantic Bugs (51.34%)

Most dangerous because code often compiles, runs, and looks plausible.

Key sub-types:
- Exception-handling defects are 36.46% of semantic bugs.
- Missing required behavior for negative paths.
- Wrong state transitions despite valid syntax and tests.
- Business-rule mismatches (thresholds, status rules, ownership checks).

Review triggers:
- Manual trace of success and failure flows.
- Explicitly inspect catch/finally and cleanup behavior.
- Verify domain invariants before and after execution.

### 2) Build Bugs (15.50%)

Often missed because reviewers reason semantically but skip toolchain behavior.

Key sub-types:
- Build hang issues are 58.62% of build bugs.
- Compilation/linker breakage in less common targets.
- CI-only failures from env/tooling divergence.

Review triggers:
- Confirm build scripts and dependency constraints changed coherently.
- Check for long-running or blocking operations in build/CI tasks.
- Validate cross-platform assumptions when touching tooling.

### 3) Analysis Checks (9.09%)

Usually perceived as low risk but can hide production reliability issues.

Key sub-types:
- Missing null checks are 47.06% of analysis-check bugs.
- Violations in static-analysis constraints.
- License/compliance flags and policy violations.

Review triggers:
- Treat nullability and guard clauses as behavior, not style.
- Scan new external deps for policy/compliance implications.
- Confirm lint/static-analysis suppressions are justified.

### 4) Compatibility Bugs (7.49%)

Frequently missed when reviewers test only their local environment.

Key sub-types:
- OS/architecture-specific behavior differences.
- Browser/runtime version assumptions.
- Downstream dependency version mismatches.

Review triggers:
- Verify feature/API usage against supported runtime matrix.
- Check serialization, locale, and filesystem assumptions.
- Confirm contract compatibility for consumers on older versions.

### 5) Concurrency and Configuration (8.56%)

Missed due to high cognitive load and low reproducibility.

Key sub-types:
- Race conditions and ordering dependencies.
- Timeouts and retry storms from bad defaults.
- Environment/config drift causing latent production failures.

Review triggers:
- Inspect lock/lifecycle boundaries and shared state.
- Validate timeout, retry, and backoff semantics.
- Confirm config defaults are safe and production-aware.

## Why Humans Miss These Bugs

Review misses are often not knowledge gaps but process and cognition failures:

- Cognitive fatigue: reviewers lose depth after multiple reviews.
- LGTM syndrome: social pressure to merge quickly causes shallow checks.
- Local-success bias: code that "looks right" and passes narrow tests is over-trusted.
- Path dependence: reviewers follow happy paths and skip negative paths.
- Concurrency blindness: humans under-model interleavings, timing, and partial failures.

Operational implication:
- Spend more time on semantic/exception paths than stylistic cleanup.
- Make explicit passes for build, compatibility, and concurrency.
- Require evidence for correctness, not plausibility.

## Reviewer Prompts

- What invariant was the original author relying on but did not encode?
- What happens when this function receives the smallest, largest, empty, duplicate, stale, or unauthorized input?
- What hidden caller or downstream consumer depends on this behavior?
- What cleanup must happen if the operation fails halfway through?
