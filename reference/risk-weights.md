# Empirical Risk Weights

These weights guide reviewer attention. They do not automatically determine severity; severity still depends on user impact and exploitability.

## Source Attribution

Primary source for AI-vs-human deltas:
- CodeRabbit State of AI vs. Human Code Generation Report.
- Sample size: 470 pull requests.
- Observation: AI-assisted PRs average 10.83 issues vs 6.45 for human-only PRs.
- Overall issue density multiplier: about 1.7x.

Supporting broader-security indicators:
- Veracode benchmark: about 45% of AI-generated snippets contain security vulnerabilities.
- Cloud Security Alliance reporting: around 62% failure rate for security/architecture quality in assessed AI code outputs.

Treat these as prioritization signals, not automatic severity labels.

## AI vs Human Review Multipliers

| Risk area | Multiplier | Typical failure mode |
| --- | ---: | --- |
| Security | 2.74x | Legacy insecure snippets, permissive configs, weak auth checks. |
| Error handling | 2.0x | Swallowed exceptions, missing cleanup, misleading fallbacks. |
| Logic | 1.75x | Plausible but semantically wrong control flow. |
| Readability/consistency | 3.0x frequency | Robotic naming, duplicate abstractions, mismatched style. |
| Performance I/O | 8.0x frequency | Query/call inside loops, repeated serialization, sync I/O. |
| Concurrency | 2.0x | Shared state, leaked goroutines/tasks, missing cancellation. |

## Percentage Breakdowns Behind Multipliers

- Logic and correctness defects: +75% vs human-authored PRs.
- Readability/style defects: about +300% frequency.
- Error-handling defects: about +200%.
- Security vulnerabilities: +274%.
- Performance I/O anti-patterns: about 8x frequency.
- Concurrency/dependency ordering faults: about +200%.

Critical semantic insight:
- Around 60% of AI-generated faults in DeepSeek-Coder and Qwen-Coder studies compile and run but remain semantically wrong.
- This is why manual logic tracing remains mandatory even with green tests.

## Missed-Bug Buckets

| Bucket | Review response |
| --- | --- |
| Semantic mismatch | Start from intent, not implementation. |
| Exceptional conditions | Trace all failure and cleanup paths. |
| Interface defects | Verify schemas, signatures, versions, and generated types. |
| Checking/validation defects | Test invalid and boundary inputs mentally or with tests. |
| Timing/serial defects | Inspect ordering, locking, cancellation, and lifecycle. |

## Critical Risk Domains

Escalate severity faster when the change touches:

- Authentication, authorization, session, or tenant boundaries.
- Payments, invoices, balances, credits, refunds, or pricing.
- Data migrations, deletion, retention, anonymization, or export.
- Secrets, credentials, tokens, certificates, webhooks, or signing.
- Infrastructure, CI/CD, shell execution, container images, or cloud permissions.
- PII, health, finance, legal, or regulated records.

## Applying Weights

1. Use weights to decide where to spend attention.
2. Use actual impact to decide severity.
3. If a weighted category has no evidence of a bug, do not manufacture a finding.
4. Mention applied weights in the report when they influenced focus.
5. Prefer explicit evidence over intuition, especially for silent logic failures.
