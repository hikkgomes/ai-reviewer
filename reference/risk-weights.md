# Review attention guidance

These categories prioritize review attention; they do not change finding
severity, prove a vulnerability, or justify a finding without evidence. Use
repository evidence and affected behaviour to decide which category matters.

| Risk area | Review response | Typical failure mode |
| --- | --- | --- |
| Security | Trace indirect trust boundaries and permissive defaults. | Auth bypass, injection, secret exposure, unsafe transport. |
| Error handling | Follow failure, rollback, timeout, and cancellation paths. | Swallowed exceptions, partial state, misleading fallback. |
| Logic | Manually execute boundary and invariant cases. | Plausible but semantically wrong control flow. |
| Interface | Verify schemas, signatures, versions, and generated types. | API break, hallucinated method, incompatible migration. |
| Performance/I/O | Trace loops, fanout, repeated queries, and serialization. | Query or network amplification, blocking work. |
| Concurrency | Review lifecycle, ordering, idempotency, and shared state. | Duplicate side effect, race, leaked task. |

## Critical risk domains

Escalate attention when the change touches authentication, tenant isolation,
payments, pricing, migrations, deletion, retention, secrets, webhooks,
infrastructure permissions, CI/CD, PII, or recovery. Escalation changes review
depth, not the evidence threshold for a finding.

## Applying guidance

1. Start from intent and actual impact.
2. Use the relevant category to choose companion files and negative tests.
3. If no evidence demonstrates a bug, do not manufacture a finding.
4. Record missing runtime or operational proof as Not verified.
