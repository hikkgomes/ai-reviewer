# Dissect review report

Routine diff reviews use this compact structure and do not emit unrelated
coverage families.

## Findings

### [High] Title
`path/file.ts:123`
Confidence: High

Explain the broken behaviour and the violated contract or invariant.

**Failure scenario:** Concrete path from input to impact.

**Evidence:** Changed code, relevant caller/schema/control, and verification performed.

**Fix:** Minimal actionable correction.

**Verification:** Test or command that should prove the fix.

## Open Questions

Include only questions that materially affect correctness or severity.

## Verification Performed

List commands, local definitions, tests, reproductions, and whether output was
complete. Approved external tools are optional and their results remain
structural candidates until contextually confirmed. State optional backend
coverage as `Finding`, `Checked`, `Not applicable`, or `Not verified`; do not
add a `Not run` state.

## Test integrity findings

List only verified test bypasses, weakened contracts, circular oracles, or
unprotected changed behaviour. Static candidates alone do not support removal.

## Proof tests performed

Record the candidate, independent oracle, focal subject, current result, control
result, reachability, and outcome. Never include an automatically committed
proof test.

## Mutation evidence

List only material surviving or killed changed-code mutations. Keep each mutant
separate and do not use one mutation score as a quality result.

## Complexity review candidates

Record function identity, base/head complexity, delta, threshold source, and the
concrete behavioural risk to review. Complexity is a signal, not an automatic
finding.

## Not verified test evidence

State missing commands, unapproved execution, incomplete matrices, invalid
fixtures, parser failures, or unavailable toolchains that limit confidence.

## Scope and Residual Risk

State changed behaviour reviewed, credible expansion, excluded pre-existing
areas, and honest Not verified evidence. A clean static review is not proof of
production safety.

## Full-review additions

Full reviews may additionally include a system model, complete applicable-family
ledger, Not applicable controls, Not verified controls, operational evidence,
and remediation priorities. Every applicable family has exactly one state:
Finding, Checked, Not applicable, or Not verified.

## Finding requirements

Every finding needs severity, confidence, exact location, violated contract,
triggering path, concrete impact, evidence chain, minimal fix, and verification
guidance. Do not output approval/rejection, risk scores, generic praise,
style-only findings, speculative vulnerabilities, or missing-test findings
without a demonstrated regression path.
