# AI-Specific Error Taxonomy

AI-generated code tends to be plausible, locally coherent, and systemically incomplete. Use this taxonomy to identify failures that static checks often miss.

## Silent Logic Failures

Symptoms:
- Compiles, runs, and passes shallow tests while returning wrong results.
- Implements a common version of the problem instead of the repo-specific rule.
- Handles happy paths and common examples while ignoring boundary states.

Review response: manually trace domain cases and compare against existing behavior.

## Hallucinated Interfaces

Symptoms:
- Nonexistent package, import, method, option, env var, route, column, enum, or CLI flag.
- Real API used with a signature from a different version or ecosystem.
- ORM or database field inferred from naming rather than schema.

Review response: inspect local definitions and lockfiles; use official docs when local evidence is insufficient.

## Context Blindness

Symptoms:
- New helper duplicates an existing utility.
- Error handling conflicts with the repo's error model.
- Feature is wired into one layer but not another.
- Global state, caching, transactions, queues, or feature flags are ignored.

Review response: walk the full data/control path across files.

## Prompt Drift and God Prompt Decay

Long prompts with many constraints decay combinatorially. If 20 independent constraints each have a 95% chance of being followed, the chance of all 20 being correct is about 35%.

Symptoms:
- Early requirements implemented, later ones omitted.
- Constraints appear in comments but not behavior.
- Mixed strategies across files.

Review response: make a checklist from the actual requirement and verify each item.

## Stylistic Dissonance

Symptoms:
- Excessive docstrings and comments for simple code.
- Robotic names such as `calculate_comprehensive_user_data_processing_result`.
- Defensive coding that masks impossible states instead of enforcing invariants.
- Optional-everything types, broad exception swallowing, and generic fallbacks.

Review response: report only when style hides defects, blocks maintenance, or violates local conventions.

## Redundant AI narration

Redundant AI narration is a reviewable category in its own right. The default
recommendation is removal, not because comments are forbidden, but because
adjacent code and repository history already carry the same information.

Verify every candidate with three checks:

1. Truthfulness: does the current code support the claim? Inspect the function
   body and direct callees only. Beyond that depth, use `not_verifiable` rather
   than spending review budget proving a negative across the call graph.
2. Relevance: is the statement part of the function contract, repository
   requirement, task or PR scope, safety constraint, or a real design decision?
3. Stability: does it describe the current invariant rather than a recent change
   or previous implementation? In diff mode compare historical claims with the
   diff or previous version. In full mode without history, truthfulness and
   relevance decide alone.

Verified classifications recommend removal:

- Misleading comment: the current code does not implement the claim.
- Unsupported non-goal: an arbitrary limitation is stated without a contract or
  requirement.
- Change-log comment: the comment describes what changed, used to happen, or was
  removed; Git already records that history.
- Negative-only documentation: the comment lists arbitrary things the function
  does not do without a meaningful invariant.
- Narration, section-header, and conversation-leak: the information is
  recoverable from adjacent code or the conversation.

Mixed comment slop recommends keeping only the stable useful part.

Keep negative statements that define real contracts, including security
restrictions, intentional unsupported behaviour, compatibility constraints,
deprecations, protocol requirements, safety rules, and explicit product
non-goals.

Calibration anchors:

```ts
// Check if the user exists        ← remove (narration)
if (user) {
  // Update the user's name        ← remove (narration)
  user.name = name;
}

// Keep the old slug because external webhook signatures include it.   ← keep (why)
const slug = existingSlug;

// Do not send notifications here.                                     ← keep (real invariant)
// The transaction can retry, so external side effects must run after commit.
```
