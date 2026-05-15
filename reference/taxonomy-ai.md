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
