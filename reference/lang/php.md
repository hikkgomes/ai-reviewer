# PHP Review Module

Activate for `.php`.

## Highest-Impact Checks

- Missing `declare(strict_types=1)` in new strict codebases.
- `isset()` chains where nullsafe `?->` or explicit validation is clearer.
- `switch` fallthrough mistakes where `match` would be safer.
- Deprecated `mysql_*` APIs.
- Loose comparison and type juggling around auth, tokens, and IDs.
- SQL concatenation and escaping assumptions.

## AI-Specific Failures

- Framework facade or helper names from a different Laravel/Symfony version.
- Generic array payloads instead of existing DTO/request validation.
- Silent fallback behavior that hides invalid state.

## Common False Positives

- Legacy files in non-strict codebases where local convention has not migrated.
- Intentional loose comparisons in compatibility shims.
