# Universal AI Review Skill

This is the canonical workflow for reviewing AI-written code in any repository.

## Sources of truth

1. `.ai-review/local.json` for repo-specific commands and constraints
2. repository files and project config
3. the actual results of commands you ran

Do not guess. If something could not be verified, say so.

## Review order

### 1. Determine scope
Default to changed files first. Expand only when:
- the user asks for a broader review
- the changed code touches shared infrastructure
- the local diff is too small to understand the behaviour safely

### 2. Load repo-local settings
Read `.ai-review/local.json` if present.

Use it for:
- install, lint, typecheck, test, build commands
- critical paths
- generated or ignored paths
- risk flags
- repo notes

### 3. Run automated checks
Prefer these scripts:
- `.ai-review/scripts/review_changed.sh`
- `.ai-review/scripts/review.sh`

Always record:
- which commands ran
- exit status
- missing tools or commands
- important warnings

### 4. Review for the common AI failure classes

1. Hallucinated APIs, methods, parameters, env vars, endpoints, or version-mismatched usage
2. Code that looks plausible but does not run
3. Subtle logic errors and bad edge-case handling
4. Over-engineering or unnecessary abstractions
5. Repetition, divergence, or dead helpers
6. Broken or harmful error handling
7. Wrong async, concurrency, or lifecycle usage
8. Security weaknesses and unsafe defaults
9. Performance cliffs and needless work
10. Tests that do not really validate behaviour
11. Dependency, runtime, or environment mismatches
12. Violated instructions or public interface changes
13. Missing validation or unsafe I/O assumptions
14. Maintainability problems
15. External-system assumptions
16. Integration mismatches
17. Toy-example incompleteness
18. Observability gaps
19. Data correctness, determinism, or numeric issues
20. Locale, Unicode, or parsing issues
21. Resource leaks or runaway retries
22. Behaviour changes hidden inside refactors
23. Licensing or policy constraints when relevant

### 5. Prioritise findings
Use this order:
- Critical: security, data loss, auth, payments, destructive behaviour, unsafe migrations
- High: incorrect logic, broken runtime behaviour, public API breakage
- Medium: maintainability, weak tests, performance cliffs without immediate failure
- Low: style, small duplication, minor cleanup

### 6. Output format
Follow `.ai-review/templates/review-report.md`.

Never claim the code is safe, correct, or production-ready unless the executed evidence supports that conclusion.
