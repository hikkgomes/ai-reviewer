# Complexity review policy

Dissect records function-level cyclomatic complexity as a review signal. A
large number is not an automatic defect or a reason to split code mechanically.

Thresholds are selected in this order:

1. Repository configuration, such as Ruff or flake8 `C901`, ESLint
   `complexity`, or golangci-lint `gocyclo` and `cyclop`.
2. An explicitly approved repository-native threshold.
3. The skill-local Lizard `1.24.0` fallback threshold, which is 15 by default.

Diff mode analyses new or changed functions and compares exact base and head
source states. Full mode analyses all selected supported functions. Generated
and vendored paths are excluded. Ambiguous base mapping produces a head metric
without an unverified delta.

Initial candidate conditions are a new function above the active threshold, a
changed function above the threshold with increased complexity, or growth of at
least five points ending above ten. Candidates require human review of branch
cohesion, failure paths, state transitions, security boundaries, and
testability.

The fallback dependency is pinned in `scripts/vendor/lizard/requirements.txt`.
Its metadata and upgrade procedure are in `PROVENANCE.json`. No global Lizard
installation is searched.

Complexity output must retain the source layer, content hash, exact line span,
metric, threshold, threshold source, and base/head mapping status. Parser
failure, ambiguous mapping, missing tooling, and exhausted limits are
`Not verified`; they do not become complexity findings.
