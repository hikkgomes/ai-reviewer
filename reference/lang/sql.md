# SQL Review Module

Activate for `.sql` and embedded query-heavy changes.

## Highest-Impact Checks

- Fanout joins that multiply rows before aggregation.
- Filtering before versus after aggregation.
- `!= 'value'` or `<> 'value'` dropping `NULL` unintentionally.
- Missing tenant/account/user constraints.
- Window functions relying on default frames.
- `LEFT JOIN` turned into `INNER JOIN` by `WHERE` filters on nullable joined tables.
- Schema hallucination: columns, tables, relations, enum values, and indexes.

## AI-Specific Failures

- Queries that look idiomatic but violate actual schema names.
- Aggregates that pass small fixtures but fail realistic cardinality.
- Missing explicit ordering where pagination or determinism matters.

## Common False Positives

- Intentional `NULL` exclusion documented by a predicate or constraint.
- Window frame defaults where the aggregate is insensitive to frame choice.
