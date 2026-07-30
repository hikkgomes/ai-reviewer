# PostgreSQL

- Entry points: migrations, schema files, policies, views, functions, triggers and grants.
- Auth/ownership: identify application identity variables and ownership columns; compare policy semantics per operation.
- Persistence: assess populated-table ordering, defaults/backfills, locks, indexes, transactional DDL and rollback.
- Dangerous bypasses: `SECURITY DEFINER`, unrestricted views/functions, `NOT NULL` before backfill, destructive DDL without recovery.
- Companions: ORM models, generated types, deployment order, seed data, query callers and rollback scripts.
- Negative tests: old and new application versions against populated data; each policy operation; concurrent migration access.
- False positives: policy definitions split across migrations must be combined in order.
- Verification: inspect the declared PostgreSQL/ORM version and local migration SQL; use explain or a disposable database if authorised.
