# SQLAlchemy

- Entry points: models, query builders, session dependencies, transactions, migrations and event hooks.
- Auth/ownership: put tenant/owner predicates on the query that mutates or returns data; do not rely on a prior check alone.
- Persistence: inspect autoflush, commit/rollback, session scope, async cancellation and migration compatibility.
- Dangerous bypasses: string SQL, broad `filter_by`, detached objects, commit in helper before caller transaction, leaked session.
- Companions: Alembic revisions, repositories, FastAPI/Django boundary, serializers, queues and tests.
- Negative tests: wrong tenant, duplicate write, rollback after failure, concurrent update and cancellation cleanup.
- False positives: repository helpers can inherit a constrained query; follow the query construction before concluding a bypass.
- Verification: inspect installed SQLAlchemy/Alembic versions and local signatures; use a disposable database for transaction tests.
