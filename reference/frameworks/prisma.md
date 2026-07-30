# Prisma

- Entry points: schema, migrations, Prisma Client calls, transactions and generated types.
- Auth/ownership: verify predicates are present in the actual `where` clause, not just in a prior lookup.
- Persistence: inspect nested writes, interactive transaction lifetime, relation optionality and migration rollout compatibility.
- Dangerous bypasses: `findUnique` by untrusted ID, `update` without tenant predicate, `$queryRawUnsafe`, swallowed transaction errors.
- Companions: schema.prisma, migration SQL, validators, route handlers, generated client version and tests.
- Negative tests: another tenant, missing relation, duplicate retry, rollback after nested write.
- False positives: a trusted internal job may use a broader query when its boundary and authorization are established.
- Verification: inspect installed Prisma version and generated client definitions; run the focused migration/client test with approval.
