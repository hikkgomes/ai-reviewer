# Supabase

- Entry points: client creation, server routes, Edge Functions, migrations, views, RPCs and storage rules.
- Auth/ownership: trace JWT identity to `auth.uid()`/tenant predicates; service-role clients require a server-only boundary.
- Persistence: inspect all migration files defining a table's RLS, policies for SELECT/INSERT/UPDATE/DELETE, grants, views and functions.
- Dangerous bypasses: browser service-role keys, missing operation policy, broad `USING (true)`, `SECURITY DEFINER` without `search_path`, RPC bypass assumptions.
- Companions: later migrations, generated types, storage policies, API routes, seed data and negative tests.
- Negative tests: each CRUD operation as another user and anonymous user; direct RPC/view access.
- False positives: a later migration may intentionally complete an earlier RLS setup; correlate migrations before reporting.
- Verification: use local SQL definitions and migration order; run a disposable local policy test only when authorised.
