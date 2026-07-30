# Next.js

- Entry points: `app/**/route.*`, `pages/api/**`, server actions, middleware, layouts and client components.
- Auth/ownership: verify server-side session and tenant checks in route/action boundaries; client guards are not enforcement.
- Persistence: inspect ORM/Supabase calls, cache/revalidate tags, cookies and generated clients with the route.
- Dangerous bypasses: `getServerSession`/middleware applied only to UI, `unsafe` server actions, trusting search params, cached personalized responses, client-only redirects.
- Companions: middleware, route config, layouts, schemas, API clients, tests and `next.config.*`.
- Negative tests: unauthenticated request, another tenant, stale cache, malformed body, server-action replay.
- False positives: public routes explicitly documented as public; middleware may intentionally exclude static assets.
- Verification: inspect installed `next` version and local route types; run the targeted test/typecheck command only after approval.
