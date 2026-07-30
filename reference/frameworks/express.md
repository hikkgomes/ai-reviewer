# Express

- Entry points: router declarations, `app.use`, controllers, error middleware and background handlers.
- Auth/ownership: trace middleware order and mounted prefixes to the handler; verify object checks after loading the object.
- Persistence: inspect transaction/session lifetime, serializers, queues and response writes.
- Dangerous bypasses: router mounted before auth, `req.body`/`req.user` trust, error middleware leaking details, unbounded body/file input.
- Companions: app bootstrap, router index, middleware, validators, models, config and integration tests.
- Negative tests: missing auth, wrong owner, invalid content type, duplicate request, thrown dependency error.
- False positives: a public router is not a finding when its contract and data exposure are explicit.
- Verification: use the declared Express version and local type definitions; run focused Supertest or integration tests when available.
