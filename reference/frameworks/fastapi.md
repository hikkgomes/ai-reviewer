# FastAPI

- Entry points: routers, dependencies, background tasks, middleware and exception handlers.
- Auth/ownership: trace `Depends` order and object lookup to the route; Pydantic validation does not authorize ownership.
- Persistence: inspect async session lifetime, commit/rollback, response models and background-task boundaries.
- Dangerous bypasses: dependency omitted on one router, response model exposing fields, blocking I/O in async path, task errors discarded.
- Companions: Pydantic schemas, SQLAlchemy session dependency, settings, routers and HTTP tests.
- Negative tests: anonymous/wrong tenant, invalid schema, commit failure, cancellation and background-task failure.
- False positives: dependency overrides in tests are not production enforcement; distinguish them from application wiring.
- Verification: inspect installed FastAPI/Pydantic versions and local definitions; run focused TestClient tests when approved.
