# Evidence-First Check Families

This file is the canonical catalog of Dissect review domains. The six layers in
`methodology.md` remain the reasoning model; these families make coverage
explicit and stable.

## Evidence states

Every applicable family ends in exactly one state:

- **Finding** — concrete evidence demonstrates a problem.
- **Checked** — sufficient evidence was inspected and no problem was found.
- **Not applicable** — the technology or control is absent.
- **Not verified** — runtime access, configuration, credentials, or operational
  evidence is missing.

`Not verified` never means safe. Missing evidence alone is not a vulnerability.
Automated candidates must be confirmed against surrounding code before they are
reported as semantic findings.

## SEC-SECRETS — Secrets and credentials

- Layers: 3, 4, 5
- Inspect source, frontend code, generated bundles/source maps, environment and
  deployment files, tests/fixtures/examples, logs/telemetry, CI, and Git history
  when enabled.
- Separate placeholders and intentionally public identifiers from credible
  privileged credentials. Supabase anonymous keys are not service-role keys.
- A server-only or service-role credential exposed to browser code is Critical.
- History and generated-output scanning are optional and must be recorded.

## SEC-AUTHN — Authentication

- Layers: 1, 4, 5, 6
- Verify authentication at every server boundary, including sensitive routes,
  direct API access, sessions, revocation/expiry, client-provided identity/role/
  tenant claims, and production development bypasses.
- Hidden UI and login screens are not authentication evidence.
- Reject trivial identity claims such as accepting any submitted email without
  identity verification.

## SEC-AUTHZ — Authorisation and tenant isolation

- Layers: 1, 2, 4, 5, 6
- Trace object ownership, tenant/account/organisation boundaries, roles,
  horizontal and vertical escalation, admin replacement/removal, exports/bulk
  operations, server actions, RPC, GraphQL, jobs, and middleware bypasses.
- Require practical negative tests for denied access.

## SEC-DATABASE — Database security and row security

- Layers: 2, 3, 4, 5, 6
- For Supabase, identify sensitive tables, verify RLS and policies for SELECT,
  INSERT, UPDATE, DELETE, ownership/tenant predicates, views/functions/RPC and
  service-role bypasses. Unconditional policies are suspicious.
- Distinguish the intended-public anonymous key from the privileged service-role
  key; browser exposure of the latter is Critical.
- Apply equivalent ownership and least-privilege checks to SQL and ORMs.
- When deployed schema/policy state is absent, mark it Not verified.

## SEC-ROUTES — Route and administrative-surface exposure

- Layers: 1, 4, 5
- Inventory routes using framework conventions. Review admin, debug, internal,
  dev, test, diagnostic, console, dashboard, health, temporary, and undocumented
  server-action surfaces.
- Check health endpoints for excessive disclosure and temporary APIs for
  accidental production enablement.
- Verify removal, production disablement, network restriction, or server-side
  authorisation. A suspicious name alone is only a candidate.

## SEC-BROWSER — CORS, browser, and transport security

- Layers: 3, 4, 5
- Review effective framework/proxy/hosting configuration for wildcard/reflected
  origins, credentialed CORS, TLS verification, CSP and security headers,
  redirects, shared caching, cookie attributes, and private browser data.

## SEC-PAYMENTS — Payments

- Layers: 1, 2, 3, 4, 5, 6
- Verify server-derived price/amount/currency/product/discount, raw-body webhook
  signature verification, expected account/object/value checks, idempotency,
  server-side success confirmation, environment separation, and authorised/
  audited refunds, credits, balances, and entitlements.
- Escalate exploitable payment failures quickly to High or Critical.

## SEC-DATA — Sensitive data and PII

- Layers: 1, 4, 5, 6
- Trace health, financial, identity/contact, support/chat, internal strategy,
  sales/advertising/cargo/operational, token, and session data through ingress,
  storage, response, logs, exports, retention, and deletion.
- Review access/tenant controls, redaction, response minimisation, public files/
  buckets, telemetry, retention, and realistic fixtures.
- Never infer regulatory compliance from source review.

## SEC-DEPLOY — Public deployment and discoverability

- Layers: 1, 4, 5
- Review hosting privacy defaults, previews/staging/internal environments,
  platform subdomains, indexing/sitemaps, public storage/static data, and URLs
  embedded in code/docs.
- `robots.txt` and `noindex` affect discovery, not access control.
- Runtime reachability is Not verified without an explicitly approved target.

## SUP-DEPENDENCY — Dependency and supply-chain integrity

- Layers: 3, 5, 6
- Check undeclared/slopsquatted packages, lockfile consistency, Git/local/
  untrusted-registry dependencies, install scripts, supported vulnerability
  audits, abandoned or surprising security-sensitive packages, version/API
  mismatch, and unused AI-added dependencies.
- Use official metadata or installed tools; never invent vulnerability claims.

## OPS-OBSERVABILITY — Error tracking and observability

- Layers: 2, 5, 6
- Review production exception capture, operational signals/alerts, correlation
  IDs, useful but redacted logs, job/webhook failures, production initialisation,
  and secure source-map handling. Evaluate capability, not vendor.

## OPS-RECOVERY — Backups and recovery

- Layers: 4, 5, 6
- Separate backup configuration from operational proof. Review retention,
  environment/account separation, encryption/access, independent deletion
  authority, restore docs/automation, restore-test evidence, and documented RPO/
  RTO.
- Configuration without restore evidence is Not verified, not automatically a
  finding.

## OPS-DESTRUCTIVE — Destructive actions and agent permissions

- Layers: 1, 2, 4, 5, 6
- Review production DB/schema/storage/backup/account/tenant/admin deletion,
  recursive deletion, infrastructure teardown, and wildcard permissions.
- Check least privilege, isolation, explicit target, confirmation/approval,
  dry-run, transactionality, audit, rollback, limits, and separation between
  primary and recovery credentials. Include CI, coding agents, and MCP/tools.

## GOV-REGRESSION — Silent rewrites and regression protection

- Layers: 1, 5, 6
- Compare changes with the stated request. Detect unrelated files, replaced
  behavior, rewritten generated assets, unexplained configuration, formatting
  churn, and removed/weakened tests.
- For critical UI pages, assess screenshot or visual-regression coverage without
  mandating a framework.
- Optional evidence source: anti-slop diagnostics can identify structural
  low-evidence patterns in JavaScript, TypeScript, Python, Go, Rust, C, C++,
  Java, and C#. Treat every match as a candidate and verify it against the
  affected contract.

## GOV-AUDIT — Governance, auditability, and shadow deployment

- Layers: 1, 4, 5
- Review evidence of bypassed review, missing production CI security checks,
  uncontrolled deployment branches/accounts, unclear ownership, unreviewed
  AI-generated infrastructure, missing privileged/deployment audit trails,
  prototype/preview production use, and unapproved agent publishing.
- Report supported organisational risks separately from vulnerabilities.

## ABUSE-BRAND — Phishing and brand impersonation

- Layers: 1, 4, 5
- Review unrelated-brand login/payment impersonation, third-party credential
  collection, misleading origin/ownership, and captured credentials sent to
  unrelated endpoints.
- Legitimate integrations and demos are not findings. When intent cannot be
  determined, use Not verified and state the needed context.

## Adding a family

Add it here once, assign a stable ID and layer mapping, then update the coverage
ledger template. Do not paste methodology into adapters: run
`python3 scripts/sync_adapters.py` to regenerate their bounded canonical blocks.
