# dissect: scanner-definition
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Callable, Iterable

from .model import Finding


Matcher = Callable[[str, str], Iterable[tuple[int, str]]]


@dataclass(frozen=True)
class Rule:
    check_id: str
    category: str
    severity: str
    confidence: str
    explanation: str
    remediation: str
    matcher: Matcher
    positive_fixture: tuple[str, str]
    negative_fixture: tuple[str, str]
    disposition: str = "finding"

    def scan(self, path: str, text: str, source: str = "working-tree") -> list[Finding]:
        return [
            Finding(
                check_id=self.check_id,
                category=self.category,
                severity=self.severity,
                confidence=self.confidence,
                path=path,
                line=line,
                evidence=evidence.replace("\n", " ")[:240],
                explanation=self.explanation,
                remediation=self.remediation,
                disposition=self.disposition,
                source=source,
            )
            for line, evidence in self.matcher(path, text)
        ]


def regex_matcher(
    pattern: str,
    *,
    flags: int = re.I | re.M,
    suffixes: tuple[str, ...] = (),
    path_pattern: str = "",
) -> Matcher:
    compiled = re.compile(pattern, flags)
    path_re = re.compile(path_pattern, re.I) if path_pattern else None

    def match(path: str, text: str) -> Iterable[tuple[int, str]]:
        if suffixes and Path(path).suffix.lower() not in suffixes:
            return []
        if path_re and not path_re.search(path):
            return []
        return [
            (text.count("\n", 0, item.start()) + 1, item.group(0))
            for item in compiled.finditer(text)
        ]

    return match


def _missing_rls(path: str, text: str) -> Iterable[tuple[int, str]]:
    if Path(path).suffix.lower() != ".sql":
        return []
    findings = []
    create = re.compile(
        r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?P<name>[\w.\"-]+)\s*\((?P<body>.*?)\)\s*;",
        re.I | re.S,
    )
    for item in create.finditer(text):
        body = item.group("body")
        if not re.search(r"\b(user_id|tenant_id|account_id|email|phone|medical|ssn)\b", body, re.I):
            continue
        table = item.group("name").strip('"')
        escaped = re.escape(table)
        if re.search(rf"alter\s+table\s+(?:only\s+)?[\".]?{escaped}[\".]?\s+enable\s+row\s+level\s+security", text, re.I):
            continue
        findings.append((text.count("\n", 0, item.start()) + 1, item.group(0)[:180]))
    return findings


def _unsafe_dependencies(path: str, text: str) -> Iterable[tuple[int, str]]:
    if Path(path).name != "package.json":
        return []
    try:
        import json

        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    findings = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            if isinstance(spec, str) and re.match(r"^(?:git(?:\+[^:]+)?://|https?://|file:|link:|github:)", spec, re.I):
                marker = f'"{name}"'
                offset = text.find(marker)
                findings.append((text.count("\n", 0, max(offset, 0)) + 1, f"{name}: {spec}"))
    scripts = data.get("scripts") or {}
    for name in ("preinstall", "install", "postinstall"):
        command = scripts.get(name)
        if command and re.search(r"\b(curl|wget)\b.*(?:\||;).*\b(sh|bash|node|python)\b", command, re.I):
            offset = text.find(f'"{name}"')
            findings.append((text.count("\n", 0, max(offset, 0)) + 1, f"{name}: {command}"))
    return findings


def _missing_webhook_verification(path: str, text: str) -> Iterable[tuple[int, str]]:
    if not re.search(r"webhook", path, re.I):
        return []
    if not re.search(r"\b(stripe|payment|checkout|event)\b", text, re.I):
        return []
    if re.search(r"(constructEvent|verifyWebhook|verifySignature|webhooks\.unwrap)", text):
        return []
    handler = re.search(r"(?:export\s+)?(?:async\s+)?(?:function\s+)?(?:POST|webhook|handler)\b", text, re.I)
    if not handler:
        return []
    return [(text.count("\n", 0, handler.start()) + 1, handler.group(0))]


def _ui_only_auth(path: str, text: str) -> Iterable[tuple[int, str]]:
    if Path(path).suffix.lower() not in {".js", ".jsx", ".ts", ".tsx"}:
        return []
    pattern = re.compile(
        r"(?:localStorage|sessionStorage)\.getItem\(['\"](?:token|isAdmin|role)['\"]\)"
        r"(?:(?!fetch\(|axios\.|server).){0,500}(?:<Admin|navigate\(['\"]/admin|return\s+.*admin)",
        re.I | re.S,
    )
    return [(text.count("\n", 0, m.start()) + 1, m.group(0)) for m in pattern.finditer(text)]


def _unprotected_sensitive_route(path: str, text: str) -> Iterable[tuple[int, str]]:
    pattern = re.compile(
        r"\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*"
        r"['\"]/(?:admin|debug|internal|dev|test)(?:/[^'\"]*)?['\"]\s*,\s*"
        r"(?:async\s*)?\(\s*(?:req|request)\s*,",
        re.I,
    )
    return [(text.count("\n", 0, m.start()) + 1, m.group(0)) for m in pattern.finditer(text)]


def _idor_candidate(path: str, text: str) -> Iterable[tuple[int, str]]:
    pattern = re.compile(
        r"\b(?:findUnique|findByPk|findOne|update|delete)\s*\(\s*(?:\{\s*)?"
        r"(?:where\s*:\s*\{\s*)?id\s*:\s*(?:req|request)\.params\.id"
        r"(?:(?!userId|tenantId|ownerId|accountId).){0,160}[}\)]",
        re.I | re.S,
    )
    return [(text.count("\n", 0, m.start()) + 1, m.group(0)) for m in pattern.finditer(text)]


RULES = (
    Rule(
        "SEC-SECRETS-001",
        "secrets",
        "critical",
        "high",
        "A privileged server/service-role credential is referenced by browser-delivered code.",
        "Move the privileged operation and credential to a server boundary; rotate exposed credentials.",
        regex_matcher(
            r"(?:NEXT_PUBLIC|VITE|PUBLIC|REACT_APP)[A-Z0-9_]*(?:SERVICE_ROLE|SECRET|PRIVATE_KEY)[A-Z0-9_]*"
            r"|SUPABASE_SERVICE_ROLE_KEY",
            suffixes=(".js", ".jsx", ".ts", ".tsx", ".map"),
        ),
        ("src/client.ts", "const key = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY"),
        ("src/client.ts", "const key = import.meta.env.VITE_SUPABASE_ANON_KEY"),
    ),
    Rule(
        "SEC-SECRETS-002",
        "secrets",
        "critical",
        "high",
        "A credential with a privileged provider-specific shape is present in text.",
        "Remove and rotate the credential; use a server-side secret store and scan history.",
        regex_matcher(r"\b(?:sk_live_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,})\b"),
        ("config/env.ts", 'const key = "sk_live_1234567890abcdefghij"'),
        ("config/env.example", 'const key = "sk_test_placeholder"'),
    ),
    Rule(
        "SEC-SECRETS-003",
        "secrets",
        "high",
        "medium",
        "A secret-labelled setting contains a long non-placeholder literal.",
        "Confirm the credential, remove it from source, rotate it, and use an approved secret store.",
        regex_matcher(
            r"\b(?:password|client_secret|api_key|access_token)\b\s*[:=]\s*['\"]"
            r"(?!placeholder|example|changeme|dummy|test)[A-Za-z0-9_./+=-]{20,}['\"]"
        ),
        (".env", "API_KEY='m9A2kL7qP4xN8vR5tY1uC6wZ'"),
        (".env.example", "API_KEY='placeholder'"),
    ),
    Rule(
        "SEC-AUTHN-001",
        "authentication",
        "high",
        "medium",
        "A sensitive UI is gated by browser-controlled state; this is not server authentication.",
        "Enforce session validation and authorisation on the server endpoint as well as in the UI.",
        _ui_only_auth,
        ("src/Admin.tsx", "const ok=localStorage.getItem('isAdmin'); if(ok) return <Admin />;"),
        ("src/Admin.tsx", "const user = await server.requireAdmin(request); return <Admin />;"),
        "review-candidate",
    ),
    Rule(
        "SEC-AUTHZ-001",
        "authorization",
        "high",
        "medium",
        "A data operation appears to use a client-controlled object ID without an ownership/tenant predicate.",
        "Bind the query to the authenticated owner/tenant and add a denied-access test.",
        _idor_candidate,
        ("api/user.ts", "return db.user.findUnique({where:{id:req.params.id}});"),
        ("api/user.ts", "return db.user.findUnique({where:{id:req.params.id,userId:req.user.id}});"),
        "review-candidate",
    ),
    Rule(
        "SEC-DATABASE-001",
        "database",
        "high",
        "high",
        "A row-security policy uses an unconditional true predicate.",
        "Replace the predicate with authenticated user/tenant ownership constraints and test every operation.",
        regex_matcher(r"create\s+policy\b.*?\b(?:using|with\s+check)\s*\(\s*true\s*\)", flags=re.I | re.S, suffixes=(".sql",)),
        ("supabase/migrations/1.sql", "create policy open on documents for select using (true);"),
        ("supabase/migrations/1.sql", "create policy own on documents using (auth.uid() = user_id);"),
    ),
    Rule(
        "SEC-DATABASE-002",
        "database",
        "high",
        "medium",
        "A SQL migration creates a table with ownership/sensitive columns without enabling RLS in available evidence.",
        "Enable RLS and add operation-specific ownership/tenant policies, or document equivalent controls.",
        _missing_rls,
        ("supabase/migrations/1.sql", "create table documents (id uuid, user_id uuid, body text);"),
        ("supabase/migrations/1.sql", "create table documents (id uuid, user_id uuid); alter table documents enable row level security;"),
        "review-candidate",
    ),
    Rule(
        "SEC-ROUTES-001",
        "routes",
        "high",
        "medium",
        "A sensitive Express-style route directly installs a handler without route-level middleware. Global protection still needs review.",
        "Verify effective server-side authentication/authorisation and add a denied direct-request test.",
        _unprotected_sensitive_route,
        ("server/routes.ts", "app.get('/admin', async (req, res) => res.json(await allUsers()));"),
        ("server/routes.ts", "app.get('/admin', requireAdmin, async (req, res) => res.json([]));"),
        "review-candidate",
    ),
    Rule(
        "SEC-BROWSER-001",
        "browser-transport",
        "critical",
        "high",
        "Credentialed CORS is configured with a wildcard origin.",
        "Allow only explicit trusted origins and validate the effective proxy/framework configuration.",
        regex_matcher(
            r"(?:origin\s*:\s*['\"]\*['\"](?:(?!\n\n).){0,180}credentials\s*:\s*true"
            r"|credentials\s*:\s*true(?:(?!\n\n).){0,180}origin\s*:\s*['\"]\*['\"])",
            flags=re.I | re.S,
        ),
        ("server/cors.ts", "cors({ origin: '*', credentials: true })"),
        ("server/cors.ts", "cors({ origin: ['https://app.example.com'], credentials: true })"),
    ),
    Rule(
        "SEC-BROWSER-002",
        "browser-transport",
        "high",
        "high",
        "TLS certificate verification is explicitly disabled.",
        "Restore certificate verification; install the correct CA chain for private services.",
        regex_matcher(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
        ("client.py", "requests.get(url, verify=False)"),
        ("client.py", "requests.get(url, verify=True)"),
    ),
    Rule(
        "SEC-PAYMENTS-001",
        "payments",
        "critical",
        "medium",
        "A payment amount appears to flow directly from the client request into provider parameters.",
        "Resolve price, currency, product, and discounts from trusted server-side data and validate them.",
        regex_matcher(
            r"(?:amount|unit_amount)\s*:\s*(?:req|request)\.(?:body|json\(\))[\w.()\[\]'\"-]*(?:amount|price)",
            suffixes=(".js", ".jsx", ".ts", ".tsx"),
        ),
        ("api/checkout.ts", "stripe.paymentIntents.create({amount: req.body.amount})"),
        ("api/checkout.ts", "stripe.paymentIntents.create({amount: product.priceInCents})"),
    ),
    Rule(
        "SEC-PAYMENTS-002",
        "payments",
        "critical",
        "medium",
        "A payment webhook handler has no signature-verification call in the available file.",
        "Verify the provider signature using the raw body before parsing or processing the event.",
        _missing_webhook_verification,
        ("api/stripe-webhook.ts", "export async function POST(req) { const event = await req.json(); return processPayment(event); }"),
        ("api/stripe-webhook.ts", "export async function POST(req) { const event = stripe.webhooks.constructEvent(await req.text(), sig, secret); }"),
        "review-candidate",
    ),
    Rule(
        "SEC-DATA-001",
        "sensitive-data",
        "high",
        "high",
        "A logging call includes a secret, token, password, health, or payment value.",
        "Remove or redact sensitive fields and test logging/telemetry serializers.",
        regex_matcher(r"(?:console\.log|logger\.(?:debug|info|warn|error)|print)\s*\([^)\n]*(?:token|secret|password|ssn|medical|cardNumber|bankAccount)", flags=re.I),
        ("api/login.ts", "logger.info('login', { token: session.token })"),
        ("api/login.ts", "logger.info('login completed', { requestId })"),
    ),
    Rule(
        "SEC-DEPLOY-001",
        "deployment",
        "high",
        "medium",
        "A storage/deployment resource is explicitly public or an internal deployment is configured as indexable.",
        "Require access control for sensitive resources; use noindex only as a discoverability supplement.",
        regex_matcher(
            r"(?:public\s*[:=]\s*true|isPublic\s*=\s*true|index\s*[:=]\s*true)",
            path_pattern=r"(?:deploy|hosting|storage|bucket|vercel|netlify|robots|infra)",
        ),
        ("infra/storage.tf", "public = true"),
        ("infra/storage.tf", "public = false"),
        "review-candidate",
    ),
    Rule(
        "SUP-DEPENDENCY-001",
        "supply-chain",
        "high",
        "high",
        "A dependency bypasses the normal registry/lockfile trust path or an install hook downloads and executes code.",
        "Pin an audited registry release and integrity lock, or document and verify the trusted source/commit.",
        _unsafe_dependencies,
        ("package.json", '{"dependencies":{"colors":"git://example.invalid/colors.git"}}'),
        ("package.json", '{"dependencies":{"colors":"1.4.0"}}'),
    ),
    Rule(
        "OPS-DESTRUCTIVE-001",
        "destructive-actions",
        "critical",
        "high",
        "A broad destructive command or infrastructure deletion flag is present.",
        "Narrow the target and add environment isolation, dry-run/approval, audit, and recovery controls.",
        regex_matcher(
            r"\brm\s+-rf\s+(?:/|\$HOME|~|\*|\$\{?[\w]+\}?/?\*)\b"
            r"|terraform\s+destroy\s+-auto-approve"
            r"|force_destroy\s*=\s*true"
            r"|DROP\s+(?:DATABASE|SCHEMA)\b",
            flags=re.I,
        ),
        ("scripts/reset.sh", "rm -rf $HOME/*"),
        ("scripts/reset.sh", "rm -rf ./tmp/test-fixture"),
    ),
)


def validate_rule_fixtures() -> list[str]:
    errors = []
    for rule in RULES:
        positive_path, positive_text = rule.positive_fixture
        negative_path, negative_text = rule.negative_fixture
        if not rule.scan(positive_path, positive_text):
            errors.append(f"{rule.check_id}: positive fixture did not match")
        if rule.scan(negative_path, negative_text):
            errors.append(f"{rule.check_id}: negative fixture matched")
    return errors
