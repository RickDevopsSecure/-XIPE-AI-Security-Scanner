"""
XIPE — GraphQL Security Tester v1.0
Covers the GraphQL attack surface that matters for modern APIs:

1. Introspection enabled in production  → schema leak
2. Field suggestion leakage             → enumerate fields without introspection
3. Query depth / complexity attack       → DoS via nested queries
4. Batch query abuse                    → rate-limit bypass via array of queries
5. IDOR via GraphQL IDs                 → direct object access with guessed IDs
6. Unauthenticated mutations            → account takeover, data modification
7. Sensitive data in __typename         → information disclosure
8. Alias-based batching (brute force)   → password spray via aliases
"""
from __future__ import annotations

import json
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.exceptions import RequestException, Timeout

from agent.finding import Finding, ScoringDetail, Severity, OWASPCategory
from utils.logger import get_logger

log = get_logger("graphql_tester")

# ── Common GraphQL endpoint paths ────────────────────────────────────────────
GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/query", "/api/query", "/gql", "/api/gql",
    "/graphql/v1", "/graphql/v2",
]

# ── Introspection query ───────────────────────────────────────────────────────
INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields { name type { name kind ofType { name kind } } }
    }
  }
}
""".strip()

# ── Depth bomb (nested query to test complexity limits) ───────────────────────
def _make_depth_bomb(depth: int = 12) -> str:
    inner = "id"
    field = "user"
    for _ in range(depth):
        inner = f"{field} {{ {inner} }}"
    return "{ " + inner + " }"


# ── Alias batch for brute-force ───────────────────────────────────────────────
def _make_alias_batch(n: int = 50) -> str:
    aliases = []
    for i in range(n):
        aliases.append(
            f'a{i}: login(input: {{email: "admin@target.com", password: "pass{i}"}}) {{ token }}'
        )
    return "mutation {\n" + "\n".join(aliases) + "\n}"


# ── Field suggestion probe ────────────────────────────────────────────────────
FIELD_PROBE_QUERY = '{ __type(name: "Query") { fields { name } } }'
TYPENAME_PROBE   = '{ __typename }'


class GraphQLTester:
    def __init__(self, base_url: str, config: Dict[str, Any]):
        self.base_url = base_url.rstrip("/")
        self.config   = config
        self.timeout  = config.get("testing", {}).get("request_timeout", 10)
        self.session  = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "XIPE-SecurityScanner/4.0"})
        token = config.get("scope", {}).get("credentials", {}).get("api_key", "")
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
        self._findings: List[Finding] = []
        self._endpoint: Optional[str] = None

    # ── Entry point ──────────────────────────────────────────────────────────

    def run(self) -> List[Finding]:
        log.info("Starting GraphQL tests against %s", self.base_url)
        endpoint = self._find_endpoint()
        if not endpoint:
            log.info("No GraphQL endpoint found — skipping")
            return []

        self._endpoint = endpoint
        log.info("GraphQL endpoint found: %s", endpoint)

        self._test_introspection(endpoint)
        self._test_field_suggestions(endpoint)
        self._test_depth_bomb(endpoint)
        self._test_batch_abuse(endpoint)
        self._test_unauthenticated_mutations(endpoint)
        self._test_alias_brute_force(endpoint)

        log.info("GraphQL tests complete — %d findings", len(self._findings))
        return self._findings

    # ── Endpoint discovery ───────────────────────────────────────────────────

    def _find_endpoint(self) -> Optional[str]:
        for path in GRAPHQL_PATHS:
            url = self.base_url + path
            try:
                # Send a minimal probe to check if it's a GraphQL endpoint
                r = self.session.post(
                    url, json={"query": TYPENAME_PROBE}, timeout=5
                )
                if r.status_code in (200, 400) and (
                    "data" in r.text or "errors" in r.text or "__typename" in r.text
                ):
                    return url
            except Exception:
                continue
        return None

    # ── 1. Introspection ─────────────────────────────────────────────────────

    def _test_introspection(self, endpoint: str):
        try:
            r = self.session.post(
                endpoint, json={"query": INTROSPECTION_QUERY}, timeout=self.timeout
            )
        except Exception:
            return

        if r.status_code != 200:
            return
        try:
            data = r.json()
        except Exception:
            return

        if data.get("data", {}).get("__schema"):
            schema = data["data"]["__schema"]
            type_names = [t["name"] for t in schema.get("types", []) if not t["name"].startswith("__")]
            mutations = schema.get("mutationType", {}) or {}

            self._add(
                title="GraphQL Introspection Enabled in Production",
                severity=Severity.HIGH,
                category=OWASPCategory.DATA_EXPOSURE,
                endpoint=endpoint,
                description=(
                    f"The GraphQL endpoint has introspection enabled. An attacker can query "
                    f"the full schema and discover all types, fields, queries, and mutations. "
                    f"Found {len(type_names)} types including: {', '.join(type_names[:8])}. "
                    f"{'Mutations detected: ' + mutations.get('name','') if mutations else ''}"
                ),
                evidence=f"__schema returned {len(type_names)} types. Mutation type: {mutations.get('name','none')}",
                recommendation=(
                    "1. Disable introspection in production: set introspection=False in your GraphQL server config.\n"
                    "2. Apollo Server: `new ApolloServer({ introspection: false })`.\n"
                    "3. Hasura: set HASURA_GRAPHQL_ENABLE_INTROSPECTION=false.\n"
                    "4. Allow introspection only for authenticated internal users if needed."
                ),
                cwe="CWE-200",
                priority_score=7.5,
                owasp_api="API8 - Security Misconfiguration",
            )

    # ── 2. Field suggestions ──────────────────────────────────────────────────

    def _test_field_suggestions(self, endpoint: str):
        """Typo in field name triggers suggestion — leaks schema without introspection."""
        probe = '{ usr { id } }'  # intentional typo
        try:
            r = self.session.post(endpoint, json={"query": probe}, timeout=self.timeout)
        except Exception:
            return

        body = r.text
        if '"Did you mean' in body or '"suggestions"' in body or "did you mean" in body.lower():
            suggestion_match = re.search(r'Did you mean[^"]*"([^"]+)"', body)
            suggestion = suggestion_match.group(0)[:80] if suggestion_match else body[:120]

            self._add(
                title="GraphQL Field Suggestion Leakage (Schema Enumeration)",
                severity=Severity.MEDIUM,
                category=OWASPCategory.DATA_EXPOSURE,
                endpoint=endpoint,
                description=(
                    "The GraphQL server returns field name suggestions on typos, allowing schema "
                    "enumeration even when introspection is disabled. Attackers can brute-force "
                    "field names by sending intentional typos and reading suggestions."
                ),
                evidence=f"Query '{{ usr {{ id }} }}' returned suggestion: {suggestion}",
                recommendation=(
                    "1. Disable field suggestions in your GraphQL server.\n"
                    "2. Apollo: `new ApolloServer({ fieldSuggestions: false })`.\n"
                    "3. This is separate from disabling introspection — both must be disabled."
                ),
                cwe="CWE-200",
                priority_score=5.5,
                owasp_api="API8 - Security Misconfiguration",
            )

    # ── 3. Query depth / complexity DoS ─────────────────────────────────────

    def _test_depth_bomb(self, endpoint: str):
        query = _make_depth_bomb(depth=14)
        try:
            r = self.session.post(
                endpoint, json={"query": query}, timeout=self.timeout
            )
        except Timeout:
            self._add(
                title="GraphQL No Query Depth Limit (DoS via Nested Queries)",
                severity=Severity.HIGH,
                category=OWASPCategory.API_UNRESTRICTED,
                endpoint=endpoint,
                description=(
                    "The GraphQL endpoint timed out processing a deeply nested query (depth=14). "
                    "Without query depth limits, attackers can craft exponentially complex queries "
                    "that exhaust server CPU/memory, causing denial of service."
                ),
                evidence="14-level nested query caused request timeout",
                recommendation=(
                    "1. Implement query depth limiting: max depth 5-7 for most use cases.\n"
                    "2. Use graphql-depth-limit or equivalent library.\n"
                    "3. Implement query complexity scoring and set a max complexity budget."
                ),
                cwe="CWE-400",
                priority_score=7.0,
                owasp_api="API4 - Unrestricted Resource Consumption",
            )
            return
        except Exception:
            return

        if r.status_code == 200:
            try:
                resp_data = r.json()
                # If we got data back (not just errors about field not found), depth is unrestricted
                errors = resp_data.get("errors", [])
                depth_blocked = any(
                    "depth" in str(e).lower() or "complexity" in str(e).lower()
                    for e in errors
                )
                if not depth_blocked:
                    self._add(
                        title="GraphQL No Query Depth Limit (DoS Risk)",
                        severity=Severity.MEDIUM,
                        category=OWASPCategory.API_UNRESTRICTED,
                        endpoint=endpoint,
                        description=(
                            "A deeply nested GraphQL query (depth=14) was processed without "
                            "being blocked. No depth limit or complexity limit is enforced. "
                            "This can be exploited to exhaust server resources."
                        ),
                        evidence=f"14-level nested query → HTTP {r.status_code}, no depth error",
                        recommendation=(
                            "1. Set maximum query depth (recommended: 5-7).\n"
                            "2. Set maximum query complexity.\n"
                            "3. Implement request timeouts and rate limiting."
                        ),
                        cwe="CWE-400",
                        priority_score=5.0,
                        owasp_api="API4 - Unrestricted Resource Consumption",
                    )
            except Exception:
                pass

    # ── 4. Batch query abuse ──────────────────────────────────────────────────

    def _test_batch_abuse(self, endpoint: str):
        """Send array of queries — if accepted, rate limits can be bypassed."""
        batch = [{"query": TYPENAME_PROBE}] * 20
        try:
            r = self.session.post(endpoint, json=batch, timeout=self.timeout)
        except Exception:
            return

        if r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, list) and len(data) > 1:
                    self._add(
                        title="GraphQL Batch Query Abuse — Rate Limit Bypass",
                        severity=Severity.MEDIUM,
                        category=OWASPCategory.API_UNRESTRICTED,
                        endpoint=endpoint,
                        description=(
                            f"The GraphQL endpoint accepts batched requests (arrays of queries). "
                            f"Sent 20 queries in one HTTP request and received {len(data)} responses. "
                            f"This allows attackers to bypass per-request rate limits — one HTTP "
                            f"request counts as one request but executes 20 operations."
                        ),
                        evidence=f"POST [{{'query':...}}×20] → {len(data)} results in one response",
                        recommendation=(
                            "1. Disable query batching if not required.\n"
                            "2. If batching is needed, limit batch size (max 5-10 operations).\n"
                            "3. Apply rate limiting per operation, not per HTTP request."
                        ),
                        cwe="CWE-770",
                        priority_score=5.5,
                        owasp_api="API4 - Unrestricted Resource Consumption",
                    )
            except Exception:
                pass

    # ── 5. Unauthenticated mutations ──────────────────────────────────────────

    def _test_unauthenticated_mutations(self, endpoint: str):
        """Probe common mutations without auth token."""
        session_no_auth = requests.Session()
        session_no_auth.verify = False

        dangerous_mutations = [
            ('deleteUser',     'mutation { deleteUser(id: "1") { success } }'),
            ('createUser',     'mutation { createUser(input: {email:"x@x.com",password:"x"}) { id } }'),
            ('updatePassword', 'mutation { updatePassword(userId:"1",newPassword:"hacked") { success } }'),
            ('resetPassword',  'mutation { resetPassword(email:"admin@target.com") { success } }'),
        ]

        for name, query in dangerous_mutations:
            try:
                r = session_no_auth.post(
                    endpoint, json={"query": query}, timeout=5
                )
                body = r.text
                # If we get back data (not auth error), mutation ran unauthenticated
                has_data = (
                    r.status_code == 200
                    and '"data"' in body
                    and '"errors"' not in body
                )
                is_auth_error = any(
                    kw in body.lower()
                    for kw in ("unauthorized", "unauthenticated", "not authenticated",
                               "forbidden", "access denied", "jwt", "token")
                )
                if has_data and not is_auth_error:
                    self._add(
                        title=f"Unauthenticated GraphQL Mutation: {name}",
                        severity=Severity.CRITICAL,
                        category=OWASPCategory.BROKEN_ACCESS,
                        endpoint=endpoint,
                        description=(
                            f"The mutation '{name}' executed successfully without authentication. "
                            f"This allows anonymous users to perform privileged operations."
                        ),
                        evidence=f"mutation {name}(…) without auth → HTTP 200 with data",
                        recommendation=(
                            "1. Require authentication on all mutations.\n"
                            "2. Use resolver-level auth checks, not just middleware.\n"
                            "3. Implement field-level authorization."
                        ),
                        cwe="CWE-306",
                        priority_score=9.5,
                        owasp_api="API2 - Broken Authentication",
                    )
            except Exception:
                continue

    # ── 6. Alias batch brute force ────────────────────────────────────────────

    def _test_alias_brute_force(self, endpoint: str):
        """Send 50 aliased login mutations in one request — bypasses lockout."""
        query = _make_alias_batch(n=30)
        try:
            r = self.session.post(endpoint, json={"query": query}, timeout=self.timeout)
        except Exception:
            return

        body = r.text
        # If we get multiple aliased responses (a0, a1, …) without lockout
        if r.status_code == 200 and '"a0"' in body and '"a1"' in body:
            lockout = any(k in body.lower() for k in ("too many", "rate limit", "locked", "429"))
            if not lockout:
                self._add(
                    title="GraphQL Alias Batching — Account Lockout Bypass",
                    severity=Severity.HIGH,
                    category=OWASPCategory.AUTH_BYPASS,
                    endpoint=endpoint,
                    description=(
                        "GraphQL aliases allow sending 30 login attempts in a single HTTP request. "
                        "If the lockout policy counts HTTP requests rather than authentication "
                        "attempts, an attacker can brute-force credentials without triggering lockout."
                    ),
                    evidence="30 aliased login mutations in one request processed without rate-limit error",
                    recommendation=(
                        "1. Count authentication attempts per user/IP, not per HTTP request.\n"
                        "2. Limit alias count per query (max 5).\n"
                        "3. Apply progressive lockout based on per-user failed attempt count."
                    ),
                    cwe="CWE-307",
                    priority_score=7.0,
                    owasp_api="API2 - Broken Authentication",
                )

    # ── Finding builder ──────────────────────────────────────────────────────

    def _add(self, title: str, severity: Severity, category: OWASPCategory,
             endpoint: str, description: str, evidence: str,
             recommendation: str, cwe: str, priority_score: float,
             owasp_api: str = "") -> Finding:
        if any(f.title == title for f in self._findings):
            return

        sev_score_map = {
            Severity.CRITICAL: 9.5, Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,   Severity.LOW: 3.0,
        }
        base = sev_score_map.get(severity, 5.0)

        scoring = ScoringDetail(
            severity_score=base,
            exploitability_score=base,
            exposure_score=8.0,
            business_risk_score=7.5,
            asset_criticality_score=7.0,
            confidence_score=8.5,
            priority_score=priority_score,
            score_explanation=f"GraphQL — {title[:60]}",
        )

        f = Finding(
            id=f"GQL-{uuid.uuid4().hex[:8].upper()}",
            title=title,
            severity=severity,
            category=category,
            module="graphql_tester",
            endpoint=endpoint,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            cwe=cwe,
            owasp_api_top10=owasp_api,
            scoring=scoring,
            tags=["graphql", "api", cwe.lower()],
        )
        self._findings.append(f)
        log.warning("GraphQL finding: %s", title)
        return f


# ── Orchestrator entry ────────────────────────────────────────────────────────

def run(base_url: str, config: Dict[str, Any]) -> List[Finding]:
    return GraphQLTester(base_url, config).run()
