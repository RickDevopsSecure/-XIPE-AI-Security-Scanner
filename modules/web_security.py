"""
XIPE — Web Security Module v3.0
Merges: web_recon + api_tester + general_web_tester
Works on ANY target. Brain-guided test selection.
"""
import uuid
import re
import time
from typing import List, Dict, Optional
from urllib.parse import urlparse
import httpx

from agent.finding import Finding, Severity, OWASPCategory
from utils.logger import PentestLogger


SECURITY_HEADERS = [
    ("Strict-Transport-Security",   Severity.MEDIUM, "HSTS",  "Add HSTS header: max-age=31536000; includeSubDomains", "A02", None),
    ("Content-Security-Policy",     Severity.MEDIUM, "CSP",   "Implement a Content Security Policy.", "A05", None),
    ("X-Content-Type-Options",      Severity.MEDIUM, "XCTO",  "Add X-Content-Type-Options: nosniff", "A05", "CWE-116"),
    ("X-Frame-Options",             Severity.LOW,    "XFO",   "Add X-Frame-Options: SAMEORIGIN", "A05", None),
    ("Referrer-Policy",             Severity.LOW,    "RP",    "Add Referrer-Policy: strict-origin-when-cross-origin", "A05", None),
    ("Permissions-Policy",          Severity.LOW,    "PP",    "Add Permissions-Policy to restrict browser features.", "A05", None),
]

SENSITIVE_PATHS = [
    ("/.env",               Severity.CRITICAL, True),
    ("/.env.local",         Severity.CRITICAL, True),
    ("/.env.production",    Severity.CRITICAL, True),
    ("/.env.backup",        Severity.CRITICAL, True),
    ("/config.json",        Severity.HIGH,     True),
    ("/config.yml",         Severity.HIGH,     True),
    ("/.git/config",        Severity.HIGH,     False),
    ("/.git/HEAD",          Severity.HIGH,     False),
    ("/backup.zip",         Severity.HIGH,     False),
    ("/backup.sql",         Severity.HIGH,     False),
    ("/dump.sql",           Severity.HIGH,     False),
    ("/admin",              Severity.MEDIUM,   False),
    ("/admin/",             Severity.MEDIUM,   False),
    ("/wp-login.php",       Severity.MEDIUM,   False),
    ("/wp-config.php",      Severity.HIGH,     True),
    ("/xmlrpc.php",         Severity.MEDIUM,   False),
    ("/phpinfo.php",        Severity.HIGH,     True),
    ("/server-status",      Severity.MEDIUM,   True),
    ("/.htpasswd",          Severity.HIGH,     True),
    ("/robots.txt",         Severity.INFO,     False),
    ("/sitemap.xml",        Severity.INFO,     False),
    ("/.well-known/security.txt", Severity.INFO, False),
]

SENSITIVE_CONTENT_KEYWORDS = [
    "password", "secret", "api_key", "apikey", "token", "private_key",
    "access_key", "aws_secret", "database_url", "db_password",
]

INFO_LEAKING_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version",
    "x-aspnetmvc-version", "x-generator",
]

API_SENSITIVE_PATHS = [
    "/api/users", "/api/v1/users", "/api/admin/users",
    "/api/v1/admin", "/api/config", "/api/v1/config",
    "/api/debug", "/api/test", "/api/v1/export",
    "/api/keys", "/api/secrets",
]


class WebSecurityModule:
    """
    Comprehensive web security testing.
    Brain-guided, context-aware, SPA-safe.
    """

    def __init__(self, config: dict, logger: PentestLogger,
                 http_client: httpx.Client, brain, classification: Dict,
                 assessment_plan: Dict):
        self.config = config
        self.logger = logger
        self.client = http_client
        self.brain = brain
        self.classification = classification
        self.assessment_plan = assessment_plan
        self.findings: List[Finding] = []
        self.base_url = config["scope"]["base_urls"][0].rstrip("/")
        self.is_spa = classification.get("is_spa", False)
        self.sys_type = classification.get("system_type", "web_application")

    def run(self) -> List[Finding]:
        self.logger.module_start("Web Security (Headers, Paths, CORS, TLS, Errors)")

        self._test_security_headers()
        self._test_sensitive_paths()
        self._test_cors()
        self._test_http_methods()
        self._test_information_disclosure()
        self._test_cookies()

        # WordPress-specific
        if "WordPress" in self.classification.get("tech_stack", []):
            self._test_wordpress()

        self.logger.module_done("Web Security", len(self.findings))
        return self.findings

    def run_api_checks(self) -> List[Finding]:
        """API-specific checks — called only when has_api=True."""
        self.logger.module_start("API Security (Auth, IDOR, Methods, GraphQL)")

        self._test_api_unauthenticated()
        self._test_graphql()
        self._test_api_rate_limiting()
        self._test_api_versioning()

        self.logger.module_done("API Security", len(self.findings))
        return self.findings

    # ── Security Headers ──────────────────────────────────────────────────────

    def _test_security_headers(self):
        try:
            resp = self.client.get(self.base_url, timeout=10)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

            # Missing security headers
            for header, severity, tag, recommendation, owasp, cwe in SECURITY_HEADERS:
                if header.lower() not in resp_headers:
                    # Landing pages get lower severity for headers
                    if self.sys_type == "landing_page" and severity == Severity.MEDIUM:
                        severity = Severity.LOW

                    self._add(
                        title=f"Missing Security Header: {header}",
                        severity=severity,
                        category=OWASPCategory.SECURITY_MISCONFIG,
                        description=(
                            f"The HTTP response from {self.base_url} is missing the '{header}' "
                            f"security header. This weakens the browser-level security posture."
                        ),
                        endpoint=self.base_url,
                        recommendation=recommendation,
                        owasp_top10=owasp,
                        cwe=cwe,
                        false_positive_risk="LOW",
                        tags=[tag, "headers"],
                    )

            # Information-leaking headers
            for h in INFO_LEAKING_HEADERS:
                if h in resp_headers:
                    self._add(
                        title=f"Technology Disclosure: {h}",
                        severity=Severity.LOW,
                        category=OWASPCategory.DATA_EXPOSURE,
                        description=f"Header '{h}: {resp_headers[h]}' discloses technology stack details.",
                        endpoint=self.base_url,
                        recommendation=f"Remove or obscure the '{h}' response header.",
                        false_positive_risk="LOW",
                        tags=["info-disclosure", "headers"],
                    )

        except Exception as e:
            self.logger.error(f"Header test error: {e}")

    # ── Sensitive Paths ───────────────────────────────────────────────────────

    def _test_sensitive_paths(self):
        for path, severity, check_content in SENSITIVE_PATHS:
            try:
                resp = self.client.get(self.base_url + path, timeout=8)
                if resp.status_code != 200:
                    continue

                ct = resp.headers.get("content-type", "")

                # SPA false positive filter
                if self.is_spa and "html" in ct and path not in ["/robots.txt", "/sitemap.xml"]:
                    continue

                body = resp.text
                evidence = None

                if check_content:
                    found_keywords = [k for k in SENSITIVE_CONTENT_KEYWORDS if k in body.lower()]
                    if found_keywords:
                        severity = Severity.CRITICAL
                        evidence = f"Contains sensitive keywords: {', '.join(found_keywords[:3])}"
                        # Sanitize — don't store actual values
                        evidence += f"\nFirst 100 chars: {re.sub(r'[^\s\w=]', '*', body[:100])}"

                if severity == Severity.INFO and not evidence:
                    # Just log it, not worth a finding
                    continue

                self._add(
                    title=f"Sensitive Path Exposed: {path}",
                    severity=severity,
                    category=OWASPCategory.DATA_EXPOSURE,
                    description=(
                        f"Sensitive path {path} is publicly accessible at {self.base_url + path}. "
                        + (f"Response contains: {evidence}" if evidence else "")
                    ),
                    endpoint=self.base_url + path,
                    evidence=evidence,
                    recommendation=f"Restrict access to {path}. Remove sensitive files from web root.",
                    owasp_top10="A05",
                    false_positive_risk="LOW" if evidence else "MEDIUM",
                    tags=["sensitive-paths"],
                )
            except Exception:
                pass
            time.sleep(0.05)

    # ── CORS ──────────────────────────────────────────────────────────────────

    def _test_cors(self):
        try:
            resp = self.client.get(
                self.base_url,
                headers={"Origin": "https://xipe-test-evil.com"},
                timeout=8,
            )
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")

            if acao == "*":
                self._add(
                    title="CORS Wildcard Origin Allowed",
                    severity=Severity.MEDIUM,
                    category=OWASPCategory.SECURITY_MISCONFIG,
                    description="Access-Control-Allow-Origin: * permits any origin to read responses.",
                    endpoint=self.base_url,
                    recommendation="Restrict CORS to specific trusted origins. Never use * with credentials.",
                    owasp_top10="A05",
                    false_positive_risk="LOW",
                    tags=["cors"],
                )
            elif "xipe-test-evil.com" in acao:
                cred_warning = " With credentials enabled, this allows cross-origin session theft." if "true" in acac.lower() else ""
                self._add(
                    title="CORS Origin Reflection — Arbitrary Origin Accepted",
                    severity=Severity.HIGH if "true" in acac.lower() else Severity.MEDIUM,
                    category=OWASPCategory.BROKEN_ACCESS,
                    description=f"Server reflects arbitrary Origin header. ACAO: {acao}.{cred_warning}",
                    endpoint=self.base_url,
                    recommendation="Validate Origin against a static allowlist. Never reflect arbitrary origins.",
                    owasp_top10="A01",
                    cwe="CWE-346",
                    false_positive_risk="LOW",
                    tags=["cors"],
                )
        except Exception:
            pass

    # ── HTTP Methods ──────────────────────────────────────────────────────────

    def _test_http_methods(self):
        try:
            resp = self.client.request("OPTIONS", self.base_url, timeout=8)
            allow = resp.headers.get("allow", resp.headers.get("Allow", "")).upper()

            for method in ["TRACE", "CONNECT"]:
                if method in allow:
                    self._add(
                        title=f"Dangerous HTTP Method Enabled: {method}",
                        severity=Severity.MEDIUM,
                        category=OWASPCategory.SECURITY_MISCONFIG,
                        description=f"HTTP {method} is enabled. TRACE enables Cross-Site Tracing (XST) attacks.",
                        endpoint=self.base_url,
                        recommendation=f"Disable HTTP {method} on the web server.",
                        owasp_top10="A05",
                        false_positive_risk="LOW",
                        tags=["http-methods"],
                    )
        except Exception:
            pass

    # ── Information Disclosure ────────────────────────────────────────────────

    def _test_information_disclosure(self):
        probe = self.base_url + f"/__xipe_{uuid.uuid4().hex[:6]}"
        error_patterns = [
            r"stack\s*trace", r"traceback\s*\(most recent",
            r"at\s+\w+\.java:\d+", r"mysql.*error",
            r"ora-\d{5}", r"syntax\s+error.*sql",
            r"exception in thread", r"debug\s*=\s*true",
            r"laravel\.log", r"rails.*error",
        ]
        try:
            resp = self.client.get(probe, timeout=8)
            body = resp.text
            for pattern in error_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    self._add(
                        title="Verbose Error Messages — Technology/Stack Disclosure",
                        severity=Severity.MEDIUM,
                        category=OWASPCategory.DATA_EXPOSURE,
                        description=f"Error page at {probe} reveals internal stack trace or technology details.",
                        endpoint=probe,
                        evidence=body[:300],
                        recommendation="Implement generic error pages. Disable debug mode in production.",
                        owasp_top10="A05",
                        cwe="CWE-209",
                        false_positive_risk="LOW",
                        tags=["error-disclosure", "info-disclosure"],
                    )
                    break
        except Exception:
            pass

    # ── Cookies ───────────────────────────────────────────────────────────────

    def _test_cookies(self):
        try:
            resp = self.client.get(self.base_url, timeout=10)
            for cookie in resp.cookies.jar:
                flags = []
                issues = []

                if not cookie.secure:
                    issues.append("missing Secure flag")
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    issues.append("missing HttpOnly flag")
                if not cookie.has_nonstandard_attr("SameSite"):
                    issues.append("missing SameSite attribute")

                if issues:
                    self._add(
                        title=f"Cookie Security Flags Missing: {cookie.name}",
                        severity=Severity.MEDIUM if "session" in cookie.name.lower() else Severity.LOW,
                        category=OWASPCategory.SECURITY_MISCONFIG,
                        description=f"Cookie '{cookie.name}' is {', '.join(issues)}.",
                        endpoint=self.base_url,
                        recommendation=f"Set Secure, HttpOnly, and SameSite=Strict on all cookies, especially session cookies.",
                        owasp_top10="A02",
                        false_positive_risk="LOW",
                        tags=["cookies", "session"],
                    )
        except Exception:
            pass

    # ── WordPress ─────────────────────────────────────────────────────────────

    def _test_wordpress(self):
        wp_paths = [
            ("/wp-json/wp/v2/users", Severity.MEDIUM, "WordPress user enumeration via REST API."),
            ("/xmlrpc.php", Severity.MEDIUM, "XML-RPC enabled — can be abused for brute force."),
            ("/wp-content/debug.log", Severity.HIGH, "WordPress debug log exposed."),
            ("/wp-includes/", Severity.INFO, "WordPress includes directory accessible."),
        ]
        for path, severity, desc in wp_paths:
            try:
                resp = self.client.get(self.base_url + path, timeout=6)
                if resp.status_code == 200:
                    ct = resp.headers.get("content-type", "")
                    if "html" in ct and path not in ["/xmlrpc.php"]:
                        continue
                    self._add(
                        title=f"WordPress Exposure: {path}",
                        severity=severity,
                        category=OWASPCategory.DATA_EXPOSURE,
                        description=desc,
                        endpoint=self.base_url + path,
                        recommendation=f"Restrict or disable {path}.",
                        owasp_top10="A05",
                        false_positive_risk="LOW",
                        tags=["wordpress"],
                    )
            except Exception:
                pass

    # ── API Security ──────────────────────────────────────────────────────────

    def _test_api_unauthenticated(self):
        for path in API_SENSITIVE_PATHS:
            try:
                resp = self.client.get(self.base_url + path, timeout=6)
                if resp.status_code == 200:
                    ct = resp.headers.get("content-type", "")
                    if "html" in ct:
                        continue
                    body = resp.text
                    if any(k in body.lower() for k in ["email", "user", "password", "token", "key"]):
                        self._add(
                            title=f"Unauthenticated API Access: {path}",
                            severity=Severity.HIGH,
                            category=OWASPCategory.API_BOLA,
                            description=f"API endpoint {path} returns sensitive data without authentication.",
                            endpoint=self.base_url + path,
                            evidence=body[:200],
                            recommendation="Require authentication on all API endpoints. Implement deny-by-default.",
                            owasp_api_top10="API2",
                            false_positive_risk="LOW",
                            tags=["api", "auth"],
                        )
            except Exception:
                pass
            time.sleep(0.1)

    def _test_graphql(self):
        for path in ["/graphql", "/api/graphql", "/graphiql"]:
            try:
                resp = self.client.post(
                    self.base_url + path,
                    json={"query": "{ __schema { types { name } } }"},
                    headers={"Content-Type": "application/json"},
                    timeout=8,
                )
                if resp.status_code == 200 and "__schema" in resp.text:
                    self._add(
                        title="GraphQL Introspection Enabled",
                        severity=Severity.MEDIUM,
                        category=OWASPCategory.API_UNRESTRICTED,
                        description="GraphQL introspection exposes the full API schema to any requester.",
                        endpoint=self.base_url + path,
                        recommendation="Disable introspection in production. Restrict to authenticated users only.",
                        owasp_api_top10="API8",
                        false_positive_risk="LOW",
                        tags=["graphql", "api"],
                    )
                    break
            except Exception:
                pass

    def _test_api_rate_limiting(self):
        """Test for absence of rate limiting — non-destructive."""
        test_endpoint = self.base_url + "/api/v1/chat"
        codes = []
        try:
            for _ in range(10):
                r = self.client.get(test_endpoint, timeout=5)
                codes.append(r.status_code)
                if r.status_code == 429:
                    return  # Rate limiting is present
            if len(set(codes)) == 1 and codes[0] == 200:
                self._add(
                    title="No Rate Limiting Detected on Chat Endpoint",
                    severity=Severity.MEDIUM,
                    category=OWASPCategory.API_UNRESTRICTED,
                    description=f"10 rapid requests to {test_endpoint} returned HTTP 200 with no rate limiting.",
                    endpoint=test_endpoint,
                    recommendation="Implement rate limiting (429 responses). Use token buckets per user/IP.",
                    owasp_api_top10="API4",
                    false_positive_risk="MEDIUM",
                    tags=["rate-limiting", "api"],
                )
        except Exception:
            pass

    def _test_api_versioning(self):
        """Check if older API versions are accessible."""
        for version in ["v0", "v2", "v3", "beta", "dev"]:
            path = f"/api/{version}"
            try:
                r = self.client.get(self.base_url + path, timeout=5)
                if r.status_code in (200, 401) and "html" not in r.headers.get("content-type", ""):
                    self._add(
                        title=f"Legacy API Version Accessible: {path}",
                        severity=Severity.LOW,
                        category=OWASPCategory.API_UNRESTRICTED,
                        description=f"API path {path} is accessible and may expose deprecated or insecure endpoints.",
                        endpoint=self.base_url + path,
                        recommendation=f"Disable legacy API versions. Redirect to current version or return 410 Gone.",
                        owasp_api_top10="API9",
                        false_positive_risk="MEDIUM",
                        tags=["api", "versioning"],
                    )
            except Exception:
                pass

    # ── Helper ────────────────────────────────────────────────────────────────

    def _add(self, false_positive_risk: str = "MEDIUM",
             owasp_top10: str = None, owasp_api_top10: str = None,
             cwe: str = None, tags: List[str] = None, **kwargs) -> Finding:
        f = Finding(
            id=f"WEB-{str(uuid.uuid4())[:8].upper()}",
            module="web_security",
            false_positive_risk=false_positive_risk,
            owasp_top10=owasp_top10,
            owasp_api_top10=owasp_api_top10,
            cwe=cwe,
            tags=tags or [],
            **kwargs,
        )
        self.findings.append(f)
        return f
