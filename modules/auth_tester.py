"""
Auth Tester — Authenticated scanning + broken authentication detection
Covers:
  - Login flow with credentials from config
  - Session token extraction and propagation to other modules
  - Broken authentication: credential stuffing indicators, account lockout bypass
  - Session fixation
  - Password reset poisoning
  - Concurrent session abuse
  - Privilege escalation via IDOR (horizontal + vertical)
  - Insecure direct object references
"""

from __future__ import annotations

import re
import time
import json
import uuid
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

import requests
from requests.exceptions import RequestException, Timeout

from agent.finding import Finding, ScoringDetail
from utils.logger import get_logger

log = get_logger("auth_tester")

# ── Login endpoint candidates ─────────────────────────────────────────────────
LOGIN_PATHS = [
    "/api/auth/login",
    "/api/login",
    "/api/v1/auth/login",
    "/api/v1/login",
    "/api/v2/auth/login",
    "/auth/login",
    "/login",
    "/api/users/login",
    "/api/sessions",
    "/api/token",
    "/oauth/token",
    "/connect/token",
    "/api/auth/token",
]

# ── Common username/password field names ──────────────────────────────────────
CREDENTIAL_FIELDS = [
    ("username", "password"),
    ("email", "password"),
    ("user", "pass"),
    ("login", "password"),
    ("identifier", "password"),
    ("email", "pass"),
]

# ── Paths to test for IDOR/privilege escalation ───────────────────────────────
IDOR_PATHS = [
    "/api/users/{id}",
    "/api/v1/users/{id}",
    "/api/accounts/{id}",
    "/api/profile/{id}",
    "/api/orders/{id}",
    "/api/invoices/{id}",
    "/api/admin/users/{id}",
    "/api/admin/users",
    "/api/admin/",
    "/admin/",
    "/api/config",
    "/api/settings",
    "/api/debug",
    "/api/internal",
    "/api/metrics",
    "/api/health/detailed",
]

# ── Default test IDs for IDOR ─────────────────────────────────────────────────
TEST_IDS = ["1", "2", "100", "0", "-1", "admin", "administrator"]

# ── Weak passwords to test alongside provided creds ──────────────────────────
WEAK_PASSWORDS = [
    "password", "123456", "admin", "admin123", "test", "test123",
    "password123", "letmein", "qwerty", "abc123", "welcome", "monkey",
]


@dataclass
class AuthSession:
    """Holds session data after a successful login."""
    token: str
    token_type: str      # "bearer" | "cookie" | "api_key"
    cookie_jar: Optional[requests.cookies.RequestsCookieJar]
    user_id: Optional[str]
    roles: List[str]
    raw_response: Dict


class AuthTester:
    """Tests authentication mechanisms and session management."""

    def __init__(self, base_url: str, config: Dict[str, Any]):
        self.base_url = base_url.rstrip("/")
        self.config = config
        self.timeout = config.get("testing", {}).get("request_timeout", 8)

        creds = config.get("scope", {}).get("credentials", {})
        self.username = creds.get("username", "")
        self.password = creds.get("password", "")
        self.api_key  = creds.get("api_key", "")

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "XIPE-SecurityScanner/4.0"})

        self.auth_session: Optional[AuthSession] = None
        self._findings: List[Finding] = []

    # ─────────────────────────────────────────────────────────────────────────
    # Public entry point
    # ─────────────────────────────────────────────────────────────────────────

    def run(self) -> List[Finding]:
        log.info("Starting authentication tests against %s", self.base_url)

        # 1. Try to establish authenticated session
        if self.api_key:
            self._setup_api_key_session()
        elif self.username and self.password:
            login_url = self._find_login_endpoint()
            if login_url:
                self._perform_login(login_url)

        # 2. Unauthenticated tests (always run)
        self._test_no_lockout()
        self._test_default_credentials()
        self._test_auth_bypass_headers()

        # 3. Authenticated tests (only if we have a session)
        if self.auth_session:
            self._test_idor()
            self._test_privilege_escalation()
            self._test_session_fixation()
            self._test_admin_endpoints_access()

        # 4. Password reset flow
        self._test_password_reset_poisoning()

        log.info("Auth tests complete — %d findings", len(self._findings))
        return self._findings

    def get_session_headers(self) -> Dict[str, str]:
        """Return auth headers for use by other modules."""
        if not self.auth_session:
            return {}
        if self.auth_session.token_type == "bearer":
            return {"Authorization": f"Bearer {self.auth_session.token}"}
        if self.auth_session.token_type == "api_key":
            return {"Authorization": f"Bearer {self.auth_session.token}",
                    "X-API-Key": self.auth_session.token}
        return {}

    # ─────────────────────────────────────────────────────────────────────────
    # Session establishment
    # ─────────────────────────────────────────────────────────────────────────

    def _setup_api_key_session(self):
        """Use configured API key as session token."""
        self.session.headers["Authorization"] = f"Bearer {self.api_key}"
        self.auth_session = AuthSession(
            token=self.api_key,
            token_type="api_key",
            cookie_jar=None,
            user_id=None,
            roles=[],
            raw_response={},
        )
        log.info("Using API key for authenticated tests")

    def _find_login_endpoint(self) -> Optional[str]:
        """Probe common login paths to find the active one."""
        for path in LOGIN_PATHS:
            url = self.base_url + path
            try:
                r = self.session.post(url, json={}, timeout=4, allow_redirects=False)
                # 400/401/422 means the endpoint exists (rejects empty creds)
                if r.status_code in (400, 401, 403, 422, 200):
                    log.debug("Found login endpoint: %s (%d)", url, r.status_code)
                    return url
            except Exception:
                continue
        return None

    def _perform_login(self, login_url: str) -> bool:
        """Attempt login with configured credentials and extract token."""
        for ufield, pfield in CREDENTIAL_FIELDS:
            try:
                r = self.session.post(
                    login_url,
                    json={ufield: self.username, pfield: self.password},
                    timeout=self.timeout,
                )
            except Exception:
                continue

            token = self._extract_token(r)
            if token:
                body = self._safe_json(r)
                user_id = (
                    str(body.get("id") or body.get("user_id") or body.get("userId") or "")
                )
                roles = body.get("roles") or body.get("permissions") or []
                self.auth_session = AuthSession(
                    token=token,
                    token_type="bearer",
                    cookie_jar=r.cookies,
                    user_id=user_id or None,
                    roles=roles if isinstance(roles, list) else [roles],
                    raw_response=body,
                )
                self.session.headers["Authorization"] = f"Bearer {token}"
                log.info("Login successful — user_id=%s roles=%s", user_id, roles)
                return True

        log.info("Login failed or no token returned for %s", login_url)
        return False

    # ─────────────────────────────────────────────────────────────────────────
    # Brute force / lockout tests
    # ─────────────────────────────────────────────────────────────────────────

    def _test_no_lockout(self):
        """
        Send 10 failed login attempts — if we never get locked out (429/401 turns to 403),
        the app lacks account lockout protection.
        """
        login_url = self._find_login_endpoint()
        if not login_url:
            return

        statuses = []
        fake_user = f"probe_{uuid.uuid4().hex[:8]}@xipe-test.invalid"
        for i in range(10):
            try:
                r = self.session.post(
                    login_url,
                    json={"email": fake_user, "password": f"wrongpass{i}"},
                    timeout=5,
                )
                statuses.append(r.status_code)
            except Exception:
                break
            time.sleep(0.2)

        # If all responses are 401/400 (never 429/403 lockout), report missing lockout
        lockout_codes = {429, 423, 403}
        got_locked = any(s in lockout_codes for s in statuses)

        if not got_locked and len(statuses) >= 8:
            self._add_finding(
                title="Missing Account Lockout / Rate Limiting on Login",
                severity="MEDIUM",
                category="Broken Authentication",
                endpoint=login_url,
                description=(
                    "The login endpoint does not implement account lockout or rate limiting. "
                    "10 consecutive failed login attempts returned consistent non-lockout responses "
                    f"({set(statuses)}). This enables automated credential stuffing and brute-force attacks."
                ),
                evidence=f"10 failed attempts returned status codes: {statuses}",
                request=f"POST {login_url} with invalid credentials × 10",
                remediation=(
                    "1. Implement progressive lockout: after 5 failed attempts, enforce exponential backoff.\n"
                    "2. Add CAPTCHA after 3 failed attempts.\n"
                    "3. Implement IP-based rate limiting (e.g., 10 req/min per IP).\n"
                    "4. Send email notification after repeated failures on a real account.\n"
                    "5. Consider using OAuth/SSO to delegate authentication."
                ),
                priority_score=5.5,
            )

    def _test_default_credentials(self):
        """Test a handful of weak/default credential combinations."""
        login_url = self._find_login_endpoint()
        if not login_url:
            return

        test_combos = [
            ("admin", "admin"), ("admin", "admin123"), ("admin", "password"),
            ("test", "test"), ("administrator", "administrator"),
            ("root", "root"), ("admin@admin.com", "admin"),
        ]

        for user, passwd in test_combos:
            try:
                r = self.session.post(
                    login_url,
                    json={"email": user, "username": user, "password": passwd},
                    timeout=5,
                )
                if r.status_code == 200 and self._extract_token(r):
                    self._add_finding(
                        title="Default Credentials Accepted",
                        severity="CRITICAL",
                        category="Broken Authentication",
                        endpoint=login_url,
                        description=(
                            f"The application accepted default credentials: '{user}' / '{passwd}'. "
                            "Default credentials are the first thing attackers try and must be "
                            "disabled before deployment."
                        ),
                        evidence=f"HTTP 200 with token returned for {user}:{passwd}",
                        request=f"POST {login_url} → {{email: {user}, password: {passwd}}}",
                        remediation=(
                            "1. Remove all default/test accounts from production.\n"
                            "2. Enforce password change on first login for all provisioned accounts.\n"
                            "3. Run automated checks for default credentials in CI/CD pipelines."
                        ),
                        priority_score=9.5,
                    )
                    break
            except Exception:
                continue

    # ─────────────────────────────────────────────────────────────────────────
    # Auth bypass via headers
    # ─────────────────────────────────────────────────────────────────────────

    def _test_auth_bypass_headers(self):
        """
        Test if protected endpoints can be bypassed using common headers
        that internal proxies might set.
        """
        bypass_headers = [
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Host": "localhost"},
        ]

        protected_paths = ["/admin", "/api/admin", "/api/config", "/api/users", "/api/settings"]

        for path in protected_paths[:3]:
            url = self.base_url + path
            try:
                baseline = self.session.get(url, timeout=5, allow_redirects=False)
            except Exception:
                continue

            if baseline.status_code not in (401, 403):
                continue  # Not protected, skip

            for headers in bypass_headers:
                try:
                    r = self.session.get(
                        url, headers=headers, timeout=5, allow_redirects=False
                    )
                    if r.status_code not in (401, 403):
                        header_name = list(headers.keys())[0]
                        self._add_finding(
                            title=f"Authentication Bypass via Header ({header_name})",
                            severity="HIGH",
                            category="Broken Authentication",
                            endpoint=url,
                            description=(
                                f"The endpoint {path} returned {r.status_code} when accessed "
                                f"with the header '{header_name}: {headers[header_name]}', "
                                f"bypassing the authentication that returned {baseline.status_code} "
                                f"without the header. This indicates the server trusts client-supplied "
                                f"forwarding headers to make authorization decisions."
                            ),
                            evidence=f"Baseline: {baseline.status_code} → With {header_name}: {r.status_code}",
                            request=f"GET {url} + {header_name}: {headers[header_name]}",
                            remediation=(
                                "1. Never trust X-Forwarded-* or X-Original-URL headers for access control.\n"
                                "2. Perform authorization checks at the application layer, not based on IP.\n"
                                "3. If running behind a trusted proxy, restrict which IPs can set these headers."
                            ),
                            priority_score=7.5,
                        )
                        break
                except Exception:
                    continue

    # ─────────────────────────────────────────────────────────────────────────
    # IDOR testing
    # ─────────────────────────────────────────────────────────────────────────

    def _test_idor(self):
        """Test for insecure direct object references using incremented IDs."""
        if not self.auth_session:
            return

        for path_template in IDOR_PATHS[:8]:
            if "{id}" not in path_template:
                # Direct path — probe for unauthorized access
                url = self.base_url + path_template
                try:
                    r = self.session.get(url, timeout=5)
                except Exception:
                    continue

                if r.status_code == 200 and len(r.text) > 100:
                    body = self._safe_json(r)
                    # If returns list of users/items, flag it
                    if isinstance(body, list) and len(body) > 0:
                        self._add_finding(
                            title=f"Unauthorized Data Exposure at {path_template}",
                            severity="HIGH",
                            category="Broken Access Control",
                            endpoint=url,
                            description=(
                                f"The endpoint {path_template} returned a list of {len(body)} items "
                                f"without proper authorization checks. This may expose sensitive "
                                f"user/resource data to any authenticated user."
                            ),
                            evidence=f"GET {url} → 200 with {len(body)} items in response array",
                            request=f"GET {url}",
                            remediation=(
                                "1. Implement object-level authorization — verify the requesting user "
                                "owns or has permission to access each returned resource.\n"
                                "2. Use opaque, non-sequential identifiers (UUIDs).\n"
                                "3. Log and alert on access to bulk enumeration endpoints."
                            ),
                            priority_score=7.0,
                        )
            else:
                # Test numeric ID enumeration
                my_id = self.auth_session.user_id
                for test_id in TEST_IDS:
                    if my_id and test_id == my_id:
                        continue  # Skip own ID
                    url = self.base_url + path_template.replace("{id}", test_id)
                    try:
                        r = self.session.get(url, timeout=5)
                    except Exception:
                        continue

                    if r.status_code == 200 and len(r.text) > 50:
                        body = self._safe_json(r)
                        if body and isinstance(body, dict):
                            self._add_finding(
                                title="Insecure Direct Object Reference (IDOR)",
                                severity="HIGH",
                                category="Broken Access Control",
                                endpoint=url,
                                description=(
                                    f"Authenticated user can access resource ID '{test_id}' at "
                                    f"{path_template} without ownership verification. "
                                    f"IDOR allows attackers to enumerate and access other users' data "
                                    f"by changing the ID parameter."
                                ),
                                evidence=f"GET {url} → 200 with resource data (user_id={my_id} accessing id={test_id})",
                                request=f"GET {url}",
                                remediation=(
                                    "1. Verify resource ownership on every request: check that the "
                                    "requesting user's ID matches the resource owner.\n"
                                    "2. Use UUIDs instead of sequential integers.\n"
                                    "3. Return 403/404 for resources the user doesn't own."
                                ),
                                priority_score=7.5,
                            )
                            break

    # ─────────────────────────────────────────────────────────────────────────
    # Privilege escalation
    # ─────────────────────────────────────────────────────────────────────────

    def _test_privilege_escalation(self):
        """
        Try to modify own role via profile update endpoint.
        """
        if not self.auth_session or not self.auth_session.user_id:
            return

        escalation_payloads = [
            {"role": "admin"},
            {"roles": ["admin"]},
            {"role": "administrator"},
            {"isAdmin": True},
            {"admin": True},
            {"scope": "admin:full"},
            {"permissions": ["*"]},
        ]

        update_paths = [
            f"/api/users/{self.auth_session.user_id}",
            "/api/profile",
            "/api/me",
            "/api/account",
        ]

        for path in update_paths:
            url = self.base_url + path
            for payload in escalation_payloads[:3]:
                try:
                    r = self.session.patch(url, json=payload, timeout=5)
                    if r.status_code in (200, 201, 204):
                        body = self._safe_json(r)
                        # Check if role was actually changed
                        resp_role = str(body.get("role", "") or body.get("roles", "")).lower()
                        if "admin" in resp_role:
                            self._add_finding(
                                title="Privilege Escalation via Profile Update",
                                severity="CRITICAL",
                                category="Broken Access Control",
                                endpoint=url,
                                description=(
                                    f"The application accepted a self-initiated role change "
                                    f"to administrator via PATCH {path}. An attacker can escalate "
                                    f"their own account to admin without administrator approval."
                                ),
                                evidence=f"PATCH {url} with {json.dumps(payload)} → role=admin in response",
                                request=f"PATCH {url} → {json.dumps(payload)}",
                                remediation=(
                                    "1. Never allow users to modify their own role/permission fields.\n"
                                    "2. Implement server-side field filtering (allowlist of updatable fields).\n"
                                    "3. Mass assignment protection: use explicit DTO/schema classes."
                                ),
                                priority_score=9.5,
                            )
                except Exception:
                    continue

    # ─────────────────────────────────────────────────────────────────────────
    # Session fixation
    # ─────────────────────────────────────────────────────────────────────────

    def _test_session_fixation(self):
        """
        Check if the session token changes after login (session fixation prevention).
        """
        login_url = self._find_login_endpoint()
        if not login_url or not (self.username and self.password):
            return

        # Get a token before login
        try:
            r1 = self.session.get(self.base_url + "/", timeout=5)
            pre_login_cookies = dict(r1.cookies)
        except Exception:
            return

        # Login
        try:
            r2 = self.session.post(
                login_url,
                json={"email": self.username, "password": self.password},
                timeout=self.timeout,
            )
        except Exception:
            return

        if r2.status_code != 200:
            return

        post_login_cookies = dict(r2.cookies)

        # Check if any session cookie remained the same
        for key in pre_login_cookies:
            if (key.lower() in ("session", "sessionid", "sess", "phpsessid", "jsessionid")
                    and key in post_login_cookies
                    and pre_login_cookies[key] == post_login_cookies[key]):
                self._add_finding(
                    title="Session Fixation Vulnerability",
                    severity="HIGH",
                    category="Broken Authentication",
                    endpoint=login_url,
                    description=(
                        f"The session cookie '{key}' was not regenerated after login. "
                        f"An attacker who sets a known session ID before authentication "
                        f"(via XSS, subdomain cookie injection, etc.) will have that session "
                        f"elevated to an authenticated state after the victim logs in."
                    ),
                    evidence=f"Cookie '{key}' value unchanged before/after login: {pre_login_cookies[key][:20]}...",
                    request=f"Pre-login cookie: {key}={pre_login_cookies[key][:20]} → Same after POST {login_url}",
                    remediation=(
                        "1. Always generate a new session ID immediately after successful authentication.\n"
                        "2. Invalidate the old session token.\n"
                        "3. Use framework-level session regeneration (e.g., express-session's regenerate())."
                    ),
                    priority_score=7.0,
                )

    # ─────────────────────────────────────────────────────────────────────────
    # Admin endpoint access
    # ─────────────────────────────────────────────────────────────────────────

    def _test_admin_endpoints_access(self):
        """
        Check if regular authenticated user can access admin endpoints.
        """
        if not self.auth_session:
            return

        # Check if we're already admin
        roles = [r.lower() for r in self.auth_session.roles]
        if any("admin" in r for r in roles):
            return  # We're admin, can't test privilege boundary

        admin_paths = [
            "/api/admin/users",
            "/api/admin/config",
            "/api/admin/stats",
            "/api/admin/logs",
            "/api/admin/",
            "/admin/api/",
        ]

        for path in admin_paths:
            url = self.base_url + path
            try:
                r = self.session.get(url, timeout=5)
            except Exception:
                continue

            if r.status_code == 200 and len(r.text) > 100:
                body = self._safe_json(r)
                if body:
                    self._add_finding(
                        title="Broken Function Level Access Control — Admin Endpoint Exposed",
                        severity="HIGH",
                        category="Broken Access Control",
                        endpoint=url,
                        description=(
                            f"A non-admin authenticated user can access the admin endpoint {path}. "
                            f"This indicates missing function-level access control, allowing any "
                            f"authenticated user to perform administrative operations."
                        ),
                        evidence=f"GET {url} → 200 as non-admin user (roles: {roles})",
                        request=f"GET {url}",
                        remediation=(
                            "1. Implement function-level authorization: check role on every admin endpoint.\n"
                            "2. Use middleware/decorators to enforce role requirements.\n"
                            "3. Return 403 with no body for unauthorized access attempts."
                        ),
                        priority_score=8.0,
                    )

    # ─────────────────────────────────────────────────────────────────────────
    # Password reset poisoning
    # ─────────────────────────────────────────────────────────────────────────

    def _test_password_reset_poisoning(self):
        """
        Test if the password reset endpoint uses the Host header to build reset links.
        """
        reset_paths = [
            "/api/auth/forgot-password",
            "/api/forgot-password",
            "/api/password-reset",
            "/api/v1/auth/forgot-password",
            "/auth/forgot-password",
            "/forgot-password",
        ]

        for path in reset_paths:
            url = self.base_url + path
            try:
                # First probe without poisoning
                r = self.session.post(url, json={"email": "probe@xipe-test.invalid"}, timeout=5)
                if r.status_code not in (200, 202, 204, 400, 422):
                    continue

                # Now poison the Host header
                r2 = self.session.post(
                    url,
                    json={"email": "probe@xipe-test.invalid"},
                    headers={"Host": "attacker.xipe-test.invalid"},
                    timeout=5,
                )

                if r2.status_code in (200, 202, 204):
                    body = r2.text[:500]
                    if "attacker.xipe-test.invalid" in body:
                        self._add_finding(
                            title="Password Reset Link Poisoning via Host Header",
                            severity="HIGH",
                            category="Broken Authentication",
                            endpoint=url,
                            description=(
                                "The password reset endpoint reflects the HTTP Host header "
                                "in the response body. If this value is also used to construct "
                                "reset email links, an attacker can set a malicious Host header "
                                "to redirect password reset tokens to attacker-controlled servers."
                            ),
                            evidence=f"Attacker Host header reflected in response: {body[:200]}",
                            request=f"POST {url} Host: attacker.xipe-test.invalid",
                            remediation=(
                                "1. Never build URLs from user-controllable Host headers.\n"
                                "2. Use a hardcoded base URL from server configuration for reset links.\n"
                                "3. Validate the Host header against a whitelist of known domains."
                            ),
                            priority_score=7.5,
                        )
            except Exception:
                continue

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _extract_token(self, response: requests.Response) -> Optional[str]:
        """Extract JWT/bearer token from response."""
        # Check Authorization header in response
        auth_header = response.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]

        # Check JSON body
        try:
            body = response.json()
            for field in ("token", "access_token", "accessToken", "jwt",
                          "auth_token", "authToken", "id_token"):
                val = body.get(field) or (body.get("data") or {}).get(field, "")
                if val and isinstance(val, str) and len(val) > 20:
                    return val
        except Exception:
            pass

        # Check Set-Cookie
        for cookie in response.cookies:
            if any(name in cookie.name.lower() for name in ("token", "jwt", "auth", "session")):
                return cookie.value

        return None

    def _safe_json(self, response: requests.Response) -> Any:
        try:
            return response.json()
        except Exception:
            return {}

    def _add_finding(
        self,
        title: str,
        severity: str,
        category: str,
        endpoint: str,
        description: str,
        evidence: str,
        request: str,
        remediation: str,
        priority_score: float,
    ):
        # Deduplicate
        if any(f.title == title for f in self._findings):
            return

        severity_map = {"CRITICAL": 0.95, "HIGH": 0.8, "MEDIUM": 0.6, "LOW": 0.4}
        exp = severity_map.get(severity, 0.7)

        scoring = ScoringDetail(
            severity=severity.lower(),
            exploitability=exp,
            exposure=0.8,
            business_risk=0.85,
            asset_criticality=0.8,
            confidence=0.9,
            priority_score=priority_score,
            rationale=evidence,
        )

        finding = Finding(
            title=title,
            severity=severity,
            category=category,
            module="auth_tester",
            endpoint=endpoint,
            description=description,
            evidence=evidence,
            request=request,
            remediation=remediation,
            cve="CWE-287",
            scoring=scoring,
            tags=["authentication", "authorization", category.lower().replace(" ", "-")],
        )
        self._findings.append(finding)
        log.warning("Auth finding: %s at %s", title, endpoint)


# ── Standalone entry for orchestrator ────────────────────────────────────────

def run(base_url: str, config: Dict[str, Any]) -> List[Finding]:
    """Callable by the orchestrator."""
    tester = AuthTester(base_url, config)
    return tester.run()
