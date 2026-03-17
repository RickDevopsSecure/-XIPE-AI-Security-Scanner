"""
XIPE — API Mapper v1.0
Inspired by the McKinsey/Lilli hack:
- Parses Swagger/OpenAPI docs if exposed
- Enumerates all endpoints with methods
- Classifies auth vs unauthenticated
- Identifies endpoints that WRITE to backend
- Finds 22 unprotected endpoints like CodeWall did
"""
import uuid
import json
import re
import time
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse
import httpx
import yaml

from agent.finding import Finding, Severity, OWASPCategory
from utils.logger import PentestLogger


# Known API doc paths
API_DOC_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json",
    "/api/swagger.json", "/api/v1/swagger.json",
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/api/openapi.json", "/api-docs", "/api-docs.json",
    "/api/docs", "/docs/api",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/.well-known/openai-configuration",
    "/redoc", "/swagger-ui", "/swagger-ui.html",
    "/graphql/schema", "/graphql/introspection",
]

# HTTP methods that WRITE to backend
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Patterns that suggest an endpoint writes to DB
WRITE_PATTERNS = [
    r"(create|insert|add|new|upload|save|store|write|update|edit|delete|remove|reset|clear)",
    r"(register|login|submit|publish|import|export)",
]

# Sensitive endpoint patterns
SENSITIVE_PATTERNS = [
    r"(admin|system|internal|debug|config|setting|secret|key|token|auth|user|account)",
    r"(password|credential|profile|permission|role|access|grant)",
    r"(prompt|model|agent|assistant|workspace|knowledge|document|file)",
]


class APIMapper:
    """
    Maps the full API surface of a target.
    Finds exposed documentation, enumerates endpoints,
    classifies auth requirements and write operations.
    """

    def __init__(self, config: dict, logger: PentestLogger,
                 http_client: httpx.Client, brain=None,
                 classification: Dict = None):
        self.config = config
        self.logger = logger
        self.client = http_client
        self.brain = brain
        self.classification = classification or {}
        self.findings: List[Finding] = []
        self.base_url = config["scope"]["base_urls"][0].rstrip("/")
        self.discovered_endpoints: List[Dict] = []
        self.unauth_endpoints: List[Dict] = []
        self.write_endpoints: List[Dict] = []

    def run(self) -> List[Finding]:
        self.logger.module_start("API Mapper (Swagger/OpenAPI + Endpoint Discovery)")

        # Step 1: Hunt for API documentation
        docs = self._find_api_docs()

        if docs:
            self.logger.info(f"📄 API docs found: {docs['url']}")
            self._add(
                title=f"API Documentation Publicly Exposed: {docs['url']}",
                severity=Severity.MEDIUM,
                category=OWASPCategory.DATA_EXPOSURE,
                description=(
                    f"API documentation is publicly accessible at {docs['url']}. "
                    f"Found {docs.get('endpoint_count', 0)} endpoints documented. "
                    f"This allows attackers to enumerate the full API surface without authentication."
                ),
                endpoint=docs['url'],
                evidence=f"Endpoints found: {docs.get('endpoint_count', 0)}\nSample: {str(docs.get('sample_endpoints', []))[:200]}",
                recommendation="Restrict API documentation to internal networks or authenticated users only.",
                owasp_top10="A05",
                false_positive_risk="LOW",
                tags=["api-docs", "information-disclosure"],
            )

            # Step 2: Parse and analyze all endpoints
            self._analyze_endpoints(docs)

        else:
            # Step 3: Brute-force endpoint discovery
            self.logger.info("No API docs found — attempting endpoint discovery...")
            self._discover_endpoints_blind()

        # Step 4: Test unauthenticated access
        self._test_unauth_access()

        # Step 5: Test write operations on sensitive endpoints
        self._test_write_operations()

        # Step 6: Test injection in non-standard params (JSON keys, headers)
        self._test_nonstandard_injection()

        self.logger.module_done("API Mapper", len(self.findings))
        return self.findings

    # ── Step 1: Find API Docs ─────────────────────────────────────────────────

    def _find_api_docs(self) -> Optional[Dict]:
        """Hunt for Swagger/OpenAPI documentation."""
        for path in API_DOC_PATHS:
            try:
                resp = self.client.get(self.base_url + path, timeout=8)
                if resp.status_code != 200:
                    continue
                ct = resp.headers.get("content-type", "")
                if "html" in ct:
                    continue

                body = resp.text
                data = None

                # Try JSON
                try:
                    data = resp.json()
                except Exception:
                    pass

                # Try YAML
                if data is None and ("yaml" in ct or path.endswith(".yaml") or path.endswith(".yml")):
                    try:
                        data = yaml.safe_load(body)
                    except Exception:
                        pass

                if data and isinstance(data, dict):
                    endpoints = self._extract_endpoints_from_spec(data)
                    return {
                        "url": self.base_url + path,
                        "path": path,
                        "spec": data,
                        "endpoints": endpoints,
                        "endpoint_count": len(endpoints),
                        "sample_endpoints": [e["path"] for e in endpoints[:5]],
                    }

                # GraphQL introspection
                if "graphql" in path:
                    gql_data = self._introspect_graphql(path)
                    if gql_data:
                        return gql_data

            except Exception:
                pass

        return None

    def _extract_endpoints_from_spec(self, spec: Dict) -> List[Dict]:
        """Extract endpoints from OpenAPI/Swagger spec."""
        endpoints = []
        paths = spec.get("paths", {})

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                method = method.upper()
                if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
                    continue

                endpoint = {
                    "path": path,
                    "method": method,
                    "summary": details.get("summary", "") if isinstance(details, dict) else "",
                    "requires_auth": self._check_auth_required(details, spec),
                    "is_write": method in WRITE_METHODS,
                    "is_sensitive": self._is_sensitive_path(path),
                    "parameters": details.get("parameters", []) if isinstance(details, dict) else [],
                }
                endpoints.append(endpoint)

        return endpoints

    def _check_auth_required(self, operation: Dict, spec: Dict) -> bool:
        """Check if an operation requires authentication."""
        if not isinstance(operation, dict):
            return True

        # Check operation-level security
        security = operation.get("security", None)
        if security is not None:
            return len(security) > 0

        # Check global security
        global_security = spec.get("security", [])
        return len(global_security) > 0

    def _is_sensitive_path(self, path: str) -> bool:
        """Check if a path is potentially sensitive."""
        path_lower = path.lower()
        for pattern in SENSITIVE_PATTERNS:
            if re.search(pattern, path_lower):
                return True
        return False

    def _introspect_graphql(self, path: str) -> Optional[Dict]:
        """Attempt GraphQL introspection."""
        try:
            resp = self.client.post(
                self.base_url + "/graphql",
                json={"query": "{ __schema { types { name fields { name } } } }"},
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if resp.status_code == 200 and "__schema" in resp.text:
                data = resp.json()
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                return {
                    "url": self.base_url + "/graphql",
                    "path": "/graphql",
                    "type": "graphql",
                    "endpoints": [{"path": f"/graphql:{t['name']}", "method": "POST",
                                   "requires_auth": False, "is_write": False,
                                   "is_sensitive": True}
                                  for t in types if not t["name"].startswith("__")],
                    "endpoint_count": len(types),
                    "sample_endpoints": [t["name"] for t in types[:5]],
                }
        except Exception:
            pass
        return None

    # ── Step 2: Analyze Endpoints ─────────────────────────────────────────────

    def _analyze_endpoints(self, docs: Dict):
        """Analyze discovered endpoints for security issues."""
        endpoints = docs.get("endpoints", [])
        self.discovered_endpoints = endpoints

        # Find unauth endpoints
        unauth = [e for e in endpoints if not e.get("requires_auth")]
        write_unauth = [e for e in unauth if e.get("is_write")]
        sensitive_unauth = [e for e in unauth if e.get("is_sensitive")]

        self.logger.info(f"  Total endpoints: {len(endpoints)}")
        self.logger.info(f"  Unauthenticated: {len(unauth)}")
        self.logger.info(f"  Write + no auth: {len(write_unauth)}")
        self.logger.info(f"  Sensitive + no auth: {len(sensitive_unauth)}")

        if len(unauth) > 0:
            self._add(
                title=f"{len(unauth)} Unauthenticated API Endpoints Found in Documentation",
                severity=Severity.HIGH if len(unauth) > 5 else Severity.MEDIUM,
                category=OWASPCategory.AUTH_BYPASS,
                description=(
                    f"API documentation reveals {len(unauth)} endpoints that do not require "
                    f"authentication according to their spec. This mirrors the McKinsey/Lilli "
                    f"attack vector where 22 unprotected endpoints led to full DB compromise. "
                    f"Write endpoints without auth: {len(write_unauth)}."
                ),
                endpoint=docs["url"],
                evidence="\n".join([f"{e['method']} {e['path']}" for e in unauth[:10]]),
                recommendation=(
                    "Audit all endpoints without authentication. Apply deny-by-default. "
                    "Especially protect any endpoint that writes to database or storage."
                ),
                owasp_api_top10="API2",
                false_positive_risk="LOW",
                tags=["api", "auth", "enumeration"],
            )

        for e in write_unauth[:5]:
            self._add(
                title=f"Write Endpoint Without Authentication: {e['method']} {e['path']}",
                severity=Severity.CRITICAL,
                category=OWASPCategory.AUTH_BYPASS,
                description=(
                    f"Endpoint {e['method']} {e['path']} performs write operations "
                    f"without requiring authentication. An attacker could modify data, "
                    f"inject content, or potentially modify AI system prompts stored in the database."
                ),
                endpoint=self.base_url + e["path"],
                recommendation=(
                    "Require authentication on all write endpoints. "
                    "Validate all user-supplied data including JSON field names, not just values."
                ),
                owasp_api_top10="API2",
                false_positive_risk="LOW",
                tags=["api", "write", "auth-bypass", "critical"],
                requires_auth=False,
            )

        self.unauth_endpoints = unauth
        self.write_endpoints = write_unauth

    # ── Step 3: Blind Discovery ───────────────────────────────────────────────

    def _discover_endpoints_blind(self):
        """Discover endpoints without documentation."""
        common_paths = [
            "/api", "/api/v1", "/api/v2",
            "/api/users", "/api/admin", "/api/config",
            "/api/messages", "/api/conversations", "/api/convos",
            "/api/prompts", "/api/agents", "/api/assistants",
            "/api/models", "/api/workspaces", "/api/documents",
            "/api/files", "/api/upload", "/api/search",
            "/api/keys", "/api/tokens", "/api/settings",
            "/api/health", "/api/status", "/api/version",
            "/api/debug", "/api/internal", "/api/system",
        ]

        found = []
        for path in common_paths:
            try:
                resp = self.client.get(self.base_url + path, timeout=5)
                if resp.status_code in (200, 401, 403, 405):
                    ct = resp.headers.get("content-type", "")
                    if "html" not in ct:
                        found.append({
                            "path": path,
                            "status": resp.status_code,
                            "requires_auth": resp.status_code in (401, 403),
                            "method": "GET",
                            "is_write": False,
                            "is_sensitive": self._is_sensitive_path(path),
                        })
                        self.logger.info(f"  Found: {path} → HTTP {resp.status_code}")
            except Exception:
                pass
            time.sleep(0.05)

        self.discovered_endpoints = found
        unauth_200 = [e for e in found if e["status"] == 200]
        self.unauth_endpoints = unauth_200

    # ── Step 4: Test Unauthenticated Access ───────────────────────────────────

    def _test_unauth_access(self):
        """Actually test if unauthenticated endpoints return data."""
        for endpoint in self.unauth_endpoints[:15]:
            path = endpoint.get("path", "")
            if not path:
                continue
            try:
                resp = self.client.get(
                    self.base_url + path,
                    headers={},  # No auth
                    timeout=8,
                )
                if resp.status_code == 200:
                    ct = resp.headers.get("content-type", "")
                    if "html" in ct:
                        continue
                    body = resp.text

                    # Check for sensitive data in response
                    sensitive_found = []
                    sensitive_keywords = [
                        "email", "password", "token", "api_key", "secret",
                        "prompt", "system_prompt", "instruction", "userId",
                        "conversationId", "messageId",
                    ]
                    for kw in sensitive_keywords:
                        if kw.lower() in body.lower():
                            sensitive_found.append(kw)

                    if sensitive_found:
                        self._add(
                            title=f"Unauthenticated API Returns Sensitive Data: {path}",
                            severity=Severity.HIGH,
                            category=OWASPCategory.DATA_EXPOSURE,
                            description=(
                                f"Endpoint {path} returns sensitive data without authentication. "
                                f"Sensitive fields detected: {', '.join(sensitive_found)}."
                            ),
                            endpoint=self.base_url + path,
                            evidence=body[:300],
                            recommendation="Require authentication. Implement field-level access control.",
                            owasp_api_top10="API1",
                            false_positive_risk="LOW",
                            tags=["api", "data-exposure", "unauth"],
                        )
            except Exception:
                pass

    # ── Step 5: Test Write Operations ─────────────────────────────────────────

    def _test_write_operations(self):
        """Test write endpoints for injection and unauthorized access."""
        write_paths = [e for e in self.discovered_endpoints if e.get("is_write")]

        # Also test known write paths
        extra_write_paths = [
            "/api/messages", "/api/conversations", "/api/prompts",
            "/api/agents", "/api/assistants", "/api/config",
            "/api/v1/messages", "/api/v1/prompts",
        ]

        for path in extra_write_paths:
            if not any(e["path"] == path for e in write_paths):
                write_paths.append({"path": path, "method": "POST"})

        for endpoint in write_paths[:10]:
            path = endpoint.get("path", "")
            try:
                resp = self.client.post(
                    self.base_url + path,
                    json={"test": "xipe_probe"},
                    headers={"Content-Type": "application/json"},
                    timeout=8,
                )
                ct = resp.headers.get("content-type", "")
                if "html" in ct:
                    continue

                if resp.status_code in (200, 201, 202):
                    self._add(
                        title=f"Unauthenticated Write Access: POST {path}",
                        severity=Severity.CRITICAL,
                        category=OWASPCategory.AUTH_BYPASS,
                        description=(
                            f"POST {path} accepts data without authentication. "
                            f"If this endpoint writes to a database, an attacker could "
                            f"inject malicious content, modify AI prompts, or corrupt data."
                        ),
                        endpoint=self.base_url + path,
                        evidence=f"HTTP {resp.status_code}: {resp.text[:200]}",
                        recommendation=(
                            "Require authentication on all write endpoints. "
                            "Validate and sanitize ALL input including JSON field names."
                        ),
                        owasp_api_top10="API2",
                        false_positive_risk="LOW",
                        tags=["api", "write", "unauth", "critical"],
                    )
            except Exception:
                pass

    # ── Step 6: Non-Standard Injection ───────────────────────────────────────

    def _test_nonstandard_injection(self):
        """
        Test injection in non-standard locations:
        - JSON keys (not just values) — the McKinsey/Lilli vector
        - Header injection
        - Path parameter injection
        """
        injection_payloads = [
            # SQL injection in JSON keys
            {"key": "id' OR '1'='1", "type": "sqli_key"},
            {"key": "name'; DROP TABLE users;--", "type": "sqli_key"},
            {"key": "field\") OR 1=1--", "type": "sqli_key"},
            # Template injection in keys
            {"key": "{{7*7}}", "type": "ssti"},
            {"key": "${7*7}", "type": "ssti"},
        ]

        test_endpoints = [
            "/api/messages", "/api/search", "/api/query",
            "/api/v1/chat", "/api/v1/messages",
        ]

        for path in test_endpoints:
            for payload in injection_payloads[:3]:
                try:
                    # Build payload with injection in JSON KEY
                    body = {payload["key"]: "test_value", "message": "hello"}
                    resp = self.client.post(
                        self.base_url + path,
                        json=body,
                        headers={"Content-Type": "application/json"},
                        timeout=8,
                    )
                    ct = resp.headers.get("content-type", "")
                    if "html" in ct:
                        continue

                    body_text = resp.text.lower()

                    # Check for SQL error indicators
                    sql_errors = [
                        "sql", "syntax error", "mysql", "postgresql",
                        "sqlite", "ora-", "odbc", "jdbc", "query",
                        "column", "table", "database error",
                    ]
                    found_errors = [e for e in sql_errors if e in body_text]

                    if found_errors and resp.status_code != 404:
                        self._add(
                            title=f"Potential SQL Injection in JSON Key: {path}",
                            severity=Severity.CRITICAL,
                            category=OWASPCategory.INJECTION,
                            description=(
                                f"Endpoint {path} appears to reflect or process JSON field names "
                                f"in a way that triggers database errors. This is the exact vector "
                                f"used to compromise McKinsey's Lilli platform: SQL injection via "
                                f"JSON keys, not values. Standard scanners miss this completely. "
                                f"Error indicators found: {', '.join(found_errors)}"
                            ),
                            endpoint=self.base_url + path,
                            evidence=(
                                f"Payload key: {payload['key']}\n"
                                f"HTTP {resp.status_code}\n"
                                f"Response: {resp.text[:400]}"
                            ),
                            recommendation=(
                                "Never concatenate user-supplied JSON field names into SQL queries. "
                                "Use a whitelist of allowed field names. "
                                "Parameterize ALL database inputs including dynamic column names."
                            ),
                            owasp_top10="A03",
                            cwe="CWE-89",
                            false_positive_risk="LOW",
                            tags=["sqli", "json-key-injection", "critical", "lilli-vector"],
                        )
                        break
                except Exception:
                    pass
                time.sleep(0.1)

    # ── Helper ────────────────────────────────────────────────────────────────

    def _add(self, owasp_top10=None, owasp_api_top10=None, cwe=None,
             tags=None, false_positive_risk="MEDIUM",
             requires_auth=True, **kwargs) -> Finding:
        f = Finding(
            id=f"MAP-{str(uuid.uuid4())[:8].upper()}",
            module="api_mapper",
            false_positive_risk=false_positive_risk,
            owasp_top10=owasp_top10,
            owasp_api_top10=owasp_api_top10,
            cwe=cwe,
            tags=tags or [],
            requires_auth=requires_auth,
            **kwargs,
        )
        self.findings.append(f)
        if f.severity.value in ("CRITICAL", "HIGH"):
            self.logger.finding(f.severity.value, f.title)
        return f
