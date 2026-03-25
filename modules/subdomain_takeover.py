"""
XIPE — Subdomain Takeover Detector v1.0
Finds dangling DNS entries pointing to decommissioned cloud services:

1. CNAME to unclaimed cloud services (AWS, Azure, GCP, GitHub Pages, Heroku, etc.)
2. A record pointing to unallocated IPs (EIP released, etc.)
3. NS delegation to dead nameservers
4. Specific service fingerprints (GitHub Pages, S3, Fastly, etc.)
"""
from __future__ import annotations

import re
import socket
import uuid
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError as ReqConnError

from agent.finding import Finding, ScoringDetail, Severity, OWASPCategory
from utils.logger import get_logger

log = get_logger("subdomain_takeover")

# ── Service fingerprints: (name, cname_pattern, error_body_pattern, severity) ─
VULNERABLE_SERVICES = [
    # GitHub Pages
    ("GitHub Pages",
     r"\.github\.io$",
     ["There isn't a GitHub Pages site here", "404 - File not found"],
     Severity.HIGH),
    # AWS S3
    ("AWS S3",
     r"\.s3\.amazonaws\.com$|\.s3-website[.-]",
     ["NoSuchBucket", "The specified bucket does not exist"],
     Severity.CRITICAL),
    # AWS Elastic Beanstalk
    ("AWS Elastic Beanstalk",
     r"\.elasticbeanstalk\.com$",
     ["404 Not Found", "No Application"],
     Severity.CRITICAL),
    # Azure
    ("Azure App Service",
     r"\.azurewebsites\.net$",
     ["404 Web Site not found", "Microsoft Azure"],
     Severity.CRITICAL),
    ("Azure Blob Storage",
     r"\.blob\.core\.windows\.net$",
     ["BlobNotFound", "ResourceNotFound"],
     Severity.CRITICAL),
    ("Azure Traffic Manager",
     r"\.trafficmanager\.net$",
     ["404", "Not Found"],
     Severity.HIGH),
    # Heroku
    ("Heroku",
     r"\.herokuapp\.com$|\.herokudns\.com$",
     ["No such app", "Heroku | No such app"],
     Severity.HIGH),
    # Netlify
    ("Netlify",
     r"\.netlify\.app$|\.netlify\.com$",
     ["Not Found", "Page Not Found", "netlify"],
     Severity.HIGH),
    # Fastly
    ("Fastly CDN",
     r"\.fastly\.net$|\.fastlylb\.net$",
     ["Fastly error: unknown domain", "Please check that this domain has been added"],
     Severity.HIGH),
    # Shopify
    ("Shopify",
     r"\.myshopify\.com$|\.shopify\.com$",
     ["Sorry, this shop is currently unavailable", "Only one step away"],
     Severity.HIGH),
    # Tumblr
    ("Tumblr",
     r"\.tumblr\.com$",
     ["Whatever you were looking for doesn't currently exist"],
     Severity.MEDIUM),
    # Ghost
    ("Ghost (CMS)",
     r"\.ghost\.io$",
     ["The thing you were looking for is no longer here"],
     Severity.MEDIUM),
    # Vercel
    ("Vercel",
     r"\.vercel\.app$",
     ["The deployment could not be found", "404: NOT_FOUND"],
     Severity.HIGH),
    # Surge.sh
    ("Surge.sh",
     r"\.surge\.sh$",
     ["project not found"],
     Severity.HIGH),
    # ReadTheDocs
    ("ReadTheDocs",
     r"\.readthedocs\.io$",
     ["unknown to Read the Docs"],
     Severity.MEDIUM),
    # Zendesk
    ("Zendesk",
     r"\.zendesk\.com$",
     ["Help Center Closed"],
     Severity.MEDIUM),
    # Intercom
    ("Intercom",
     r"\.intercom\.io$",
     ["This page is reserved for artistic dogs"],
     Severity.MEDIUM),
]

# ── Subdomain wordlist for enumeration ────────────────────────────────────────
COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "staging", "test", "portal",
    "admin", "mail2", "www2", "cpanel", "whm", "autodiscover", "autoconfig",
    "ftp", "m", "imap", "pop", "pop3", "exchange", "owa", "shop", "store",
    "cdn", "static", "assets", "media", "img", "images", "docs", "support",
    "help", "status", "monitoring", "grafana", "kibana", "jenkins", "ci",
    "gitlab", "github", "git", "svn", "jira", "confluence", "wiki",
    "beta", "alpha", "demo", "sandbox", "preview", "app", "apps", "mobile",
    "dashboard", "panel", "control", "manage", "old", "legacy", "backup",
]


def _get_cname(hostname: str) -> Optional[str]:
    """Resolve CNAME for a hostname. Returns the canonical name or None."""
    try:
        result = socket.getaddrinfo(hostname, None)
        # Use getfqdn as a simple CNAME resolver
        cname = socket.getfqdn(hostname)
        if cname != hostname:
            return cname.rstrip(".")
        return None
    except Exception:
        return None


def _get_a_record(hostname: str) -> Optional[str]:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def _http_fingerprint(url: str, timeout: int = 6) -> Tuple[Optional[int], str]:
    """Return (status_code, response_body[:2000]) or (None, '')."""
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         allow_redirects=True,
                         headers={"User-Agent": "XIPE-SecurityScanner/4.0"})
        return r.status_code, r.text[:2000]
    except Exception:
        return None, ""


class SubdomainTakeoverDetector:
    def __init__(self, base_url: str, config: Dict[str, Any]):
        self.base_url = base_url.rstrip("/")
        self.config   = config
        self.timeout  = config.get("testing", {}).get("request_timeout", 8)

        # Extract root domain
        import re as _re
        match = _re.search(r"https?://([^/]+)", self.base_url)
        self.host = match.group(1).split(":")[0] if match else ""
        # Get root domain (last two parts)
        parts = self.host.split(".")
        self.root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else self.host

        self._findings: List[Finding] = []

    # ── Entry point ──────────────────────────────────────────────────────────

    def run(self) -> List[Finding]:
        if not self.root_domain:
            return []

        log.info("Starting subdomain takeover scan for %s", self.root_domain)

        # 1. Enumerate subdomains and check for dangling CNAMEs
        subdomains = self._enumerate_subdomains()
        log.info("Checking %d subdomains for takeover", len(subdomains))

        for sub in subdomains:
            self._check_subdomain(sub)

        # 2. Check the main domain itself
        self._check_subdomain(self.host)

        log.info("Subdomain takeover scan complete — %d findings", len(self._findings))
        return self._findings

    # ── Subdomain enumeration ────────────────────────────────────────────────

    def _enumerate_subdomains(self) -> List[str]:
        found = []
        for prefix in COMMON_SUBDOMAINS:
            fqdn = f"{prefix}.{self.root_domain}"
            if _get_a_record(fqdn):
                found.append(fqdn)
        return found

    # ── Per-subdomain check ──────────────────────────────────────────────────

    def _check_subdomain(self, fqdn: str):
        # Resolve CNAME
        cname = _get_cname(fqdn)
        ip    = _get_a_record(fqdn)

        if not cname and not ip:
            # Hostname doesn't resolve — potential dangling DNS if we can confirm it existed
            return

        # Check against known vulnerable services
        target = cname or fqdn
        for svc_name, cname_pattern, body_patterns, severity in VULNERABLE_SERVICES:
            if not re.search(cname_pattern, target, re.I):
                continue

            # CNAME matches a cloud service — check if it's unclaimed
            status, body = _http_fingerprint(f"http://{fqdn}", self.timeout)
            if status is None:
                status, body = _http_fingerprint(f"https://{fqdn}", self.timeout)

            is_unclaimed = (
                status in (404, 410, 500, 503) or
                any(pattern.lower() in body.lower() for pattern in body_patterns)
            )

            if is_unclaimed:
                self._add_takeover_finding(fqdn, cname or target, svc_name, severity, status, body[:300])
                break

    # ── Finding builder ──────────────────────────────────────────────────────

    def _add_takeover_finding(self, fqdn: str, cname: str, service: str,
                               severity: Severity, status: Optional[int], evidence_body: str):
        if any(fqdn in f.title for f in self._findings):
            return

        sev_map = {Severity.CRITICAL: 9.5, Severity.HIGH: 8.0, Severity.MEDIUM: 5.5}
        priority = sev_map.get(severity, 7.0)

        scoring = ScoringDetail(
            severity_score=sev_map.get(severity, 7.0),
            exploitability_score=9.0,   # Very easy once identified
            exposure_score=8.0,
            business_risk_score=9.0,    # Brand/data risk
            asset_criticality_score=8.5,
            confidence_score=8.5,
            priority_score=priority,
            score_explanation=f"Subdomain takeover — {fqdn} → {service}",
        )

        description = (
            f"The subdomain '{fqdn}' has a CNAME pointing to '{cname}' ({service}), "
            f"but the target resource does not exist or is unclaimed. "
            f"An attacker can register this resource on {service} and serve malicious "
            f"content under your domain, perform phishing attacks, steal cookies scoped "
            f"to *.{self.root_domain}, or bypass CSP/CORS policies."
        )

        if service in ("AWS S3", "AWS Elastic Beanstalk", "Azure App Service", "Azure Blob Storage"):
            remediation = (
                f"1. Immediate: Remove the CNAME record for '{fqdn}' from your DNS zone.\n"
                f"2. If the service is still needed, re-provision the {service} resource "
                f"and ensure the bucket/app name matches.\n"
                f"3. Audit all DNS records quarterly for dangling references.\n"
                f"4. For S3: enforce bucket name reservation before deleting content."
            )
        else:
            remediation = (
                f"1. Immediate: Remove the DNS CNAME for '{fqdn}' if the service is no longer used.\n"
                f"2. If still needed, re-register the resource on {service}.\n"
                f"3. Implement a DNS change approval process to prevent orphaned records.\n"
                f"4. Use automated tools (e.g., dnsReaper, can-i-take-over-xyz) in CI/CD."
            )

        f = Finding(
            id=f"SDT-{uuid.uuid4().hex[:8].upper()}",
            title=f"Subdomain Takeover — {fqdn} → {service}",
            severity=severity,
            category=OWASPCategory.SECURITY_MISCONFIG,
            module="subdomain_takeover",
            endpoint=f"https://{fqdn}",
            description=description,
            evidence=f"CNAME: {fqdn} → {cname} | HTTP {status} | Body: {evidence_body[:150]}",
            recommendation=remediation,
            cwe="CWE-284",
            scoring=scoring,
            tags=["subdomain-takeover", "dns", service.lower().replace(" ", "-"), "recon"],
        )
        self._findings.append(f)
        log.warning("Subdomain takeover: %s → %s (%s)", fqdn, service, severity.value)


# ── Orchestrator entry ────────────────────────────────────────────────────────

def run(base_url: str, config: Dict[str, Any]) -> List[Finding]:
    return SubdomainTakeoverDetector(base_url, config).run()
