"""XIPE — TLS Checker v3.0"""
import uuid
from typing import List
from urllib.parse import urlparse
import httpx
from agent.finding import Finding, Severity, OWASPCategory
from utils.logger import PentestLogger

class TLSChecker:
    def __init__(self, config, logger, http_client):
        self.config = config
        self.logger = logger
        self.client = http_client
        self.base_url = config["scope"]["base_urls"][0].rstrip("/")
        self.findings: List[Finding] = []

    def run(self) -> List[Finding]:
        self.logger.module_start("TLS / Transport Security")
        parsed = urlparse(self.base_url)
        if parsed.scheme == "http":
            self.findings.append(Finding(
                id=f"TLS-{str(uuid.uuid4())[:8].upper()}",
                module="tls_checker",
                title="HTTP Used — No Encryption",
                severity=Severity.HIGH,
                category=OWASPCategory.DATA_EXPOSURE,
                description=f"{self.base_url} uses unencrypted HTTP. All traffic is exposed.",
                endpoint=self.base_url,
                recommendation="Enforce HTTPS. Redirect all HTTP to HTTPS. Implement HSTS.",
                false_positive_risk="LOW",
                tags=["tls", "transport"],
            ))
        elif parsed.scheme == "https":
            http_url = self.base_url.replace("https://", "http://", 1)
            try:
                resp = self.client.get(http_url, timeout=8, follow_redirects=False)
                if resp.status_code == 200:
                    self.findings.append(Finding(
                        id=f"TLS-{str(uuid.uuid4())[:8].upper()}",
                        module="tls_checker",
                        title="HTTP Accessible Without Redirect to HTTPS",
                        severity=Severity.MEDIUM,
                        category=OWASPCategory.DATA_EXPOSURE,
                        description=f"HTTP version of {self.base_url} serves content without redirecting to HTTPS.",
                        endpoint=http_url,
                        recommendation="Redirect all HTTP to HTTPS (301). Implement HSTS.",
                        false_positive_risk="LOW",
                        tags=["tls", "redirect"],
                    ))
            except Exception:
                pass
        self.logger.module_done("TLS / Transport Security", len(self.findings))
        return self.findings
