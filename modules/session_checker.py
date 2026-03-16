"""XIPE — Session Security Checker v3.0"""
import uuid
from typing import List
import httpx
from agent.finding import Finding, Severity, OWASPCategory
from utils.logger import PentestLogger

class SessionChecker:
    def __init__(self, config, logger, http_client):
        self.config = config
        self.logger = logger
        self.client = http_client
        self.base_url = config["scope"]["base_urls"][0].rstrip("/")
        self.findings: List[Finding] = []

    def run(self) -> List[Finding]:
        self.logger.module_start("Session Security")
        try:
            resp = self.client.get(self.base_url, timeout=10)
            for cookie in resp.cookies.jar:
                issues = []
                if not cookie.secure:
                    issues.append("missing Secure flag")
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    issues.append("missing HttpOnly flag")
                if not cookie.has_nonstandard_attr("SameSite"):
                    issues.append("missing SameSite attribute")
                if issues:
                    sev = Severity.MEDIUM if "session" in cookie.name.lower() else Severity.LOW
                    self.findings.append(Finding(
                        id=f"SESS-{str(uuid.uuid4())[:8].upper()}",
                        module="session_checker",
                        title=f"Cookie Security Flags Missing: {cookie.name}",
                        severity=sev,
                        category=OWASPCategory.SECURITY_MISCONFIG,
                        description=f"Cookie '{cookie.name}' is {', '.join(issues)}.",
                        endpoint=self.base_url,
                        recommendation="Set Secure, HttpOnly, and SameSite=Strict on all cookies.",
                        false_positive_risk="LOW",
                        tags=["cookies", "session"],
                    ))
        except Exception as e:
            self.logger.error(f"Session check error: {e}")
        self.logger.module_done("Session Security", len(self.findings))
        return self.findings
