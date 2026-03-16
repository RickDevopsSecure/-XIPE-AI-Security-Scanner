"""XIPE — JavaScript Analyzer v3.0"""
import re, uuid
from typing import List
import httpx
from agent.finding import Finding, Severity, OWASPCategory
from utils.logger import PentestLogger

class JSAnalyzer:
    def __init__(self, config, logger, http_client):
        self.config = config
        self.logger = logger
        self.client = http_client
        self.base_url = config["scope"]["base_urls"][0].rstrip("/")
        self.findings: List[Finding] = []

    def run(self) -> List[Finding]:
        self.logger.module_start("JavaScript Analysis")
        try:
            resp = self.client.get(self.base_url, timeout=10)
            js_files = re.findall(r'src="([^"]*\.js[^"]*)"', resp.text)
            for js_path in js_files[:8]:
                js_url = js_path if js_path.startswith("http") else self.base_url + "/" + js_path.lstrip("/")
                try:
                    js = self.client.get(js_url, timeout=8).text
                    self._check_js(js, js_url)
                except Exception:
                    pass
        except Exception as e:
            self.logger.error(f"JS analysis error: {e}")
        self.logger.module_done("JavaScript Analysis", len(self.findings))
        return self.findings

    def _check_js(self, content: str, url: str):
        patterns = [
            (r'api[_-]?key["\s]*[:=]["\s]*(["\'])([A-Za-z0-9_\-]{20,})\1', "API Key Exposed in JavaScript"),
            (r'secret["\s]*[:=]["\s]*(["\'])([A-Za-z0-9_\-]{20,})\1', "Secret Exposed in JavaScript"),
            (r'https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)[:\d]*/[\w/]+', "Internal Endpoint in JavaScript"),
            (r'Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', "Hardcoded JWT Token in JavaScript"),
        ]
        for pattern, title in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                self.findings.append(Finding(
                    id=f"JS-{str(uuid.uuid4())[:8].upper()}",
                    module="js_analyzer",
                    title=title,
                    severity=Severity.HIGH,
                    category=OWASPCategory.DATA_EXPOSURE,
                    description=f"Found in {url}: {title}",
                    endpoint=url,
                    recommendation="Remove hardcoded secrets from JavaScript. Use environment variables.",
                    false_positive_risk="MEDIUM",
                    tags=["javascript", "secrets"],
                ))
