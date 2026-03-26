"""
XIPE — AI Security Module v3.0
Merges: LiveAITester + PromptInjection + RAGTester + AgentTester
Full AI Brain pipeline. Works with any AI platform.
"""
import uuid
import time
from typing import List, Dict, Optional
import httpx

from agent.finding import Finding, Severity, OWASPCategory
from modules.universal_ai_client import UniversalAIClient
from utils.logger import PentestLogger


ATTACK_CATEGORIES = [
    ("system_prompt_leakage", "LLM07", Severity.HIGH),
    ("injection",             "LLM01", Severity.CRITICAL),
    ("data_extraction",       "LLM02", Severity.HIGH),
    ("jailbreak",             "LLM01", Severity.HIGH),
    ("excessive_agency",      "LLM06", Severity.HIGH),
    ("indirect_injection",    "LLM08", Severity.MEDIUM),
]


class AISecurityModule:
    """
    Tests any AI platform for OWASP LLM Top 10 vulnerabilities.
    Brain generates context-aware attacks and analyzes responses.
    """

    def __init__(self, config: dict, logger: PentestLogger,
                 http_client: httpx.Client, brain, classification: Dict):
        self.config = config
        self.logger = logger
        self.client = http_client
        self.brain = brain
        self.classification = classification
        self.findings: List[Finding] = []
        self.base_url = config["scope"]["base_urls"][0].rstrip("/")
        self.interactions: List[Dict] = []  # stored for trustworthiness eval
        self.ai_client: Optional[UniversalAIClient] = None
        self.auth_token: Optional[str] = None

    def run(self) -> List[Finding]:
        self.logger.module_start("AI Security (OWASP LLM Top 10 — Universal)")

        # Initialize universal client
        self.ai_client = UniversalAIClient(
            base_url=self.base_url,
            logger=self.logger,
        )

        # Detect platform
        platform = self.ai_client.detect_platform()
        self.logger.info(f"AI platform: {platform}")

        # Authenticate if possible
        self._authenticate(platform)
        if self.auth_token:
            self.ai_client.token = self.auth_token

        # Find chat endpoint
        endpoint = self.ai_client.discover_chat_endpoint()
        if not endpoint:
            self.logger.warning("No chat endpoint found — checking if CDN is blocking...")
            try:
                test = self.http_client.get(self.base_url + "/api/convos",
                    headers={"Authorization": f"Bearer {self.auth_token or ''}"},
                    timeout=5)
                if "html" in test.headers.get("content-type",""):
                    self._add(
                        title="CDN/CloudFront Blocking Direct API Access",
                        severity=Severity.INFO,
                        category=OWASPCategory.SECURITY_MISCONFIG,
                        description=("CloudFront intercepts all /api/* routes except /api/auth/* and returns the SPA HTML. "
                            "Direct automated AI security testing is blocked at the CDN layer. "
                            "This acts as a compensating control against automated attacks."),
                        endpoint=self.base_url + "/api/convos",
                        recommendation="Verify CloudFront behaviors are intentional. Ensure /api/auth/* is rate-limited since it bypasses CDN protection.",
                        false_positive_risk="LOW",
                        tags=["cloudfront", "cdn", "api-protection"],
                    )
                    self.logger.info("CDN blocking detected — documented as finding")
            except Exception:
                pass
            self.logger.module_done("AI Security", len(self.findings))
            return self.findings

        self.logger.info(f"Chat endpoint: {endpoint} [{self.ai_client.chat_format}]")

        # Verify connectivity
        test_resp = self.ai_client.send_message("Hello! What can you help me with?")
        if test_resp:
            self.logger.info(f"✅ Chat reachable — response: {test_resp[:80]}")
            self.interactions.append({
                "attack_prompt": "Hello! What can you help me with?",
                "ai_response": test_resp,
                "is_vulnerability": False,
                "attack_category": "connectivity_test",
            })
        else:
            self.logger.warning("Chat not responding — will attempt attacks anyway")

        # Run all attack categories
        self._run_attacks()

        # Check for open registration (auth-specific)
        self._check_open_registration(platform)

        self.logger.module_done("AI Security", len(self.findings))
        return self.findings

    # ── Authentication ────────────────────────────────────────────────────────

    def _authenticate(self, platform: str):
        """Attempt to authenticate on the platform."""
        if platform == "librechat":
            self._auth_librechat()
        else:
            self._try_default_creds()

    def _auth_librechat(self):
        test_email = f"xipe_{uuid.uuid4().hex[:6]}@mailnull.com"
        test_pass = "XipePentest2026!"
        try:
            reg = self.client.post(
                f"{self.base_url}/api/auth/register",
                json={"name": "XIPE", "email": test_email,
                      "password": test_pass, "confirm_password": test_pass},
                timeout=15,
            )
            if reg.status_code == 200:
                login = self.client.post(
                    f"{self.base_url}/api/auth/login",
                    json={"email": test_email, "password": test_pass},
                    timeout=15,
                )
                if login.status_code == 200:
                    data = login.json()
                    self.auth_token = data.get("token")
                    user = data.get("user", {})

                    if user.get("emailVerified"):
                        self._add(
                            title="Email Verification Bypass — Accounts Auto-Verified",
                            severity=Severity.HIGH,
                            category=OWASPCategory.AUTH_BYPASS,
                            description=(
                                f"Account {test_email} was created and authenticated without "
                                f"email verification. emailVerified=true was set automatically, "
                                f"enabling unlimited disposable-email account creation."
                            ),
                            endpoint=f"{self.base_url}/api/auth/register",
                            recommendation="Enforce email verification. Block login for emailVerified=false.",
                            owasp_top10="A07",
                            false_positive_risk="LOW",
                            tags=["auth", "registration"],
                        )
                        self.logger.warning("🚨 Email verification bypass confirmed!")

                    # Accept terms
                    if self.auth_token:
                        try:
                            self.client.post(
                                f"{self.base_url}/api/user/terms/accept",
                                headers={"Authorization": f"Bearer {self.auth_token}"},
                                timeout=8,
                            )
                        except Exception:
                            pass
        except Exception as e:
            self.logger.error(f"Auth error: {e}")

    def _try_default_creds(self):
        """Try common default credentials."""
        endpoints = ["/api/auth/login", "/auth/login", "/login", "/api/login"]
        creds_list = [
            {"email": "admin@admin.com", "password": "admin"},
            {"username": "admin", "password": "admin"},
            {"email": "admin@example.com", "password": "password"},
        ]
        for endpoint in endpoints:
            for creds in creds_list:
                try:
                    resp = self.client.post(
                        self.base_url + endpoint, json=creds, timeout=5
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        token = (data.get("token") or data.get("access_token") or
                                 data.get("jwt") or data.get("accessToken"))
                        if token:
                            # Store token for AI testing — finding is reported by auth_tester
                            self.auth_token = token
                            return
                except Exception:
                    pass

    def _check_open_registration(self, platform: str):
        """Check if registration is open to anyone."""
        reg_endpoints = ["/api/auth/register", "/api/register", "/register", "/signup"]
        for endpoint in reg_endpoints:
            try:
                resp = self.client.get(self.base_url + endpoint, timeout=5)
                if resp.status_code in (200, 405):
                    ct = resp.headers.get("content-type", "")
                    if "html" not in ct or resp.status_code == 405:
                        self._add(
                            title="Open Registration — Unauthenticated Account Creation Enabled",
                            severity=Severity.MEDIUM,
                            category=OWASPCategory.AUTH_BYPASS,
                            description=(
                                f"Registration endpoint {endpoint} is accessible. "
                                "Without controls, anyone can create accounts and consume AI resources."
                            ),
                            endpoint=self.base_url + endpoint,
                            recommendation="Require invitation codes or admin approval for new registrations.",
                            owasp_top10="A07",
                            false_positive_risk="MEDIUM",
                            tags=["registration", "auth"],
                        )
                        break
            except Exception:
                pass

    # ── AI Attacks ────────────────────────────────────────────────────────────

    def _run_attacks(self):
        """Run all attack categories with Brain-generated prompts."""
        for category_key, owasp_id, base_severity in ATTACK_CATEGORIES:
            self.logger.info(f"Testing {owasp_id} — {category_key}...")

            prompts = self.brain.generate_attacks(
                classification=self.classification,
                attack_type=category_key,
                history=self.interactions,
            )

            for prompt in prompts:
                response = self.ai_client.send_message(prompt)

                interaction = {
                    "attack_prompt": prompt,
                    "ai_response": response or "",
                    "attack_category": category_key,
                    "is_vulnerability": False,
                    "severity": "INFO",
                    "vulnerability_type": category_key,
                    "evidence": "",
                }

                if response:
                    self.logger.info(f"  ✓ Response ({len(response)} chars)")

                    analysis = self.brain.analyze_ai_response(
                        prompt=prompt,
                        response=response,
                        attack_type=category_key,
                        classification=self.classification,
                    )

                    interaction["is_vulnerability"] = analysis.get("is_vulnerability", False)
                    interaction["severity"] = analysis.get("severity", "INFO")
                    interaction["evidence"] = analysis.get("evidence", "")

                    if analysis.get("is_vulnerability"):
                        written = self.brain.write_finding(
                            raw=analysis,
                            classification=self.classification,
                            evidence=response,
                        )

                        sev_map = {
                            "CRITICAL": Severity.CRITICAL,
                            "HIGH": Severity.HIGH,
                            "MEDIUM": Severity.MEDIUM,
                            "LOW": Severity.LOW,
                            "INFO": Severity.INFO,
                        }
                        severity = sev_map.get(
                            analysis.get("severity", "MEDIUM").upper(),
                            base_severity,
                        )

                        owasp_llm_map = {
                            "system_prompt_leakage": "LLM07",
                            "injection":             "LLM01",
                            "data_extraction":       "LLM02",
                            "jailbreak":             "LLM01",
                            "excessive_agency":      "LLM06",
                            "indirect_injection":    "LLM08",
                        }

                        self._add(
                            title=written.get("title", analysis.get("finding_title", f"{owasp_id} — {category_key}")),
                            severity=severity,
                            category=OWASPCategory.PROMPT_INJECTION,
                            description=written.get("technical_description", analysis.get("finding_description", "")),
                            endpoint=self.ai_client.chat_endpoint or self.base_url,
                            evidence=f"Prompt: {prompt[:200]}\n\nResponse: {response[:400]}",
                            recommendation=written.get("remediation", analysis.get("recommendation", "")),
                            owasp_llm_top10=owasp_llm_map.get(category_key, owasp_id),
                            false_positive_risk="LOW" if analysis.get("confidence", 0) > 0.8 else "MEDIUM",
                            tags=["ai", "llm", category_key, owasp_id.lower()],
                        )
                        self.logger.finding(severity.value, written.get("title", category_key)[:80])
                else:
                    self.logger.info(f"  No response for {category_key}")

                self.interactions.append(interaction)
                time.sleep(2)

    # ── Helper ────────────────────────────────────────────────────────────────

    def _add(self, owasp_top10=None, owasp_api_top10=None,
             owasp_llm_top10=None, cwe=None, tags=None,
             false_positive_risk="MEDIUM", **kwargs) -> Finding:
        f = Finding(
            id=f"AI-{str(uuid.uuid4())[:8].upper()}",
            module="ai_security",
            false_positive_risk=false_positive_risk,
            owasp_top10=owasp_top10,
            owasp_llm_top10=owasp_llm_top10,
            cwe=cwe,
            tags=tags or [],
            **kwargs,
        )
        self.findings.append(f)
        return f
