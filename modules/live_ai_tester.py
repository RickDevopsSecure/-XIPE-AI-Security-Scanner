"""
XIPE — Live AI Interaction Tester v3.0
Full AI-powered: works with ANY AI platform.
AI Brain generates attacks, analyzes responses, writes findings.
"""
import uuid
import time
import json
from typing import List, Dict, Optional
import httpx

from agent.finding import Finding, Severity, OWASPCategory
from agent.ai_brain import XIAIBrain
from modules.universal_ai_client import UniversalAIClient
from utils.logger import PentestLogger


class LiveAITester:

    def __init__(self, config: dict, logger: PentestLogger, http_client: httpx.Client):
        self.config = config
        self.logger = logger
        self.client = http_client
        self.findings: List[Finding] = []
        self.base_url = config["scope"]["base_urls"][0].rstrip("/")
        self.auth_token: Optional[str] = None
        self.attack_history: List[Dict] = []

        # AI Brain — generates attacks and analyzes responses
        self.brain = XIAIBrain(logger=logger)

        # Universal client — talks to ANY AI platform
        self.ai_client: Optional[UniversalAIClient] = None

    def run(self) -> List[Finding]:
        self.logger.module_start("Live AI Interaction Tester v3 (Universal + Full AI)")

        # Step 1: Detect platform
        self.ai_client = UniversalAIClient(
            base_url=self.base_url,
            logger=self.logger,
        )
        platform = self.ai_client.detect_platform()
        self.logger.info(f"Platform: {platform}")

        # Step 2: Authenticate if possible
        self._attempt_auth(platform)
        if self.auth_token:
            self.ai_client.token = self.auth_token

        # Step 3: Find the chat endpoint
        chat_endpoint = self.ai_client.discover_chat_endpoint()
        if not chat_endpoint:
            self.logger.warning("No chat endpoint found — skipping live AI attacks")
            self.logger.module_done("Live AI Interaction Tester v3", len(self.findings))
            return self.findings
        self.logger.info(f"Chat endpoint: {chat_endpoint} [{self.ai_client.chat_format}]")

        # Step 4: Test basic connectivity — send one message to confirm it works
        self.logger.info("Testing chat connectivity...")
        test_response = self.ai_client.send_message("Hello, what can you help me with?")
        if test_response:
            self.logger.info(f"✅ Chat working — response: {test_response[:80]}...")
        else:
            self.logger.warning("Chat not responding — attacks will attempt anyway")

        # Step 5: Brain analyzes target and generates attack strategy
        self.logger.info("🧠 AI Brain analyzing target and generating attack strategy...")
        recon_data = {
            "platform": platform,
            "base_url": self.base_url,
            "chat_format": self.ai_client.chat_format,
            "config": self.ai_client.platform_config,
            "auth_available": bool(self.auth_token),
            "test_response": test_response[:200] if test_response else None,
        }
        strategy = self.brain.analyze_target(self.base_url, recon_data)
        self.logger.info(f"Strategy: {strategy.get('platform_type', 'unknown')}")
        self.logger.info(f"Priority attacks: {', '.join(strategy.get('priority_attacks', [])[:3])}")

        # Step 6: Execute all attack categories with AI guidance
        self._run_intelligent_attacks(strategy, test_response)

        self.logger.module_done("Live AI Interaction Tester v3", len(self.findings))
        return self.findings

    # ── Authentication ────────────────────────────────────────────────────────

    def _attempt_auth(self, platform: str):
        """Try to authenticate on the platform."""
        if platform == "librechat":
            self._auth_librechat()
        elif platform == "openai_api":
            pass  # API key auth handled separately
        elif platform == "flowise":
            pass  # No auth by default
        # For unknown platforms — try common auth patterns
        elif platform == "unknown":
            self._try_generic_auth()

    def _auth_librechat(self):
        """Auto-register and login on LibreChat."""
        test_email = f"xipe_{uuid.uuid4().hex[:6]}@mailnull.com"
        test_pass = "XipePentest2026!"

        try:
            reg = self.client.post(
                f"{self.base_url}/api/auth/register",
                json={"name": "XIPE Scanner", "email": test_email,
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

                    # Finding: email verification bypass
                    if user.get("emailVerified"):
                        self._add_finding(
                            title="Email Verification Bypass — Accounts auto-verified without email confirmation",
                            severity=Severity.HIGH,
                            category=OWASPCategory.AUTH_BYPASS,
                            description=(
                                f"Account {test_email} logged in successfully without email verification. "
                                f"emailVerified=true was set automatically. Allows mass account creation "
                                f"with disposable emails to abuse AI resources."
                            ),
                            endpoint=f"{self.base_url}/api/auth/login",
                            recommendation="Enforce email verification. Block login for emailVerified=false.",
                        )
                        self.logger.warning("🚨 Email verification bypass confirmed!")

                    # Finding: open registration
                    self._add_finding(
                        title="Open Registration — Unauthenticated account creation enabled",
                        severity=Severity.MEDIUM,
                        category=OWASPCategory.AUTH_BYPASS,
                        description=(
                            "Platform allows open registration without invitation or approval. "
                            "Combined with email bypass, attackers can create unlimited accounts."
                        ),
                        endpoint=f"{self.base_url}/api/auth/register",
                        recommendation="Implement invitation-only or admin-approval registration.",
                    )

                    # Accept terms
                    if self.auth_token:
                        self.client.post(
                            f"{self.base_url}/api/user/terms/accept",
                            headers={"Authorization": f"Bearer {self.auth_token}"},
                            timeout=10,
                        )
                        self.logger.info(f"Auth OK: {self.auth_token[:30]}...")
        except Exception as e:
            self.logger.error(f"Auth error: {e}")

    def _try_generic_auth(self):
        """Try common authentication patterns on unknown platforms."""
        common_auth_endpoints = [
            "/api/auth/login",
            "/auth/login",
            "/login",
            "/api/login",
            "/api/v1/auth",
        ]
        test_creds = [
            {"username": "admin", "password": "admin"},
            {"email": "admin@admin.com", "password": "admin"},
            {"user": "test", "pass": "test"},
        ]
        for endpoint in common_auth_endpoints:
            for creds in test_creds:
                try:
                    resp = self.client.post(
                        self.base_url + endpoint,
                        json=creds,
                        timeout=5,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        token = (data.get("token") or data.get("access_token") or
                                 data.get("jwt") or data.get("accessToken"))
                        if token:
                            self.auth_token = token
                            self.logger.warning(f"🚨 Default credentials work: {creds} at {endpoint}")
                            self._add_finding(
                                title=f"Default Credentials Accepted — {endpoint}",
                                severity=Severity.CRITICAL,
                                category=OWASPCategory.AUTH_BYPASS,
                                description=f"Platform accepts default credentials: {creds}",
                                endpoint=self.base_url + endpoint,
                                recommendation="Change all default credentials immediately.",
                            )
                            return
                except Exception:
                    pass

    # ── Intelligent Attack Runner ─────────────────────────────────────────────

    def _run_intelligent_attacks(self, strategy: Dict, test_response: Optional[str]):
        """
        Full AI-powered attack sequence.
        Brain generates prompts, XIPE sends them, Brain analyzes responses.
        """
        attack_categories = [
            ("system_prompt_leakage", "LLM07 — System Prompt Leakage"),
            ("injection", "LLM01 — Direct Prompt Injection"),
            ("data_extraction", "LLM02 — Sensitive Data Extraction"),
            ("jailbreak", "LLM01 — Jailbreak Attempts"),
            ("indirect_injection", "LLM08 — Indirect Prompt Injection"),
            ("excessive_agency", "LLM06 — Excessive Agency"),
        ]

        custom_prompts = strategy.get("custom_prompts", {})

        for category_key, label in attack_categories:
            prompts = custom_prompts.get(category_key, [])

            # Brain generates additional prompts based on history
            self.logger.info(f"🧠 Generating attacks: {label}...")
            for _ in range(max(0, 3 - len(prompts))):
                generated = self.brain.generate_next_attack(
                    self.attack_history, strategy, category_key
                )
                if generated and generated not in prompts:
                    prompts.append(generated)

            if not prompts:
                self.logger.info(f"  No prompts generated for {category_key}")
                continue

            self.logger.info(f"Testing {label} ({len(prompts)} prompts)...")

            for prompt in prompts:
                response = self.ai_client.send_message(prompt)

                if response:
                    self.logger.info(f"  ✓ Got response ({len(response)} chars)")

                    # Brain analyzes the response
                    analysis = self.brain.analyze_response(
                        attack_prompt=prompt,
                        ai_response=response,
                        attack_type=category_key,
                        target_context=strategy,
                    )

                    # Record for adaptive next attacks
                    self.attack_history.append({
                        "prompt": prompt[:200],
                        "response": response[:200],
                        "is_vulnerability": analysis.get("is_vulnerability", False),
                        "category": category_key,
                    })

                    if analysis.get("is_vulnerability"):
                        # Brain writes the professional finding
                        written = self.brain.write_finding(
                            raw_finding=analysis,
                            target_context=strategy,
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
                            analysis.get("severity", "MEDIUM").upper(), Severity.MEDIUM
                        )

                        self._add_finding(
                            title=written.get("title", analysis.get("finding_title", f"AI vulnerability: {category_key}")),
                            severity=severity,
                            category=OWASPCategory.PROMPT_INJECTION,
                            description=written.get("technical_description", analysis.get("finding_description", "")),
                            endpoint=self.ai_client.chat_endpoint,
                            response_snippet=f"Prompt: {prompt[:150]}\n\nResponse: {response[:400]}",
                            recommendation=written.get("remediation", analysis.get("recommendation", "")),
                        )
                        self.logger.finding(
                            severity.value,
                            written.get("title", category_key)[:80]
                        )
                else:
                    self.logger.info(f"  No response for {category_key} prompt")

                time.sleep(2)

    # ── Helper ────────────────────────────────────────────────────────────────

    def _add_finding(self, false_positive_risk: str = "LOW", **kwargs) -> Finding:
        finding = Finding(
            id=f"LIVE-{str(uuid.uuid4())[:8].upper()}",
            module="live_ai_tester",
            false_positive_risk=false_positive_risk,
            **kwargs,
        )
        self.findings.append(finding)
        return finding
