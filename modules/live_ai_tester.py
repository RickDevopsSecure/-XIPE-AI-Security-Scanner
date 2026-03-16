"""
XIPE — Live AI Interaction Module v2.0 — Powered by Claude
Usa Claude para generar ataques personalizados y analizar respuestas.
"""
import uuid
import time
import json
import re
from typing import List, Dict, Optional
import httpx

from agent.finding import Finding, Severity, OWASPCategory
from agent.ai_brain import XIAIBrain
from modules.librechat_client import LibreChatClient
from utils.logger import PentestLogger


class LiveAITester:

    def __init__(self, config: dict, logger: PentestLogger, http_client: httpx.Client):
        self.config = config
        self.logger = logger
        self.client = http_client
        self.findings: List[Finding] = []
        self.base_url = config["scope"]["base_urls"][0].rstrip("/")
        self.auth_token: Optional[str] = None
        self.chat_endpoint: Optional[str] = None
        self.chat_format: Optional[str] = None
        self.model_info: Dict = {}
        self.attack_history: List[Dict] = []
        self.librechat_client = None
        self.active_conv_id = None

        # Claude es el cerebro
        self.brain = XIAIBrain(logger=logger)

    def run(self) -> List[Finding]:
        self.logger.module_start("Live AI Interaction Tester (Powered by Claude)")

        # Paso 1: Detectar plataforma
        platform = self._detect_platform()
        self.logger.info(f"Plataforma: {platform}")

        # Paso 2: Autenticación
        self._attempt_auth(platform)

        if not self.auth_token and not self.chat_endpoint:
            self.logger.warning("No se pudo autenticar.")
            self.logger.module_done("Live AI Interaction Tester", 0)
            return self.findings

        # Paso 3: Descubrir endpoint
        self._discover_chat_endpoint(platform)

        if not self.chat_endpoint:
            self.logger.warning("No se encontró endpoint de chat.")
            self.logger.module_done("Live AI Interaction Tester", len(self.findings))
            return self.findings

        # Paso 4: Claude analiza el target y genera estrategia
        self.logger.info("🧠 Claude analizando target y generando estrategia de ataque...")
        recon_data = {
            "platform": platform,
            "base_url": self.base_url,
            "model_info": self.model_info,
            "config_data": self._get_public_config(),
        }
        attack_strategy = self.brain.analyze_target(self.base_url, recon_data)
        self.logger.info(f"Estrategia: {attack_strategy.get('platform_type', 'unknown')}")
        self.logger.info(f"Ataques prioritarios: {', '.join(attack_strategy.get('priority_attacks', []))}")

        # Paso 5: Ejecutar ataques con Claude guiando
        self._run_intelligent_attacks(attack_strategy)

        self.logger.module_done("Live AI Interaction Tester", len(self.findings))
        return self.findings

    # ── Platform Detection ────────────────────────────────────────────────────

    def _detect_platform(self) -> str:
        try:
            resp = self.client.get(f"{self.base_url}/api/config", timeout=10)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "registrationEnabled" in data:
                        return "librechat"
                except Exception:
                    pass
            resp2 = self.client.get(f"{self.base_url}/v1/models", timeout=8)
            if resp2.status_code == 200:
                try:
                    data2 = resp2.json()
                    if "data" in data2:
                        return "openai_api"
                except Exception:
                    pass
        except Exception:
            pass
        return "unknown"

    def _get_public_config(self) -> Dict:
        try:
            resp = self.client.get(f"{self.base_url}/api/config", timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return {}

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _attempt_auth(self, platform: str):
        if platform == "librechat":
            self._auth_librechat()
        elif platform == "openai_api":
            self.chat_endpoint = f"{self.base_url}/v1/chat/completions"
            self.chat_format = "openai"

    def _auth_librechat(self):
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
                self.logger.info(f"Registro: {test_email}")

                login = self.client.post(
                    f"{self.base_url}/api/auth/login",
                    json={"email": test_email, "password": test_pass},
                    timeout=15,
                )
                if login.status_code == 200:
                    data = login.json()
                    self.auth_token = data.get("token")
                    user = data.get("user", {})

                    # Hallazgo: email verification bypass
                    if user.get("emailVerified"):
                        self._add_finding(
                            title="Email verification bypass — accounts auto-verified without email confirmation",
                            severity=Severity.HIGH,
                            category=OWASPCategory.AUTH_BYPASS,
                            description=(
                                f"Account created with unverified email ({test_email}) was "
                                f"immediately logged in with emailVerified=true. "
                                f"This allows mass account creation with disposable emails "
                                f"to access the AI platform without any verification."
                            ),
                            endpoint=f"{self.base_url}/api/auth/login",
                            response_snippet=json.dumps(user, indent=2)[:300],
                            recommendation="Enforce email verification. Block login if emailVerified=false.",
                            false_positive_risk="LOW",
                        )
                        self.logger.warning("🚨 Email verification bypass confirmed!")

                    # Hallazgo: registro abierto
                    self._add_finding(
                        title="Open registration — unauthenticated account creation enabled",
                        severity=Severity.MEDIUM,
                        category=OWASPCategory.AUTH_BYPASS,
                        description=(
                            f"The platform allows anyone to register without invitation or approval. "
                            f"Combined with email verification bypass, attackers can create unlimited "
                            f"accounts to abuse AI resources or escalate privileges."
                        ),
                        endpoint=f"{self.base_url}/api/auth/register",
                        recommendation="Implement invitation-only registration or email domain whitelist.",
                        false_positive_risk="LOW",
                    )

                    # Aceptar términos
                    if self.auth_token:
                        self.client.post(
                            f"{self.base_url}/api/user/terms/accept",
                            headers={"Authorization": f"Bearer {self.auth_token}"},
                            timeout=10,
                        )
                        self.logger.info(f"Auth OK: {self.auth_token[:30]}...")
        except Exception as e:
            self.logger.error(f"Auth error: {e}")

    # ── Chat Endpoint Discovery ───────────────────────────────────────────────

    def _discover_chat_endpoint(self, platform: str):
        headers = {}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        if platform == "librechat":
            try:
                resp = self.client.get(
                    f"{self.base_url}/api/endpoints",
                    headers=headers, timeout=10,
                )
                if resp.status_code == 200:
                    endpoints = resp.json()
                    if endpoints:
                        endpoint_name = list(endpoints.keys())[0]
                        endpoint_type = endpoints[endpoint_name].get("type", "custom")
                        self.model_info["endpoint_name"] = endpoint_name
                        self.model_info["endpoint_type"] = endpoint_type
                        self.model_info["endpoints"] = endpoints
                        self.chat_format = "librechat"
                        self.chat_endpoint = f"{self.base_url}/api/ask/{endpoint_type}"
                        self.logger.info(f"Chat endpoint: {self.chat_endpoint}")
            except Exception as e:
                self.logger.error(f"Error discovering endpoints: {e}")

        elif platform == "openai_api":
            self.chat_endpoint = f"{self.base_url}/v1/chat/completions"
            self.chat_format = "openai"

    # ── Intelligent Attack Runner ─────────────────────────────────────────────

    def _run_intelligent_attacks(self, strategy: Dict):
        """
        Claude guía la secuencia de ataques adaptándose a las respuestas.
        """
        custom_prompts = strategy.get("custom_prompts", {})
        priority_attacks = strategy.get("priority_attacks", [])

        attack_categories = [
            ("system_prompt_leakage", "LLM07 - System Prompt Leakage"),
            ("injection", "LLM01 - Prompt Injection"),
            ("data_extraction", "LLM02 - Sensitive Data Extraction"),
            ("jailbreak", "LLM01 - Jailbreak"),
        ]

        for category_key, attack_label in attack_categories:
            prompts = custom_prompts.get(category_key, [])

            if not prompts:
                # Claude genera prompts si no tiene para esta categoría
                self.logger.info(f"🧠 Claude generando ataques para {category_key}...")
                generated = self.brain.generate_next_attack(
                    self.attack_history,
                    strategy,
                    category_key,
                )
                if generated:
                    prompts = [generated]

            if not prompts:
                continue

            self.logger.info(f"Testing {attack_label} ({len(prompts)} prompts)...")

            for prompt in prompts:
                response = self._send_message(prompt)

                if response:
                    # Claude analiza la respuesta
                    analysis = self.brain.analyze_response(
                        attack_prompt=prompt,
                        ai_response=response,
                        attack_type=category_key,
                        target_context=strategy,
                    )

                    # Guardar en historial para ataques adaptativos
                    self.attack_history.append({
                        "prompt": prompt,
                        "response": response[:200],
                        "is_vulnerability": analysis.get("is_vulnerability", False),
                        "category": category_key,
                    })

                    if analysis.get("is_vulnerability"):
                        # Claude redacta el hallazgo profesionalmente
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
                            analysis.get("severity", "MEDIUM").upper(),
                            Severity.MEDIUM
                        )

                        self._add_finding(
                            title=written.get("title", analysis.get("finding_title", f"AI vulnerability: {category_key}")),
                            severity=severity,
                            category=OWASPCategory.PROMPT_INJECTION,
                            description=written.get("technical_description", analysis.get("finding_description", "")),
                            endpoint=self.chat_endpoint,
                            response_snippet=f"Prompt: {prompt[:150]}\n\nResponse: {response[:300]}",
                            recommendation=written.get("remediation", analysis.get("recommendation", "")),
                            false_positive_risk="LOW",
                        )
                        self.logger.finding(
                            severity.value,
                            f"Claude confirmed: {analysis.get('finding_title', category_key)}"
                        )

                else:
                    self.logger.info(f"  No response for {category_key} prompt")

                time.sleep(2)

    # ── Message Sender ────────────────────────────────────────────────────────

    def _send_message(self, text: str) -> Optional[str]:
        if not self.auth_token:
            return None
        if self.chat_format == "librechat":
            if not self.librechat_client:
                from modules.librechat_client import LibreChatClient
                self.librechat_client = LibreChatClient(self.base_url, self.auth_token)
            response = self.librechat_client.send_message(text, self.active_conv_id)
            if response:
                self.logger.info(f"  ✓ AI response: {response[:80]}")
            return response
        elif self.chat_format == "openai":
            return self._send_openai(text, {"Content-Type": "application/json", "Authorization": f"Bearer {self.auth_token}"})
        return None

    def _send_librechat(self, text: str, headers: dict) -> Optional[str]:
        endpoint_name = self.model_info.get("endpoint_name", "OpenWild")
        endpoint_type = self.model_info.get("endpoint_type", "custom")

        payload = {
            "text": text,
            "endpoint": endpoint_name,
            "endpointType": endpoint_type,
            "model": endpoint_name,
            "conversationId": "new",
            "parentMessageId": "00000000-0000-0000-0000-000000000000",
        }

        try:
            with self.client.stream(
                "POST",
                f"{self.base_url}/api/ask/{endpoint_type}",
                headers=headers,
                json=payload,
                timeout=60,
            ) as resp:
                content_type = resp.headers.get("content-type", "")
                if "text/html" in content_type or resp.status_code != 200:
                    return None

                full_response = ""
                final_message = None

                for line in resp.iter_lines():
                    if not line or not line.startswith("data:"):
                        continue
                    data_str = line[5:].strip()
                    if data_str == "[DONE]":
                        break
                    try:
                        data = json.loads(data_str)
                        if "text" in data:
                            full_response += data["text"]
                        elif "message" in data and "content" in data.get("message", {}):
                            final_message = data["message"]["content"]
                        elif "final" in data and data.get("final"):
                            final_message = data.get("responseMessage", {}).get("text", full_response)
                    except json.JSONDecodeError:
                        pass

                return (final_message or full_response).strip() or None

        except Exception as e:
            self.logger.error(f"LibreChat stream error: {e}")
            return None

    def _send_openai(self, text: str, headers: dict) -> Optional[str]:
        payload = {
            "model": self.model_info.get("model", "gpt-3.5-turbo"),
            "messages": [{"role": "user", "content": text}],
        }
        resp = self.client.post(self.chat_endpoint, headers=headers, json=payload, timeout=30)
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"]
        return None

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
