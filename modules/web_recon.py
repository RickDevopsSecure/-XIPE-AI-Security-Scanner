"""
XIPE — Web Recon & AI Discovery Module v2
Mejoras: detección de SPA, verificación de JSON real, reducción de falsos positivos.
"""
import uuid
import time
import re
import json
from typing import List, Optional, Dict, Tuple
from urllib.parse import urljoin, urlparse
import httpx

from agent.finding import Finding, Severity, OWASPCategory
from utils.logger import PentestLogger


AI_ENDPOINT_PATTERNS = [
    "/api/v1/chat", "/api/chat", "/v1/chat/completions",
    "/api/v1/query", "/api/query",
    "/api/v1/documents", "/api/documents",
    "/api/v1/assistants", "/api/assistants",
    "/api/v1/workspaces", "/api/workspaces",
    "/api/v1/models", "/v1/models",
    "/api/v1/files", "/api/v1/knowledge",
    "/api/v1/agents", "/api/v1/bots",
    "/api/v1/embed", "/api/v1/embeddings",
    "/health", "/api/health", "/api/v1/health",
    "/api/v1/config", "/api/v1/admin",
    "/swagger.json", "/openapi.json",
    "/.well-known/openai-configuration",
    "/docs", "/api/docs",
]

AI_TECH_HEADERS = [
    "x-openai-version", "x-anthropic-version",
    "x-langchain", "x-flowise",
]

AI_RESPONSE_INDICATORS = [
    "openai", "anthropic", "claude", "gpt", "llm", "langchain",
    "llamaindex", "embedding", "rag", "retrieval",
    "chat completion", "language model", "generative ai",
    "flowise", "ollama", "huggingface",
]

TECH_FINGERPRINTS = {
    "Next.js":    ["__next", "_next/static"],
    "React":      ["react-root", "__reactFiber"],
    "Vue.js":     ["vue-app", "__vue__"],
    "Angular":    ["ng-version", "_nghost"],
    "WordPress":  ["wp-content", "wp-json"],
    "Nginx":      ["server: nginx"],
    "Apache":     ["server: apache"],
    "Cloudflare": ["cf-ray", "server: cloudflare"],
    "AWS":        ["x-amz", "amazonaws.com"],
    "Express":    ["x-powered-by: express"],
    "FastAPI":    ["fastapi", "x-process-time"],
}


class WebReconModule:

    def __init__(self, config: dict, logger: PentestLogger, http_client: httpx.Client):
        self.config = config
        self.logger = logger
        self.client = http_client
        self.findings: List[Finding] = []
        self.base_url = config["scope"]["base_urls"][0].rstrip("/")
        self.discovered_endpoints: Dict[str, dict] = {}
        self.tech_stack: List[str] = []
        self.has_ai: bool = False
        self.is_spa: bool = False
        self._spa_fingerprint: Optional[str] = None

    def run(self) -> List[Finding]:
        self.logger.module_start("Web Recon & AI Discovery")

        self._recon_base()
        self._detect_spa()
        self._discover_ai_endpoints()
        self._update_config_with_discoveries()

        confirmed = sum(1 for e in self.discovered_endpoints.values() if e.get("confirmed"))
        self.logger.info(f"Tech stack: {', '.join(self.tech_stack) or 'Unknown'}")
        self.logger.info(f"SPA detectada: {'SÍ — filtrando falsos positivos' if self.is_spa else 'NO'}")
        self.logger.info(f"Endpoints AI confirmados: {confirmed}")
        self.logger.info(f"Plataforma de IA: {'SÍ' if self.has_ai else 'NO detectada'}")

        self.logger.module_done("Web Recon & AI Discovery", len(self.findings))
        return self.findings

    # ── Base recon ────────────────────────────────────────────────────────────

    def _recon_base(self):
        self.logger.info(f"Reconocimiento de {self.base_url}...")
        try:
            resp = self.client.get(self.base_url, timeout=15, follow_redirects=True)
            self._detect_tech(resp)
            self._check_security_headers(resp)

            body = resp.text.lower()
            ai_found = [ind for ind in AI_RESPONSE_INDICATORS if ind in body]
            if ai_found:
                self.has_ai = True

            if resp.history:
                chain = " → ".join(str(r.url) for r in resp.history)
                self.logger.info(f"Redirect: {chain} → {resp.url}")

        except Exception as e:
            self.logger.error(f"Error en recon base: {e}")

    def _detect_spa(self):
        """
        Detecta si el target es una SPA comparando respuestas de rutas que no existen.
        Una SPA devuelve el mismo HTML 200 para CUALQUIER ruta (incluidas inexistentes).
        """
        canary_paths = [
            f"/__xipe_canary_{uuid.uuid4().hex[:8]}__",
            f"/this_path_does_not_exist_{uuid.uuid4().hex[:6]}",
        ]
        
        canary_responses = []
        for path in canary_paths:
            try:
                resp = self.client.get(
                    self.base_url + path,
                    timeout=8,
                    follow_redirects=True,
                )
                canary_responses.append({
                    "status": resp.status_code,
                    "content_type": resp.headers.get("content-type", ""),
                    "body_snippet": resp.text[:200] if resp.text else "",
                    "length": len(resp.text),
                })
                time.sleep(0.3)
            except Exception:
                canary_responses.append({"status": 0})

        # Es SPA si rutas inexistentes devuelven 200 con HTML
        spa_votes = 0
        for cr in canary_responses:
            if (cr.get("status") == 200 and
                    "html" in cr.get("content_type", "").lower()):
                spa_votes += 1

        if spa_votes >= 1:
            self.is_spa = True
            # Guardar fingerprint del HTML de la SPA para comparar
            if canary_responses and canary_responses[0].get("body_snippet"):
                self._spa_fingerprint = canary_responses[0]["body_snippet"][:100]
            self.logger.warning(
                "SPA detectada — los endpoints que devuelvan HTML serán marcados "
                "como falsos positivos."
            )

    def _is_false_positive(self, resp: httpx.Response) -> Tuple[bool, str]:
        """
        Determina si un 200 es falso positivo.
        Returns: (is_fp, reason)
        """
        content_type = resp.headers.get("content-type", "").lower()
        body = resp.text

        # Si es SPA y devuelve HTML → falso positivo
        if self.is_spa and "html" in content_type:
            return True, "SPA HTML response (not a real API endpoint)"

        # Si el body está vacío → probablemente no es un endpoint real
        if not body or len(body.strip()) < 2:
            return False, ""  # Puede ser un 200 vacío legítimo (health check)

        # Si no es JSON y parece HTML → falso positivo
        if "<html" in body[:200].lower() or "<!doctype" in body[:200].lower():
            return True, "HTML response (not a JSON API endpoint)"

        # Intentar parsear como JSON
        try:
            json.loads(body)
            return False, ""  # JSON válido → no es falso positivo
        except json.JSONDecodeError:
            # No es JSON — puede ser texto plano legítimo o HTML disfrazado
            if "html" in content_type:
                return True, "HTML content-type with non-JSON body"
            # Texto plano puede ser legítimo para /health, /ping
            return False, ""

    # ── Security headers ─────────────────────────────────────────────────────

    def _check_security_headers(self, resp: httpx.Response):
        required = {
            "Strict-Transport-Security": ("MEDIUM", "Add HSTS header."),
            "Content-Security-Policy":   ("MEDIUM", "Implement CSP to prevent XSS."),
            "X-Content-Type-Options":    ("MEDIUM", "Add X-Content-Type-Options: nosniff."),
            "X-Frame-Options":           ("LOW",    "Add X-Frame-Options to prevent clickjacking."),
        }
        resp_lower = {k.lower(): v for k, v in resp.headers.items()}
        for header, (sev, rec) in required.items():
            if header.lower() not in resp_lower:
                self._add_finding(
                    title=f"Missing security header: {header}",
                    severity=Severity[sev],
                    category=OWASPCategory.DATA_EXPOSURE,
                    description=f"Response from {self.base_url} missing '{header}'.",
                    endpoint=self.base_url,
                    recommendation=rec,
                    false_positive_risk="LOW",
                )

        for header in ["server", "x-powered-by", "x-aspnet-version"]:
            if header in resp_lower:
                self._add_finding(
                    title=f"Technology disclosure via header: {header}",
                    severity=Severity.LOW,
                    category=OWASPCategory.DATA_EXPOSURE,
                    description=f"Header reveals technology: {header}: {resp_lower[header]}",
                    endpoint=self.base_url,
                    recommendation=f"Suppress the '{header}' response header.",
                    false_positive_risk="LOW",
                )

    def _detect_tech(self, resp: httpx.Response):
        headers_str = " ".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
        body = resp.text.lower()
        combined = headers_str + " " + body
        for tech, patterns in TECH_FINGERPRINTS.items():
            if any(p.lower() in combined for p in patterns):
                if tech not in self.tech_stack:
                    self.tech_stack.append(tech)
        for h in AI_TECH_HEADERS:
            if h in {k.lower() for k in resp.headers}:
                self.has_ai = True
                self.tech_stack.append(f"AI:{h}")

    # ── AI endpoint discovery ─────────────────────────────────────────────────

    def _discover_ai_endpoints(self):
        self.logger.info(f"Buscando endpoints de IA en {self.base_url}...")
        confirmed_count = 0

        for path in AI_ENDPOINT_PATTERNS:
            url = self.base_url + path
            try:
                resp = self.client.get(url, timeout=8, follow_redirects=False)
                status = resp.status_code

                if status not in (200, 201, 204, 401, 403, 405, 422):
                    continue

                # Verificar si es falso positivo
                is_fp, fp_reason = self._is_false_positive(resp) if status == 200 else (False, "")

                if is_fp:
                    self.logger.info(f"  [{status}] {path} — SKIPPED (false positive: {fp_reason})")
                    continue

                # Determinar severidad real
                severity, description = self._assess_endpoint(path, status, resp)

                self.discovered_endpoints[path] = {
                    "status": status,
                    "confirmed": not is_fp,
                    "severity": severity.value,
                }

                if not is_fp:
                    confirmed_count += 1
                    if status == 200:
                        self.has_ai = True

                self._add_finding(
                    title=f"AI endpoint discovered: {path} (HTTP {status})",
                    severity=severity,
                    category=OWASPCategory.DATA_EXPOSURE,
                    description=description,
                    endpoint=url,
                    response_snippet=resp.text[:300] if status in (200, 201) else None,
                    recommendation=(
                        "Verify this endpoint requires authentication. "
                        "Implement deny-by-default on all API routes."
                    ),
                    false_positive_risk="LOW" if status in (401, 403) else "MEDIUM",
                )
                self.logger.info(f"  [{status}] {path} ✓ confirmed")

            except Exception:
                pass

            time.sleep(0.2)

        self.logger.info(f"Endpoints confirmados: {confirmed_count}")

    def _assess_endpoint(
        self, path: str, status: int, resp: httpx.Response
    ) -> Tuple[Severity, str]:
        """Evalúa severidad real del endpoint."""
        url = self.base_url + path

        if status in (401, 403):
            return (
                Severity.INFO,
                f"Endpoint {url} exists but requires authentication (expected behavior).",
            )

        if status == 200:
            body = resp.text.lower()
            # Endpoints admin sin auth = CRITICAL
            if any(k in path for k in ["/admin", "/config", "/internal"]):
                return (
                    Severity.HIGH,
                    f"Sensitive endpoint {url} returned HTTP 200. "
                    f"Administrative or configuration endpoints should require auth.",
                )
            # Documentación API pública = HIGH
            if any(k in path for k in ["swagger", "openapi", ".well-known"]):
                return (
                    Severity.HIGH,
                    f"API documentation at {url} is publicly accessible. "
                    f"This exposes the full API surface to potential attackers.",
                )
            # AI indicators in response = HIGH
            if any(ind in body for ind in AI_RESPONSE_INDICATORS):
                return (
                    Severity.HIGH,
                    f"Confirmed AI endpoint at {url} responding without authentication. "
                    f"Contains AI platform indicators in response.",
                )
            # Other 200 = MEDIUM
            return (
                Severity.MEDIUM,
                f"Endpoint {url} returned HTTP 200 without authentication credentials. "
                f"Verify if this endpoint should be publicly accessible.",
            )

        if status == 405:
            return (
                Severity.LOW,
                f"Endpoint {url} exists (GET not allowed). "
                f"May accept POST requests — manual verification recommended.",
            )

        return (Severity.INFO, f"Endpoint {url} returned HTTP {status}.")

    # ── Config update ─────────────────────────────────────────────────────────

    def _update_config_with_discoveries(self):
        if not self.discovered_endpoints:
            return

        endpoints = self.config["scope"].setdefault("endpoints", {})
        mapping = {
            "chat":      ["/api/v1/chat", "/api/chat", "/v1/chat/completions"],
            "rag_query": ["/api/v1/query", "/api/query"],
            "documents": ["/api/v1/documents", "/api/documents"],
            "assistants":["/api/v1/assistants"],
            "workspaces":["/api/v1/workspaces"],
            "health":    ["/health", "/api/health"],
        }
        for key, candidates in mapping.items():
            for c in candidates:
                if c in self.discovered_endpoints and self.discovered_endpoints[c].get("confirmed"):
                    endpoints[key] = c
                    break

        if not self.has_ai:
            self.logger.warning("No confirmed AI platform. AI modules may find fewer results.")

    # ── Helper ────────────────────────────────────────────────────────────────

    def _add_finding(self, false_positive_risk: str = "MEDIUM", **kwargs) -> Finding:
        finding = Finding(
            id=f"RECON-{str(uuid.uuid4())[:8].upper()}",
            module="web_recon",
            false_positive_risk=false_positive_risk,
            **kwargs,
        )
        self.findings.append(finding)
        if finding.severity.value in ("HIGH", "CRITICAL"):
            self.logger.finding(finding.severity.value, finding.title)
        return finding
