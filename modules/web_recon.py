"""
XIPE — Web Recon & AI Discovery Module
Reconocimiento completo del target antes de los módulos de AI pentesting.
Detecta automáticamente si tiene plataforma de IA y qué endpoints existen.
"""
import uuid
import time
import re
from typing import List, Optional, Dict
from urllib.parse import urljoin, urlparse
import httpx

from agent.finding import Finding, Severity, OWASPCategory
from utils.logger import PentestLogger


# ─── Paths comunes de APIs de IA ─────────────────────────────────────────────
AI_ENDPOINT_PATTERNS = [
    # Chat / completions
    "/api/v1/chat", "/api/chat", "/v1/chat/completions", "/api/completions",
    "/chat", "/chat/completions", "/api/v1/completions", "/api/message",
    "/api/v1/message", "/api/v1/messages", "/api/messages",

    # RAG / search
    "/api/v1/query", "/api/query", "/api/search", "/api/v1/search",
    "/api/v1/rag", "/api/rag", "/search", "/api/v1/retrieve",

    # Documents / knowledge base
    "/api/v1/documents", "/api/documents", "/api/v1/files", "/api/files",
    "/api/v1/knowledge", "/documents", "/files",

    # Assistants / agents
    "/api/v1/assistants", "/api/assistants", "/api/v1/agents", "/api/agents",
    "/api/v1/bots", "/api/bots", "/assistants",

    # Workspaces / tenants
    "/api/v1/workspaces", "/api/workspaces", "/api/v1/organizations",
    "/api/organizations", "/api/v1/tenants",

    # Models
    "/api/v1/models", "/api/models", "/v1/models",

    # Common AI platform paths
    "/api/v1/prompt", "/api/prompt", "/api/v1/generate", "/api/generate",
    "/api/v1/embed", "/api/embed", "/api/v1/embeddings",

    # Health / info
    "/health", "/api/health", "/status", "/api/status",
    "/api/v1/health", "/ping", "/api/ping",

    # Docs / swagger
    "/docs", "/api/docs", "/swagger", "/swagger.json",
    "/openapi.json", "/api/openapi.json", "/.well-known/openai-configuration",

    # Admin
    "/api/v1/admin", "/admin", "/api/admin",
    "/api/v1/config", "/api/config",
]

# Headers que revelan tecnología de IA
AI_TECH_HEADERS = [
    "x-openai-version", "x-anthropic-version", "x-cohere-version",
    "x-langchain", "x-llamaindex", "x-flowise", "x-rasa",
]

# Strings en respuestas que indican IA
AI_RESPONSE_INDICATORS = [
    "openai", "anthropic", "claude", "gpt", "llm", "langchain",
    "llamaindex", "vector", "embedding", "rag", "retrieval",
    "chat completion", "language model", "generative ai",
    "assistant", "chatbot", "flowise", "ollama", "huggingface",
]

# Tech stack fingerprints
TECH_FINGERPRINTS = {
    "Next.js":       ["__next", "_next/static", "x-powered-by: next.js"],
    "React":         ["react-root", "__reactFiber", "react.development"],
    "Vue.js":        ["vue-app", "__vue__", "data-v-"],
    "Angular":       ["ng-version", "_nghost", "ng-app"],
    "WordPress":     ["wp-content", "wp-includes", "wp-json"],
    "Nginx":         ["server: nginx"],
    "Apache":        ["server: apache"],
    "Cloudflare":    ["cf-ray", "server: cloudflare"],
    "AWS":           ["x-amz", "amazonaws.com", "x-amzn"],
    "Vercel":        ["x-vercel", "server: vercel"],
    "FastAPI":       ["fastapi", "x-process-time"],
    "Django":        ["csrfmiddlewaretoken", "django"],
    "Flask":         ["werkzeug", "flask"],
    "Express":       ["x-powered-by: express"],
    "OpenAI API":    ["x-openai", "openai"],
    "Flowise":       ["flowise", "x-flowise"],
    "Langchain":     ["langchain", "langserve"],
}


class WebReconModule:
    """
    Reconocimiento web completo del target.
    
    Ejecuta:
    1. HTTP recon — headers, tech stack, redirect chain
    2. AI endpoint discovery — busca automáticamente endpoints de IA
    3. Security headers audit
    4. Certificate info
    5. Subdomain recon básico (www, api, app, admin, dev, staging)
    6. Actualiza config con endpoints descubiertos
    """

    def __init__(self, config: dict, logger: PentestLogger, http_client: httpx.Client):
        self.config = config
        self.logger = logger
        self.client = http_client
        self.findings: List[Finding] = []
        self.base_url = config["scope"]["base_urls"][0].rstrip("/")
        self.discovered_endpoints: Dict[str, int] = {}
        self.tech_stack: List[str] = []
        self.has_ai: bool = False

    def run(self) -> List[Finding]:
        self.logger.module_start("Web Recon & AI Discovery")

        self._recon_base()
        self._discover_subdomains()
        self._discover_ai_endpoints()
        self._update_config_with_discoveries()

        self.logger.info(f"Tech stack detectado: {', '.join(self.tech_stack) or 'No identificado'}")
        self.logger.info(f"Endpoints AI encontrados: {len(self.discovered_endpoints)}")
        self.logger.info(f"Plataforma de IA: {'SÍ' if self.has_ai else 'NO detectada'}")

        self.logger.module_done("Web Recon & AI Discovery", len(self.findings))
        return self.findings

    def _recon_base(self):
        """Reconocimiento del sitio principal."""
        self.logger.info(f"Reconocimiento de {self.base_url}...")

        try:
            resp = self.client.get(self.base_url, timeout=15, follow_redirects=True)

            # Tech stack detection
            self._detect_tech(resp)

            # Security headers
            self._check_security_headers(resp)

            # Check for AI indicators in response
            body = resp.text.lower()
            ai_found = [ind for ind in AI_RESPONSE_INDICATORS if ind in body]
            if ai_found:
                self.has_ai = True
                self._add_finding(
                    title=f"AI platform indicators found in response: {', '.join(ai_found[:3])}",
                    severity=Severity.INFO,
                    category=OWASPCategory.DATA_EXPOSURE,
                    description=(
                        f"The target {self.base_url} contains references to AI technologies: "
                        f"{', '.join(ai_found)}. This confirms the presence of AI components."
                    ),
                    endpoint=self.base_url,
                    response_snippet=resp.text[:300],
                    recommendation="Verify that AI components are properly secured and not exposing sensitive configuration.",
                )

            # Redirect chain info
            if resp.history:
                self.logger.info(f"Redirect chain: {' → '.join(str(r.url) for r in resp.history)} → {resp.url}")

        except Exception as e:
            self.logger.error(f"Error en recon base: {e}")
            self._add_finding(
                title=f"Target unreachable: {self.base_url}",
                severity=Severity.INFO,
                category=OWASPCategory.DATA_EXPOSURE,
                description=f"Could not connect to {self.base_url}: {str(e)}",
                endpoint=self.base_url,
                recommendation="Verify the target URL is correct and accessible.",
            )

    def _detect_tech(self, resp: httpx.Response):
        """Detecta el tech stack del target."""
        headers_str = " ".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
        body = resp.text.lower()
        combined = headers_str + " " + body

        for tech, patterns in TECH_FINGERPRINTS.items():
            if any(p.lower() in combined for p in patterns):
                if tech not in self.tech_stack:
                    self.tech_stack.append(tech)

        # Check AI-specific headers
        for header in AI_TECH_HEADERS:
            if header in resp.headers:
                self.has_ai = True
                self.tech_stack.append(f"AI: {header}")

    def _check_security_headers(self, resp: httpx.Response):
        """Audita headers de seguridad."""
        required = {
            "Strict-Transport-Security": ("MEDIUM", "Add HSTS header to enforce HTTPS connections."),
            "Content-Security-Policy":   ("MEDIUM", "Implement CSP to prevent XSS attacks."),
            "X-Content-Type-Options":    ("MEDIUM", "Add X-Content-Type-Options: nosniff."),
            "X-Frame-Options":           ("LOW",    "Add X-Frame-Options to prevent clickjacking."),
            "Referrer-Policy":           ("LOW",    "Add Referrer-Policy to control referrer information."),
        }

        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header, (sev, rec) in required.items():
            if header.lower() not in resp_headers_lower:
                self._add_finding(
                    title=f"Missing security header: {header}",
                    severity=Severity[sev],
                    category=OWASPCategory.DATA_EXPOSURE,
                    description=f"The response from {self.base_url} does not include the '{header}' security header.",
                    endpoint=self.base_url,
                    recommendation=rec,
                )

        # Check for sensitive headers
        sensitive = {
            "server":        "Server version disclosure",
            "x-powered-by":  "Technology stack disclosure",
            "x-aspnet-version": "ASP.NET version disclosure",
        }
        for header, issue in sensitive.items():
            if header in resp_headers_lower:
                self._add_finding(
                    title=f"Information disclosure via header: {header}",
                    severity=Severity.LOW,
                    category=OWASPCategory.DATA_EXPOSURE,
                    description=f"{issue}: {header}: {resp_headers_lower[header]}",
                    endpoint=self.base_url,
                    recommendation=f"Remove or suppress the '{header}' header from responses.",
                )

    def _discover_subdomains(self):
        """Verifica subdominios comunes."""
        self.logger.info("Verificando subdominios comunes...")
        parsed = urlparse(self.base_url)
        domain = parsed.netloc.replace("www.", "")
        scheme = parsed.scheme

        subdomains = ["api", "app", "admin", "dev", "staging", "portal",
                      "dashboard", "chat", "ai", "bot", "docs"]

        for sub in subdomains:
            url = f"{scheme}://{sub}.{domain}"
            try:
                resp = self.client.get(url, timeout=5, follow_redirects=True)
                if resp.status_code < 400:
                    self._add_finding(
                        title=f"Active subdomain discovered: {sub}.{domain}",
                        severity=Severity.INFO,
                        category=OWASPCategory.DATA_EXPOSURE,
                        description=(
                            f"Subdomain {url} is active (HTTP {resp.status_code}). "
                            f"This may expose additional attack surface."
                        ),
                        endpoint=url,
                        response_snippet=resp.text[:200],
                        recommendation="Ensure all active subdomains are within the security scope and properly hardened.",
                    )
                    self.logger.info(f"Subdomain activo: {url} ({resp.status_code})")
            except Exception:
                pass
            time.sleep(0.3)

    def _discover_ai_endpoints(self):
        """Descubre endpoints de IA activos en el target."""
        self.logger.info(f"Buscando endpoints de IA en {self.base_url}...")
        found_count = 0

        for path in AI_ENDPOINT_PATTERNS:
            url = self.base_url + path
            try:
                # GET request
                resp = self.client.get(url, timeout=8, follow_redirects=False)
                status = resp.status_code

                if status in (200, 201, 204, 401, 403, 405, 422):
                    self.discovered_endpoints[path] = status
                    found_count += 1

                    severity = Severity.INFO
                    desc = f"Endpoint {url} responded with HTTP {status}."

                    if status == 200:
                        severity = Severity.MEDIUM
                        desc += " Endpoint is accessible without authentication."
                        self.has_ai = True

                        # Check if response looks like AI
                        body = resp.text.lower()
                        if any(ind in body for ind in AI_RESPONSE_INDICATORS):
                            severity = Severity.HIGH
                            desc += " Response contains AI platform indicators."

                    elif status in (401, 403):
                        desc += " Endpoint exists but requires authentication (good)."

                    elif status == 405:
                        desc += " Endpoint exists (GET not allowed — try POST)."
                        # Try POST
                        try:
                            post_resp = self.client.post(
                                url,
                                json={"messages": [{"role": "user", "content": "test"}]},
                                timeout=8,
                            )
                            if post_resp.status_code == 200:
                                severity = Severity.HIGH
                                desc += f" POST returns HTTP 200 without authentication!"
                                self.has_ai = True
                                self.discovered_endpoints[path] = 200
                        except Exception:
                            pass

                    self._add_finding(
                        title=f"AI endpoint discovered: {path} (HTTP {status})",
                        severity=severity,
                        category=OWASPCategory.DATA_EXPOSURE,
                        description=desc,
                        endpoint=url,
                        response_snippet=resp.text[:200] if status == 200 else None,
                        recommendation=(
                            "Verify this endpoint is intentionally public. "
                            "Implement authentication if not required to be public. "
                            "Review what data is exposed via this endpoint."
                        ),
                    )

                    self.logger.info(f"  [{status}] {path}")

            except Exception:
                pass

            time.sleep(0.2)

        self.logger.info(f"Endpoints encontrados: {found_count}")

    def _update_config_with_discoveries(self):
        """Actualiza el config con los endpoints descubiertos para que otros módulos los usen."""
        if not self.discovered_endpoints:
            return

        endpoints = self.config["scope"].setdefault("endpoints", {})

        # Mapear endpoints descubiertos al config
        mapping = {
            "chat":       ["/api/v1/chat", "/api/chat", "/chat", "/v1/chat/completions"],
            "rag_query":  ["/api/v1/query", "/api/query", "/api/search", "/api/v1/search"],
            "documents":  ["/api/v1/documents", "/api/documents", "/documents"],
            "assistants": ["/api/v1/assistants", "/api/assistants", "/assistants"],
            "workspaces": ["/api/v1/workspaces", "/api/workspaces"],
            "health":     ["/health", "/api/health", "/status", "/ping"],
        }

        for endpoint_key, candidates in mapping.items():
            for candidate in candidates:
                if candidate in self.discovered_endpoints:
                    endpoints[endpoint_key] = candidate
                    break

        # Si no tiene endpoints de IA, desactivar módulos de IA
        if not self.has_ai:
            self.logger.warning(
                "No se detectó plataforma de IA. "
                "Los módulos de AI pentesting pueden no encontrar hallazgos relevantes."
            )
            # Aun así corremos — puede haber falsos negativos en el recon

    def _add_finding(self, **kwargs) -> Finding:
        finding = Finding(
            id=f"RECON-{str(uuid.uuid4())[:8].upper()}",
            module="web_recon",
            false_positive_risk="LOW",
            **kwargs,
        )
        self.findings.append(finding)
        if finding.severity.value in ("HIGH", "CRITICAL"):
            self.logger.finding(finding.severity.value, finding.title)
        return finding
