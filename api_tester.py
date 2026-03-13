"""
Módulo: API Security Tester
Cubre: Auth bypass, IDOR, excessive data exposure, rate limiting
Tests autorizados sobre las APIs del cliente.
"""
import uuid
import time
from typing import List, Optional, Dict, Any
import httpx

from agent.finding import Finding, Severity, OWASPCategory
from utils.logger import PentestLogger


class APITester:
    """
    Prueba de seguridad en APIs del cliente.
    
    Tests incluidos:
    - Endpoints sin autenticación (dentro del scope autorizado)
    - IDOR en recursos de IA (workspaces, assistants, users)
    - Excessive data exposure
    - Rate limiting / DoS suave
    - Headers de seguridad
    - Métodos HTTP no esperados
    """

    def __init__(self, config: dict, logger: PentestLogger, http_client: httpx.Client):
        self.config = config
        self.logger = logger
        self.client = http_client
        self.findings: List[Finding] = []
        
        self.base_url = config["scope"]["base_urls"][0]
        self.endpoints = config["scope"]["endpoints"]
        self.credentials = config["scope"]["credentials"]

    def run(self) -> List[Finding]:
        self.logger.module_start("API Security Tester")
        
        self._test_unauthenticated_access()
        self._test_idor_resources()
        self._test_http_methods()
        self._test_security_headers()
        self._test_rate_limiting()
        self._test_information_disclosure()
        
        self.logger.module_done("API Security Tester", len(self.findings))
        return self.findings

    def _test_unauthenticated_access(self):
        """Prueba acceso a endpoints SIN credenciales."""
        self.logger.info("Probando acceso sin autenticación en endpoints del scope...")
        
        # Endpoints que deberían requerir auth
        protected_endpoints = [
            self.endpoints.get("chat", "/api/v1/chat"),
            self.endpoints.get("rag_query", "/api/v1/query"),
            self.endpoints.get("documents", "/api/v1/documents"),
            self.endpoints.get("assistants", "/api/v1/assistants"),
            self.endpoints.get("workspaces", "/api/v1/workspaces"),
        ]
        
        # Endpoints que pueden ser públicos
        public_endpoints = [
            self.endpoints.get("health", "/health"),
            "/metrics",
            "/api/v1/models",  # Común en plataformas de IA
            "/api/v1/version",
        ]
        
        for endpoint in protected_endpoints:
            time.sleep(self.config["testing"]["request_delay_seconds"])
            url = self.base_url + endpoint
            
            # Sin ningún header de auth
            try:
                resp = self.client.get(url, headers={"Content-Type": "application/json"},
                                       timeout=self.config["testing"]["timeout_seconds"])
                
                if resp.status_code == 200:
                    self._add_finding(
                        title=f"Endpoint protegido accesible sin autenticación: {endpoint}",
                        severity=Severity.CRITICAL,
                        category=OWASPCategory.AUTH_BYPASS,
                        description=(
                            f"El endpoint {url} devolvió HTTP 200 sin presentar credenciales. "
                            "Este endpoint debería requerir autenticación."
                        ),
                        endpoint=url,
                        response_snippet=resp.text[:400],
                        recommendation=(
                            "Implementar middleware de autenticación en todos los endpoints protegidos. "
                            "Verificar que no existan rutas que bypaseen el middleware de auth. "
                            "Implementar deny-by-default en el API gateway."
                        ),
                    )
                elif resp.status_code == 403:
                    self.logger.success(f"Auth correcta en {endpoint} (403)")
                elif resp.status_code == 401:
                    self.logger.success(f"Auth correcta en {endpoint} (401)")
                    
            except Exception as e:
                self.logger.error(f"Error probando {url}: {e}")
        
        # Para endpoints públicos, verificar que no expongan demasiado
        for endpoint in public_endpoints:
            time.sleep(self.config["testing"]["request_delay_seconds"])
            url = self.base_url + endpoint
            
            try:
                resp = self.client.get(url, timeout=self.config["testing"]["timeout_seconds"])
                
                if resp.status_code == 200:
                    # Verificar si expone información sensible
                    sensitive_keys = ["version", "environment", "database", "secret", 
                                     "key", "token", "internal", "debug"]
                    content = resp.text.lower()
                    exposed = [k for k in sensitive_keys if k in content]
                    
                    if exposed:
                        self._add_finding(
                            title=f"Endpoint público expone información sensible: {endpoint}",
                            severity=Severity.MEDIUM,
                            category=OWASPCategory.DATA_EXPOSURE,
                            description=(
                                f"El endpoint público {url} expone información potencialmente sensible: {exposed}."
                            ),
                            endpoint=url,
                            response_snippet=resp.text[:400],
                            recommendation=(
                                "Limitar la información expuesta en endpoints de salud y métricas. "
                                "Separar endpoints de health check internos de los públicos."
                            ),
                        )
            except Exception:
                pass

    def _test_idor_resources(self):
        """Prueba IDOR en recursos de IA (workspaces, assistants, users)."""
        self.logger.info("Probando IDOR en recursos de IA...")
        
        # IDs numéricos secuenciales comunes
        test_ids = ["1", "2", "3", "100", "admin", "0", "null", "undefined", 
                    "00000000-0000-0000-0000-000000000001"]
        
        idor_endpoints = {
            "workspaces": self.endpoints.get("workspaces", "/api/v1/workspaces"),
            "assistants": self.endpoints.get("assistants", "/api/v1/assistants"),
            "documents": self.endpoints.get("documents", "/api/v1/documents"),
        }
        
        headers = self._build_headers()
        
        for resource_name, base_endpoint in idor_endpoints.items():
            for test_id in test_ids[:4]:  # Probar primeros 4 para no saturar
                time.sleep(self.config["testing"]["request_delay_seconds"])
                url = f"{self.base_url}{base_endpoint}/{test_id}"
                
                try:
                    resp = self.client.get(url, headers=headers,
                                           timeout=self.config["testing"]["timeout_seconds"])
                    
                    if resp.status_code == 200:
                        data = resp.json()
                        
                        # Verificar si el recurso pertenece al usuario de prueba
                        # (Si no tiene campo owner/user_id, es sospechoso)
                        has_ownership = any(
                            k in str(data).lower() 
                            for k in ["owner", "user_id", "created_by", "workspace_id"]
                        )
                        
                        self._add_finding(
                            title=f"Posible IDOR en {resource_name}: ID {test_id}",
                            severity=Severity.HIGH,
                            category=OWASPCategory.IDOR,
                            description=(
                                f"Acceso exitoso a {url} con ID secuencial '{test_id}'. "
                                f"Verificar si este recurso pertenece al usuario de prueba o a otro tenant. "
                                f"Ownership verificable en respuesta: {has_ownership}."
                            ),
                            endpoint=url,
                            response_snippet=str(data)[:400],
                            recommendation=(
                                "Usar UUIDs no secuenciales como identificadores de recursos. "
                                "Validar ownership del recurso en cada request, no confiar solo en el ID. "
                                "Implementar autorización a nivel de objeto (OLA) en el ORM."
                            ),
                        )
                        break  # Un hallazgo por tipo de recurso
                        
                except Exception as e:
                    self.logger.error(f"Error en IDOR test {url}: {e}")

    def _test_http_methods(self):
        """Prueba métodos HTTP no esperados en endpoints de IA."""
        self.logger.info("Probando métodos HTTP inesperados...")
        
        headers = self._build_headers()
        test_url = self.base_url + self.endpoints.get("assistants", "/api/v1/assistants")
        
        unexpected_methods = ["DELETE", "PATCH", "PUT", "OPTIONS", "TRACE"]
        
        for method in unexpected_methods:
            time.sleep(self.config["testing"]["request_delay_seconds"])
            try:
                resp = self.client.request(
                    method, test_url, headers=headers,
                    timeout=self.config["testing"]["timeout_seconds"],
                )
                
                if resp.status_code == 200:
                    self._add_finding(
                        title=f"Método HTTP {method} aceptado en endpoint crítico",
                        severity=Severity.MEDIUM,
                        category=OWASPCategory.AUTH_BYPASS,
                        description=(
                            f"El endpoint {test_url} responde a {method} con HTTP 200. "
                            "Verificar si esto permite modificaciones o eliminaciones no autorizadas."
                        ),
                        endpoint=test_url,
                        response_snippet=resp.text[:300],
                        recommendation=(
                            "Implementar allowlist de métodos HTTP por endpoint. "
                            "Responder con 405 Method Not Allowed para métodos no soportados."
                        ),
                    )
                elif method == "TRACE" and resp.status_code != 405:
                    self._add_finding(
                        title="Método TRACE habilitado (XST potencial)",
                        severity=Severity.LOW,
                        category=OWASPCategory.DATA_EXPOSURE,
                        description="TRACE no está explícitamente deshabilitado. Puede permitir Cross-Site Tracing.",
                        endpoint=test_url,
                        recommendation="Deshabilitar el método TRACE en el servidor web/API gateway.",
                    )
            except Exception:
                pass

    def _test_security_headers(self):
        """Verifica headers de seguridad en las respuestas."""
        self.logger.info("Verificando headers de seguridad...")
        
        required_headers = {
            "X-Content-Type-Options": ("nosniff", Severity.MEDIUM),
            "X-Frame-Options": (None, Severity.LOW),
            "Strict-Transport-Security": (None, Severity.MEDIUM),
            "Content-Security-Policy": (None, Severity.MEDIUM),
            "X-XSS-Protection": (None, Severity.LOW),
        }
        
        forbidden_headers = {
            "Server": "Expone versión del servidor",
            "X-Powered-By": "Expone tecnología del servidor",
            "X-AspNet-Version": "Expone versión de framework",
        }
        
        try:
            resp = self.client.get(
                self.base_url + self.endpoints.get("health", "/health"),
                timeout=self.config["testing"]["timeout_seconds"],
            )
            
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            
            for header, (expected_value, severity) in required_headers.items():
                if header.lower() not in resp_headers:
                    self._add_finding(
                        title=f"Header de seguridad ausente: {header}",
                        severity=severity,
                        category=OWASPCategory.DATA_EXPOSURE,
                        description=f"La respuesta no incluye el header de seguridad '{header}'.",
                        endpoint=self.base_url,
                        recommendation=f"Agregar el header '{header}' en todas las respuestas HTTP.",
                    )
            
            for header, issue in forbidden_headers.items():
                if header.lower() in resp_headers:
                    self._add_finding(
                        title=f"Header de información sensible expuesto: {header}",
                        severity=Severity.LOW,
                        category=OWASPCategory.DATA_EXPOSURE,
                        description=f"La respuesta incluye '{header}: {resp_headers[header.lower()]}'. {issue}.",
                        endpoint=self.base_url,
                        recommendation=f"Eliminar o suprimir el header '{header}' de las respuestas.",
                    )
                    
        except Exception as e:
            self.logger.error(f"Error verificando headers: {e}")

    def _test_rate_limiting(self):
        """Prueba si hay rate limiting adecuado en endpoints de IA."""
        self.logger.info("Probando rate limiting...")
        
        headers = self._build_headers()
        chat_url = self.base_url + self.endpoints.get("chat", "/api/v1/chat")
        
        responses_200 = 0
        test_count = 10  # Enviar 10 requests rápidos
        
        for i in range(test_count):
            try:
                resp = self.client.post(
                    chat_url,
                    json={"messages": [{"role": "user", "content": f"ping {i}"}]},
                    headers=headers,
                    timeout=10,
                )
                if resp.status_code == 200:
                    responses_200 += 1
                elif resp.status_code == 429:
                    self.logger.success(f"Rate limiting activo (429 en request {i+1})")
                    break
            except Exception:
                pass
        
        if responses_200 == test_count:
            self._add_finding(
                title="Sin rate limiting en endpoint de chat",
                severity=Severity.MEDIUM,
                category=OWASPCategory.LLM10_UNBOUNDED_CONSUMPTION,
                description=(
                    f"Se enviaron {test_count} requests consecutivos al endpoint de chat "
                    "sin recibir ningún 429 Too Many Requests. "
                    "Sin rate limiting, el sistema es vulnerable a abuso de recursos y DoS."
                ),
                endpoint=chat_url,
                recommendation=(
                    "Implementar rate limiting por usuario/IP/API key. "
                    "Considerar límites por minuto, hora y día. "
                    "Usar token bucket o sliding window para el algoritmo de rate limiting. "
                    "Agregar alertas cuando se alcancen umbrales de uso."
                ),
                references=["https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/"],
            )

    def _test_information_disclosure(self):
        """Prueba endpoints comunes que pueden exponer información interna."""
        self.logger.info("Probando information disclosure...")
        
        disclosure_paths = [
            "/api/v1/config",
            "/api/v1/settings",
            "/api/v1/debug",
            "/api/v1/admin",
            "/api/v1/internal",
            "/api/docs",
            "/swagger.json",
            "/openapi.json",
            "/.well-known/openai-configuration",
            "/api/v1/models",
        ]
        
        for path in disclosure_paths:
            time.sleep(self.config["testing"]["request_delay_seconds"])
            url = self.base_url + path
            
            try:
                resp = self.client.get(
                    url, headers=self._build_headers(),
                    timeout=self.config["testing"]["timeout_seconds"],
                )
                
                if resp.status_code == 200 and len(resp.text) > 50:
                    severity = Severity.MEDIUM
                    
                    # Más grave si expone documentación de API o configuración
                    if any(k in path for k in ["swagger", "openapi", "config", "admin"]):
                        severity = Severity.HIGH
                    
                    self._add_finding(
                        title=f"Information disclosure en {path}",
                        severity=severity,
                        category=OWASPCategory.DATA_EXPOSURE,
                        description=(
                            f"El endpoint {url} es accesible y devuelve contenido. "
                            "Esto puede exponer información de arquitectura interna, "
                            "endpoints no documentados o configuración del sistema."
                        ),
                        endpoint=url,
                        response_snippet=resp.text[:400],
                        recommendation=(
                            "Deshabilitar o proteger con autenticación endpoints de debugging y configuración. "
                            "En producción, no exponer swagger/openapi sin autenticación. "
                            "Implementar deny-by-default para rutas no explícitamente definidas."
                        ),
                    )
            except Exception:
                pass

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _build_headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.credentials.get("api_key"):
            headers["Authorization"] = f"Bearer {self.credentials['api_key']}"
        return headers

    def _add_finding(self, **kwargs) -> Finding:
        finding = Finding(
            id=f"API-{str(uuid.uuid4())[:8].upper()}",
            module="api_tester",
            **kwargs,
        )
        self.findings.append(finding)
        self.logger.finding(finding.severity.value, finding.title, finding_id=finding.id)
        return finding
