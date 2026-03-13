"""
Orquestador principal del framework de AI Pentesting de Inbest.
Coordina todos los módulos y consolida los hallazgos.
"""
import json
import time
from datetime import datetime
from pathlib import Path
from typing import List
import httpx
import yaml

from agent.finding import Finding, Severity
from modules.prompt_injection import PromptInjectionTester
from modules.rag_tester import RAGTester
from modules.api_tester import APITester
from modules.agent_tester import AgentTester
from reporting.pdf_report import PDFReportGenerator
from utils.logger import PentestLogger


class PentestOrchestrator:
    """
    Orquestador central del engagement de AI Pentesting.
    
    Flujo:
    1. Valida configuración y autorización
    2. Inicializa módulos según config
    3. Ejecuta cada módulo en secuencia
    4. Consolida hallazgos
    5. Genera reporte PDF + JSON
    6. (Opcional) sube a S3
    """

    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.engagement_id = self.config["engagement"]["id"]
        
        # Inicializar logger
        self.logger = PentestLogger(
            log_file=self.config["output"]["log_file"],
            engagement_id=self.engagement_id,
        )
        
        # HTTP client compartido con rate limiting
        delay = self.config["testing"]["request_delay_seconds"]
        self.http_client = httpx.Client(
            verify=True,
            follow_redirects=True,
            timeout=self.config["testing"]["timeout_seconds"],
            headers={"User-Agent": "Inbest-AI-Pentest/1.0 (Authorized Security Testing)"},
        )
        
        self.all_findings: List[Finding] = []
        self.start_time = datetime.utcnow()

    def run(self):
        """Ejecuta el engagement completo."""
        self._print_banner()
        self._validate_authorization()
        self._verify_connectivity()
        
        modules_config = self.config["modules"]
        
        # ─── Ejecutar módulos configurados ───────────────────────────────────
        if modules_config.get("api_tester", True):
            tester = APITester(self.config, self.logger, self.http_client)
            self.all_findings.extend(tester.run())
        
        if modules_config.get("prompt_injection", True):
            tester = PromptInjectionTester(self.config, self.logger, self.http_client)
            self.all_findings.extend(tester.run())
        
        if modules_config.get("rag_tester", True):
            tester = RAGTester(self.config, self.logger, self.http_client)
            self.all_findings.extend(tester.run())
        
        if modules_config.get("agent_tester", True):
            tester = AgentTester(self.config, self.logger, self.http_client)
            self.all_findings.extend(tester.run())
        
        # ─── Generar reportes ─────────────────────────────────────────────────
        self._generate_outputs()
        self._print_summary()

    def _print_banner(self):
        self.logger.section("INBEST AI PENTESTING FRAMEWORK v1.0")
        eng = self.config["engagement"]
        self.logger.info(f"Engagement ID : {eng['id']}")
        self.logger.info(f"Cliente       : {eng['client_name']}")
        self.logger.info(f"Tester        : {eng['tester']}")
        self.logger.info(f"Autorizado por: {eng['authorized_by']}")
        self.logger.info(f"Documento     : {eng['authorization_document']}")
        self.logger.section("")

    def _validate_authorization(self):
        """Verifica que la configuración de autorización esté completa."""
        required = ["id", "client_name", "authorized_by", "authorization_document"]
        eng = self.config["engagement"]
        
        missing = [f for f in required if not eng.get(f)]
        if missing:
            raise ValueError(
                f"Configuración incompleta. Campos requeridos faltantes: {missing}. "
                "El engagement requiere autorización documentada antes de ejecutar."
            )
        
        # Verificar que la fecha esté dentro del rango autorizado
        today = datetime.utcnow().date()
        start = datetime.strptime(eng["start_date"], "%Y-%m-%d").date()
        end = datetime.strptime(eng["end_date"], "%Y-%m-%d").date()
        
        if not (start <= today <= end):
            raise ValueError(
                f"El engagement no está activo. Rango autorizado: {start} - {end}. "
                f"Fecha actual: {today}."
            )
        
        self.logger.success("Autorización validada correctamente.")

    def _verify_connectivity(self):
        """Verifica conectividad con los endpoints del scope."""
        self.logger.info("Verificando conectividad con el entorno del cliente...")
        base_url = self.config["scope"]["base_urls"][0]
        health_path = self.config["scope"]["endpoints"].get("health", "/health")
        
        try:
            resp = self.http_client.get(
                base_url + health_path,
                timeout=10,
            )
            self.logger.success(f"Conectividad OK — {base_url} responde con HTTP {resp.status_code}")
        except Exception as e:
            self.logger.warning(f"No se pudo verificar conectividad: {e}. Continuando...")

    def _generate_outputs(self):
        """Genera JSON de resultados y reporte PDF."""
        self.logger.section("Generando Reportes")
        
        # ─── JSON ─────────────────────────────────────────────────────────────
        output_dir = Path(self.config["output"]["json_results"]).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        json_path = self.config["output"]["json_results"]
        results = {
            "engagement": self.config["engagement"],
            "execution": {
                "start_time": self.start_time.isoformat(),
                "end_time": datetime.utcnow().isoformat(),
                "total_findings": len(self.all_findings),
                "by_severity": self._count_by_severity(),
            },
            "findings": [f.to_dict() for f in self.all_findings],
        }
        
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        self.logger.success(f"JSON exportado: {json_path}")
        
        # ─── PDF ──────────────────────────────────────────────────────────────
        pdf_path = self.config["output"]["pdf_report"]
        generator = PDFReportGenerator(
            findings=self.all_findings,
            engagement=self.config["engagement"],
            output_path=pdf_path,
            execution_meta=results["execution"],
        )
        generator.generate()
        self.logger.success(f"PDF generado: {pdf_path}")
        
        # ─── S3 (opcional) ────────────────────────────────────────────────────
        if self.config.get("aws", {}).get("enabled"):
            self._upload_to_s3(json_path, pdf_path)

    def _upload_to_s3(self, json_path: str, pdf_path: str):
        try:
            import boto3
            aws = self.config["aws"]
            s3 = boto3.client("s3", region_name=aws["region"])
            prefix = aws["s3_prefix"]
            
            for local_path in [json_path, pdf_path]:
                key = prefix + Path(local_path).name
                s3.upload_file(local_path, aws["s3_bucket"], key)
                self.logger.success(f"Subido a S3: s3://{aws['s3_bucket']}/{key}")
        except Exception as e:
            self.logger.error(f"Error subiendo a S3: {e}")

    def _count_by_severity(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for f in self.all_findings:
            counts[f.severity.value] += 1
        return counts

    def _print_summary(self):
        self.logger.section("RESUMEN DEL ENGAGEMENT")
        by_severity = self._count_by_severity()
        
        self.logger.info(f"Total de hallazgos: {len(self.all_findings)}")
        for severity, count in by_severity.items():
            if count > 0:
                self.logger.info(f"  {severity}: {count}")
        
        duration = (datetime.utcnow() - self.start_time).seconds
        self.logger.info(f"Duración: {duration // 60}m {duration % 60}s")
        self.logger.success("Engagement completado. Revisar el reporte PDF para los hallazgos detallados.")

    @staticmethod
    def _load_config(config_path: str) -> dict:
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    
    def __del__(self):
        if hasattr(self, "http_client"):
            self.http_client.close()
