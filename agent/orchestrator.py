"""
XIPE — Orquestador v2
Agrega: notificaciones Teams, upload S3, reporte bilingüe, config desde SSM.
"""
import json
import os
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
from reporting.teams_notifier import TeamsNotifier
from utils.logger import PentestLogger


class PentestOrchestrator:

    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self._apply_env_overrides()          # SSM / env vars tienen prioridad
        self.engagement_id = self.config["engagement"]["id"]

        self.logger = PentestLogger(
            log_file=self.config["output"]["log_file"],
            engagement_id=self.engagement_id,
        )

        self.http_client = httpx.Client(
            verify=True,
            follow_redirects=True,
            timeout=self.config["testing"]["timeout_seconds"],
            headers={"User-Agent": "Inbest-XIPE/1.0 (Authorized Security Testing)"},
        )

        # Teams notifier (opcional)
        webhook = (
            self.config.get("integrations", {}).get("teams_webhook_url")
            or os.environ.get("TEAMS_WEBHOOK_URL", "")
        )
        self.teams = TeamsNotifier(webhook) if webhook else None

        self.all_findings: List[Finding] = []
        self.start_time = datetime.utcnow()

    def run(self):
        self._print_banner()
        self._validate_authorization()
        self._verify_connectivity()

        modules_config = self.config["modules"]

        if modules_config.get("api_tester", True):
            tester = APITester(self.config, self.logger, self.http_client)
            self.all_findings.extend(tester.run())

        if modules_config.get("prompt_injection", True):
            tester = PromptInjectionTester(self.config, self.logger, self.http_client)
            findings = tester.run()
            # Notificación inmediata por CRITICAL
            for f in findings:
                if self.teams and f.severity == Severity.CRITICAL:
                    self.teams.notify_finding_realtime(f, self.engagement_id)
            self.all_findings.extend(findings)

        if modules_config.get("rag_tester", True):
            tester = RAGTester(self.config, self.logger, self.http_client)
            self.all_findings.extend(tester.run())

        if modules_config.get("agent_tester", True):
            tester = AgentTester(self.config, self.logger, self.http_client)
            self.all_findings.extend(tester.run())

        self._generate_outputs()
        self._print_summary()

    # ── Outputs ───────────────────────────────────────────────────────────────

    def _generate_outputs(self):
        self.logger.section("Generando Reportes")

        deduplicated = self._deduplicate_findings()
        removed = len(self.all_findings) - len(deduplicated)
        if removed > 0:
            self.logger.info(f"Deduplicación: {removed} hallazgo(s) consolidados.")

        output_dir = Path(self.config["output"]["json_results"]).parent
        output_dir.mkdir(parents=True, exist_ok=True)

        duration = int((datetime.utcnow() - self.start_time).total_seconds())

        execution_meta = {
            "start_time":     self.start_time.isoformat(),
            "end_time":       datetime.utcnow().isoformat(),
            "duration_seconds": duration,
            "total_findings": len(deduplicated),
            "total_raw":      len(self.all_findings),
            "by_severity":    self._count_by_severity(deduplicated),
        }

        # JSON
        json_path = self.config["output"]["json_results"]
        results = {
            "engagement": self.config["engagement"],
            "execution":  execution_meta,
            "findings":   [f.to_dict() for f in deduplicated],
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        self.logger.success(f"JSON exportado: {json_path}")

        # PDF bilingüe
        pdf_path = self.config["output"]["pdf_report"]
        generator = PDFReportGenerator(
            findings=deduplicated,
            engagement=self.config["engagement"],
            output_path=pdf_path,
            execution_meta=execution_meta,
        )
        generator.generate()
        self.logger.success(f"PDF generado: {pdf_path}")

        # S3 upload
        pdf_s3_url = None
        if self.config.get("aws", {}).get("enabled"):
            pdf_s3_url = self._upload_to_s3(json_path, pdf_path)

        # Notificación Teams — resumen final
        if self.teams:
            self.logger.info("Enviando resumen a Microsoft Teams...")
            sent = self.teams.notify_engagement_complete(
                engagement=self.config["engagement"],
                findings=deduplicated,
                pdf_s3_url=pdf_s3_url,
                duration_seconds=duration,
            )
            if sent:
                self.logger.success("Notificación enviada a Teams ✓")
            else:
                self.logger.warning("No se pudo enviar la notificación a Teams")

    def _upload_to_s3(self, json_path: str, pdf_path: str) -> str:
        """Sube los resultados a S3 y retorna la URL del PDF."""
        try:
            import boto3
            aws = self.config["aws"]
            s3 = boto3.client("s3", region_name=aws["region"])
            prefix = aws.get("s3_prefix", f"engagements/{self.engagement_id}/")
            bucket = aws["s3_bucket"]

            pdf_key = prefix + Path(pdf_path).name
            s3.upload_file(json_path, bucket, prefix + Path(json_path).name)
            s3.upload_file(pdf_path,  bucket, pdf_key)

            # URL pre-firmada válida 7 días
            pdf_url = s3.generate_presigned_url(
                "get_object",
                Params={"Bucket": bucket, "Key": pdf_key},
                ExpiresIn=604800,
            )
            self.logger.success(f"Subido a S3: s3://{bucket}/{pdf_key}")
            return pdf_url
        except Exception as e:
            self.logger.error(f"Error subiendo a S3: {e}")
            return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _apply_env_overrides(self):
        """Permite sobreescribir config desde variables de entorno (Lambda/ECS)."""
        overrides = {
            "ENGAGEMENT_ID":    ("engagement", "id"),
            "CLIENT_NAME":      ("engagement", "client_name"),
            "S3_BUCKET":        ("aws", "s3_bucket"),
            "S3_PREFIX":        ("aws", "s3_prefix"),
            "TEAMS_WEBHOOK_URL": None,  # manejado directo en __init__
        }
        for env_var, path in overrides.items():
            val = os.environ.get(env_var)
            if val and path:
                section, key = path
                if section not in self.config:
                    self.config[section] = {}
                self.config[section][key] = val

        if os.environ.get("S3_BUCKET"):
            self.config.setdefault("aws", {})["enabled"] = True

    def _deduplicate_findings(self) -> list:
        seen = {}
        deduped = []
        for f in self.all_findings:
            key = f"{f.title}|{f.category}|{f.module}"
            if key not in seen:
                seen[key] = f
                deduped.append(f)
            else:
                existing = seen[key]
                if f.response_snippet and not existing.response_snippet:
                    existing.response_snippet = f.response_snippet
        return deduped

    def _count_by_severity(self, findings=None) -> dict:
        counts = {s.value: 0 for s in Severity}
        for f in (findings or self.all_findings):
            counts[f.severity.value] += 1
        return counts

    def _print_banner(self):
        self.logger.section("XIPE — AI Security Scanner v2.0 by Inbest")
        eng = self.config["engagement"]
        self.logger.info(f"Engagement ID : {eng['id']}")
        self.logger.info(f"Cliente       : {eng['client_name']}")
        self.logger.info(f"Tester        : {eng['tester']}")
        self.logger.info(f"Autorizado por: {eng['authorized_by']}")
        self.logger.section("")

    def _validate_authorization(self):
        required = ["id", "client_name", "authorized_by", "authorization_document"]
        eng = self.config["engagement"]
        missing = [f for f in required if not eng.get(f)]
        if missing:
            raise ValueError(f"Campos de autorización faltantes: {missing}")

        today = datetime.utcnow().date()
        start = datetime.strptime(eng["start_date"], "%Y-%m-%d").date()
        end   = datetime.strptime(eng["end_date"],   "%Y-%m-%d").date()
        if not (start <= today <= end):
            raise ValueError(f"Engagement fuera de rango autorizado: {start} — {end}")

        self.logger.success("Autorización validada correctamente.")

    def _verify_connectivity(self):
        self.logger.info("Verificando conectividad con el entorno del cliente...")
        base_url = self.config["scope"]["base_urls"][0]
        health   = self.config["scope"]["endpoints"].get("health", "/health")
        try:
            resp = self.http_client.get(base_url + health, timeout=10)
            self.logger.success(f"Conectividad OK — {base_url} → HTTP {resp.status_code}")
        except Exception as e:
            self.logger.warning(f"No se pudo verificar conectividad: {e}. Continuando...")

    def _print_summary(self):
        self.logger.section("RESUMEN DEL ENGAGEMENT")
        by_sev = self._count_by_severity(self._deduplicate_findings())
        self.logger.info(f"Total de hallazgos únicos: {sum(by_sev.values())}")
        for sev, count in by_sev.items():
            if count > 0:
                self.logger.info(f"  {sev}: {count}")
        duration = int((datetime.utcnow() - self.start_time).total_seconds())
        self.logger.info(f"Duración: {duration // 60}m {duration % 60}s")
        self.logger.success("Engagement completado. Reporte PDF listo para el cliente.")

    @staticmethod
    def _load_config(config_path: str) -> dict:
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def __del__(self):
        if hasattr(self, "http_client"):
            self.http_client.close()
