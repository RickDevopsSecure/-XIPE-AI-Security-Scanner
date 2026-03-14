"""
XIPE — Módulo de notificaciones a Microsoft Teams
Envía cards adaptativas con resumen de hallazgos al canal de Inbest.
"""
import json
import httpx
from datetime import datetime
from typing import List
from agent.finding import Finding, Severity


SEVERITY_COLORS = {
    "CRITICAL": "attention",   # rojo en Teams
    "HIGH":     "warning",     # naranja
    "MEDIUM":   "warning",
    "LOW":      "accent",      # azul
    "INFO":     "default",
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


class TeamsNotifier:
    """
    Envía notificaciones a Microsoft Teams via Incoming Webhook.
    Configura el webhook en Teams:
      Canal → ... → Connectores → Incoming Webhook → Copiar URL
    """

    def __init__(self, webhook_url: str, channel_name: str = "Inbest Security"):
        self.webhook_url = webhook_url
        self.channel_name = channel_name

    def notify_engagement_complete(
        self,
        engagement: dict,
        findings: List[Finding],
        pdf_s3_url: str = None,
        duration_seconds: int = 0,
    ):
        """Envía resumen completo del engagement al canal de Teams."""
        by_sev = self._count_by_severity(findings)
        risk_level = self._risk_level(by_sev)
        fecha = datetime.utcnow().strftime("%d/%m/%Y %H:%M UTC")

        # ── Card principal ────────────────────────────────────────────────────
        card = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        # Header
                        {
                            "type": "Container",
                            "style": "emphasis",
                            "items": [{
                                "type": "ColumnSet",
                                "columns": [
                                    {
                                        "type": "Column",
                                        "width": "auto",
                                        "items": [{
                                            "type": "TextBlock",
                                            "text": "⚔️ XIPE",
                                            "size": "ExtraLarge",
                                            "weight": "Bolder",
                                            "color": "Accent",
                                        }]
                                    },
                                    {
                                        "type": "Column",
                                        "width": "stretch",
                                        "items": [
                                            {
                                                "type": "TextBlock",
                                                "text": "AI Security Scanner",
                                                "weight": "Bolder",
                                                "size": "Medium",
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": f"Engagement completado — {fecha}",
                                                "size": "Small",
                                                "isSubtle": True,
                                                "spacing": "None",
                                            }
                                        ]
                                    }
                                ]
                            }]
                        },
                        # Info del engagement
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Cliente:", "value": engagement.get("client_name", "N/A")},
                                {"title": "Engagement ID:", "value": engagement.get("id", "N/A")},
                                {"title": "Tester:", "value": engagement.get("tester", "N/A")},
                                {"title": "Duración:", "value": f"{duration_seconds // 60}m {duration_seconds % 60}s"},
                                {"title": "Nivel de riesgo:", "value": f"**{risk_level}**"},
                            ]
                        },
                        # Separador
                        {"type": "Separator"},
                        # Resumen de hallazgos
                        {
                            "type": "TextBlock",
                            "text": f"📊 Resumen — {len(findings)} hallazgos únicos",
                            "weight": "Bolder",
                            "size": "Medium",
                            "spacing": "Medium",
                        },
                        {
                            "type": "ColumnSet",
                            "columns": [
                                self._sev_column("CRITICAL", by_sev.get("CRITICAL", 0)),
                                self._sev_column("HIGH",     by_sev.get("HIGH", 0)),
                                self._sev_column("MEDIUM",   by_sev.get("MEDIUM", 0)),
                                self._sev_column("LOW",      by_sev.get("LOW", 0)),
                            ]
                        },
                        # Top hallazgos críticos
                        {"type": "Separator"},
                        {
                            "type": "TextBlock",
                            "text": "🚨 Hallazgos Críticos / Altos",
                            "weight": "Bolder",
                            "spacing": "Medium",
                        },
                        *self._top_findings_blocks(findings),
                    ],
                    "actions": self._build_actions(pdf_s3_url, engagement),
                }
            }]
        }

        return self._send(card)

    def notify_finding_realtime(self, finding: Finding, engagement_id: str):
        """Notificación inmediata cuando se encuentra un hallazgo CRITICAL."""
        if finding.severity != Severity.CRITICAL:
            return

        card = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "Container",
                            "style": "attention",
                            "items": [{
                                "type": "TextBlock",
                                "text": "🔴 HALLAZGO CRÍTICO DETECTADO",
                                "weight": "Bolder",
                                "size": "Large",
                                "color": "Attention",
                            }]
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Engagement:", "value": engagement_id},
                                {"title": "ID:", "value": finding.id},
                                {"title": "Título:", "value": finding.title},
                                {"title": "Categoría:", "value": finding.category.value},
                                {"title": "Módulo:", "value": finding.module},
                                {"title": "Endpoint:", "value": finding.endpoint or "N/A"},
                            ]
                        },
                        {
                            "type": "TextBlock",
                            "text": f"**Descripción:** {(finding.description or '')[:200]}...",
                            "wrap": True,
                            "spacing": "Medium",
                        },
                        {
                            "type": "TextBlock",
                            "text": f"**Recomendación:** {(finding.recommendation or '')[:150]}...",
                            "wrap": True,
                            "isSubtle": True,
                            "spacing": "Small",
                        }
                    ]
                }
            }]
        }

        return self._send(card)

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _sev_column(self, severity: str, count: int) -> dict:
        colors = {
            "CRITICAL": "Attention",
            "HIGH":     "Warning",
            "MEDIUM":   "Warning",
            "LOW":      "Accent",
        }
        return {
            "type": "Column",
            "width": "stretch",
            "items": [
                {
                    "type": "TextBlock",
                    "text": str(count),
                    "size": "ExtraLarge",
                    "weight": "Bolder",
                    "color": colors.get(severity, "Default"),
                    "horizontalAlignment": "Center",
                },
                {
                    "type": "TextBlock",
                    "text": severity,
                    "size": "Small",
                    "isSubtle": True,
                    "horizontalAlignment": "Center",
                    "spacing": "None",
                }
            ]
        }

    def _top_findings_blocks(self, findings: List[Finding]) -> list:
        critical_high = [f for f in findings if f.severity.value in ("CRITICAL", "HIGH")][:5]
        blocks = []
        for f in critical_high:
            emoji = SEVERITY_EMOJI.get(f.severity.value, "⚪")
            blocks.append({
                "type": "TextBlock",
                "text": f"{emoji} **{f.severity.value}** — {f.title}",
                "wrap": True,
                "spacing": "Small",
                "size": "Small",
            })
        if not blocks:
            blocks.append({
                "type": "TextBlock",
                "text": "✅ Sin hallazgos críticos o altos.",
                "color": "Good",
            })
        return blocks

    def _build_actions(self, pdf_s3_url: str, engagement: dict) -> list:
        actions = []
        if pdf_s3_url:
            actions.append({
                "type": "Action.OpenUrl",
                "title": "📄 Ver Reporte PDF",
                "url": pdf_s3_url,
            })
        actions.append({
            "type": "Action.OpenUrl",
            "title": "🔗 GitHub XIPE",
            "url": "https://github.com/RickDevopsSecure/-XIPE-AI-Security-Scanner",
        })
        return actions

    def _count_by_severity(self, findings: List[Finding]) -> dict:
        counts = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def _risk_level(self, by_sev: dict) -> str:
        if by_sev.get("CRITICAL", 0) > 0:
            return "🔴 CRÍTICO"
        if by_sev.get("HIGH", 0) > 0:
            return "🟠 ALTO"
        if by_sev.get("MEDIUM", 0) > 0:
            return "🟡 MEDIO"
        return "🔵 BAJO"

    def _send(self, payload: dict) -> bool:
        try:
            resp = httpx.post(
                self.webhook_url,
                json=payload,
                timeout=15,
                headers={"Content-Type": "application/json"},
            )
            return resp.status_code == 200
        except Exception as e:
            print(f"Error enviando a Teams: {e}")
            return False
