"""
Generador de reportes PDF profesionales para engagements de AI Pentesting.
Genera un reporte ejecutivo y técnico listo para entregar al cliente.
"""
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.platypus.flowables import HRFlowable
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

from agent.finding import Finding, Severity


# ─── Paleta de colores Inbest ─────────────────────────────────────────────────
INBEST_DARK = colors.HexColor("#0D1117")
INBEST_BLUE = colors.HexColor("#1A73E8")
INBEST_CYAN = colors.HexColor("#00BCD4")
INBEST_GREEN = colors.HexColor("#00C853")
INBEST_WHITE = colors.white

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#B71C1C"),
    "HIGH":     colors.HexColor("#E53935"),
    "MEDIUM":   colors.HexColor("#F57C00"),
    "LOW":      colors.HexColor("#1565C0"),
    "INFO":     colors.HexColor("#455A64"),
}


class PDFReportGenerator:
    """Genera reporte PDF profesional del engagement de AI Pentesting."""

    def __init__(
        self,
        findings: List[Finding],
        engagement: dict,
        output_path: str,
        execution_meta: dict,
    ):
        self.findings = sorted(findings, key=lambda f: f.severity_score, reverse=True)
        self.engagement = engagement
        self.output_path = output_path
        self.meta = execution_meta
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        self.doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )
        
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def generate(self):
        story = []
        
        story += self._build_cover()
        story.append(PageBreak())
        story += self._build_executive_summary()
        story.append(PageBreak())
        story += self._build_findings_table()
        story.append(PageBreak())
        story += self._build_detailed_findings()
        story += self._build_appendix()
        
        self.doc.build(story, onFirstPage=self._header_footer, onLaterPages=self._header_footer)

    # ─── Secciones del reporte ────────────────────────────────────────────────

    def _build_cover(self) -> list:
        elems = []
        
        elems.append(Spacer(1, 1.5 * inch))
        
        # Título principal
        elems.append(Paragraph("AI SECURITY ASSESSMENT", self.styles["CoverTitle"]))
        elems.append(Paragraph("Reporte de Pentesting", self.styles["CoverSubtitle"]))
        elems.append(Spacer(1, 0.3 * inch))
        elems.append(HRFlowable(width="100%", thickness=2, color=INBEST_BLUE))
        elems.append(Spacer(1, 0.3 * inch))
        
        # Info del engagement
        eng = self.engagement
        info_data = [
            ["Cliente:", eng["client_name"]],
            ["Engagement ID:", eng["id"]],
            ["Tester:", eng["tester"]],
            ["Fecha:", datetime.utcnow().strftime("%d de %B de %Y")],
            ["Autorizado por:", eng["authorized_by"]],
            ["Documento:", eng["authorization_document"]],
        ]
        
        t = Table(info_data, colWidths=[2 * inch, 4 * inch])
        t.setStyle(TableStyle([
            ("FONT", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONT", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 11),
            ("TEXTCOLOR", (0, 0), (0, -1), INBEST_BLUE),
            ("TEXTCOLOR", (1, 0), (1, -1), colors.black),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        elems.append(t)
        
        elems.append(Spacer(1, 1 * inch))
        
        # Badge de confidencialidad
        conf_data = [["⚠ CONFIDENCIAL — USO INTERNO DEL CLIENTE ÚNICAMENTE"]]
        conf_t = Table(conf_data, colWidths=[6.5 * inch])
        conf_t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), SEVERITY_COLORS["HIGH"]),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
            ("FONT", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        elems.append(conf_t)
        
        return elems

    def _build_executive_summary(self) -> list:
        elems = []
        elems.append(Paragraph("Resumen Ejecutivo", self.styles["SectionTitle"]))
        elems.append(HRFlowable(width="100%", thickness=1, color=INBEST_BLUE))
        elems.append(Spacer(1, 0.15 * inch))
        
        by_sev = self.meta.get("by_severity", {})
        total = self.meta.get("total_findings", len(self.findings))
        
        # Texto ejecutivo
        critical = by_sev.get("CRITICAL", 0)
        high = by_sev.get("HIGH", 0)
        
        risk_level = "CRÍTICO" if critical > 0 else "ALTO" if high > 0 else "MEDIO"
        
        summary_text = (
            f"Inbest Cybersecurity realizó una evaluación de seguridad de sistemas de Inteligencia "
            f"Artificial en el entorno de <b>{self.engagement['client_name']}</b>, cubriendo "
            f"plataformas RAG, chatbots, APIs de LLMs y agentes autónomos. "
            f"El nivel de riesgo general identificado es <b>{risk_level}</b>."
        )
        elems.append(Paragraph(summary_text, self.styles["BodyText"]))
        elems.append(Spacer(1, 0.2 * inch))
        
        # Tabla resumen de hallazgos
        summary_data = [["Severidad", "Cantidad", "Impacto"]]
        severity_info = {
            "CRITICAL": "Explotación inmediata, daño severo",
            "HIGH": "Alta probabilidad de explotación",
            "MEDIUM": "Explotable con condiciones adicionales",
            "LOW": "Riesgo limitado, mitigación recomendada",
            "INFO": "Hallazgo informativo",
        }
        
        for sev, info in severity_info.items():
            count = by_sev.get(sev, 0)
            if count > 0:
                summary_data.append([sev, str(count), info])
        
        summary_data.append(["TOTAL", str(total), ""])
        
        t = Table(summary_data, colWidths=[1.3 * inch, 0.8 * inch, 4.4 * inch])
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), INBEST_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, colors.HexColor("#F5F5F5")]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#E3F2FD")),
            ("FONT", (0, -1), (-1, -1), "Helvetica-Bold"),
        ]
        
        # Colorear filas por severidad
        for i, row in enumerate(summary_data[1:-1], 1):
            sev = row[0]
            if sev in SEVERITY_COLORS:
                style.append(("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLORS[sev]))
                style.append(("FONT", (0, i), (0, i), "Helvetica-Bold"))
        
        t.setStyle(TableStyle(style))
        elems.append(t)
        
        return elems

    def _build_findings_table(self) -> list:
        elems = []
        elems.append(Paragraph("Tabla de Hallazgos", self.styles["SectionTitle"]))
        elems.append(HRFlowable(width="100%", thickness=1, color=INBEST_BLUE))
        elems.append(Spacer(1, 0.15 * inch))
        
        table_data = [["ID", "Severidad", "Título", "Categoría OWASP"]]
        
        for f in self.findings:
            table_data.append([
                f.id,
                f.severity.value,
                Paragraph(f.title[:60], self.styles["SmallText"]),
                Paragraph(f.category.value[:40], self.styles["SmallText"]),
            ])
        
        t = Table(table_data, colWidths=[0.9 * inch, 0.9 * inch, 2.8 * inch, 1.9 * inch])
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), INBEST_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FAFAFA")]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
        
        for i, finding in enumerate(self.findings, 1):
            color = SEVERITY_COLORS.get(finding.severity.value, colors.grey)
            style.append(("TEXTCOLOR", (1, i), (1, i), color))
            style.append(("FONT", (1, i), (1, i), "Helvetica-Bold"))
        
        t.setStyle(TableStyle(style))
        elems.append(t)
        
        return elems

    def _build_detailed_findings(self) -> list:
        elems = []
        elems.append(Paragraph("Hallazgos Detallados", self.styles["SectionTitle"]))
        elems.append(HRFlowable(width="100%", thickness=1, color=INBEST_BLUE))
        
        for i, f in enumerate(self.findings, 1):
            elems.append(Spacer(1, 0.2 * inch))
            
            # Header del finding
            sev_color = SEVERITY_COLORS.get(f.severity.value, colors.grey)
            header_data = [[
                f"{f.id}",
                f.title,
                f.severity.value,
            ]]
            header_t = Table(header_data, colWidths=[0.9 * inch, 4.3 * inch, 1.3 * inch])
            header_t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), INBEST_DARK),
                ("TEXTCOLOR", (0, 0), (1, 0), colors.white),
                ("TEXTCOLOR", (2, 0), (2, 0), sev_color),
                ("FONT", (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("ALIGN", (2, 0), (2, 0), "RIGHT"),
            ]))
            elems.append(KeepTogether([header_t]))
            
            # Detalles
            detail_data = [
                ["Categoría OWASP:", f.category.value],
                ["Endpoint:", Paragraph(f.endpoint or "N/A", self.styles["SmallMono"])],
                ["Módulo:", f.module],
            ]
            detail_t = Table(detail_data, colWidths=[1.4 * inch, 5.1 * inch])
            detail_t.setStyle(TableStyle([
                ("FONT", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TEXTCOLOR", (0, 0), (0, -1), INBEST_BLUE),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8F9FA")),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ]))
            elems.append(detail_t)
            elems.append(Spacer(1, 0.08 * inch))
            
            elems.append(Paragraph("<b>Descripción:</b>", self.styles["BodyText"]))
            elems.append(Paragraph(f.description, self.styles["BodyText"]))
            
            if f.response_snippet:
                elems.append(Spacer(1, 0.05 * inch))
                elems.append(Paragraph("<b>Evidencia:</b>", self.styles["BodyText"]))
                elems.append(Paragraph(
                    f.response_snippet[:300].replace("<", "&lt;").replace(">", "&gt;"),
                    self.styles["CodeText"]
                ))
            
            elems.append(Spacer(1, 0.05 * inch))
            elems.append(Paragraph("<b>Recomendación:</b>", self.styles["BodyText"]))
            elems.append(Paragraph(f.recommendation, self.styles["BodyText"]))
            
            elems.append(HRFlowable(width="100%", thickness=0.3, color=colors.lightgrey))
        
        return elems

    def _build_appendix(self) -> list:
        elems = [PageBreak()]
        elems.append(Paragraph("Apéndice: Marco OWASP LLM Top 10", self.styles["SectionTitle"]))
        elems.append(HRFlowable(width="100%", thickness=1, color=INBEST_BLUE))
        elems.append(Spacer(1, 0.15 * inch))
        
        owasp_items = [
            ("LLM01", "Prompt Injection", "Inyección de instrucciones maliciosas en el prompt"),
            ("LLM02", "Sensitive Information Disclosure", "Exposición de datos sensibles en las respuestas"),
            ("LLM04", "Data and Model Poisoning", "Manipulación del proceso de entrenamiento o datos"),
            ("LLM05", "Improper Output Handling", "Falta de validación del output del LLM"),
            ("LLM06", "Excessive Agency", "El agente actúa más allá de sus privilegios necesarios"),
            ("LLM07", "System Prompt Leakage", "Exposición de instrucciones del sistema al usuario"),
            ("LLM08", "Vector and Embedding Weaknesses", "Vulnerabilidades en el pipeline RAG"),
            ("LLM10", "Unbounded Consumption", "Falta de límites en el uso de recursos"),
        ]
        
        data = [["ID", "Nombre", "Descripción"]]
        for item in owasp_items:
            data.append(list(item))
        
        t = Table(data, colWidths=[0.7 * inch, 2 * inch, 3.8 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), INBEST_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(t)
        
        return elems

    # ─── Header / Footer ──────────────────────────────────────────────────────

    def _header_footer(self, canvas, doc):
        canvas.saveState()
        
        # Header
        canvas.setFillColor(INBEST_DARK)
        canvas.rect(0, letter[1] - 0.5 * inch, letter[0], 0.5 * inch, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(0.75 * inch, letter[1] - 0.32 * inch, "INBEST CYBERSECURITY | AI Security Assessment")
        canvas.drawRightString(
            letter[0] - 0.75 * inch,
            letter[1] - 0.32 * inch,
            f"CONFIDENCIAL | {self.engagement['id']}"
        )
        
        # Footer
        canvas.setFillColor(colors.HexColor("#455A64"))
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(0.75 * inch, 0.35 * inch, 
                         f"© {datetime.utcnow().year} Inbest Cybersecurity — Documento confidencial")
        canvas.drawRightString(letter[0] - 0.75 * inch, 0.35 * inch, f"Página {doc.page}")
        
        canvas.restoreState()

    # ─── Estilos ──────────────────────────────────────────────────────────────

    def _setup_styles(self):
        self.styles.add(ParagraphStyle(
            "CoverTitle",
            parent=self.styles["Title"],
            fontSize=28,
            textColor=INBEST_DARK,
            spaceAfter=8,
            fontName="Helvetica-Bold",
        ))
        self.styles.add(ParagraphStyle(
            "CoverSubtitle",
            parent=self.styles["Normal"],
            fontSize=16,
            textColor=INBEST_BLUE,
            spaceAfter=20,
        ))
        self.styles.add(ParagraphStyle(
            "SectionTitle",
            parent=self.styles["Heading1"],
            fontSize=14,
            textColor=INBEST_DARK,
            spaceBefore=12,
            spaceAfter=4,
            fontName="Helvetica-Bold",
        ))
        self.styles.add(ParagraphStyle(
            "BodyText",
            parent=self.styles["Normal"],
            fontSize=9,
            leading=14,
            spaceAfter=6,
        ))
        self.styles.add(ParagraphStyle(
            "SmallText",
            parent=self.styles["Normal"],
            fontSize=8,
            leading=11,
        ))
        self.styles.add(ParagraphStyle(
            "SmallMono",
            parent=self.styles["Normal"],
            fontSize=7.5,
            fontName="Courier",
            textColor=colors.HexColor("#C62828"),
        ))
        self.styles.add(ParagraphStyle(
            "CodeText",
            parent=self.styles["Normal"],
            fontSize=7.5,
            fontName="Courier",
            backColor=colors.HexColor("#F5F5F5"),
            textColor=colors.HexColor("#212121"),
            leftIndent=8,
            rightIndent=8,
            spaceBefore=4,
            spaceAfter=4,
        ))
