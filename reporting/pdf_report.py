"""
Generador de reportes PDF profesionales para engagements de AI Pentesting.
"""
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

MESES_ES = {
    1: "enero", 2: "febrero", 3: "marzo", 4: "abril",
    5: "mayo", 6: "junio", 7: "julio", 8: "agosto",
    9: "septiembre", 10: "octubre", 11: "noviembre", 12: "diciembre",
}

def _fecha_es() -> str:
    hoy = datetime.utcnow()
    return f"{hoy.day} de {MESES_ES[hoy.month]} de {hoy.year}"

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

from agent.finding import Finding, Severity


INBEST_DARK  = colors.HexColor("#0D1117")
INBEST_BLUE  = colors.HexColor("#1A73E8")
INBEST_CYAN  = colors.HexColor("#00BCD4")
INBEST_GREEN = colors.HexColor("#00C853")
INBEST_WHITE = colors.white

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#B71C1C"),
    "HIGH":     colors.HexColor("#E53935"),
    "MEDIUM":   colors.HexColor("#F57C00"),
    "LOW":      colors.HexColor("#1565C0"),
    "INFO":     colors.HexColor("#455A64"),
}


def _safe(text: str, limit: int = 0) -> str:
    """Escapa caracteres HTML para uso seguro en Paragraph de ReportLab."""
    t = (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return t[:limit] if limit else t


class PDFReportGenerator:

    def __init__(self, findings, engagement, output_path, execution_meta):
        self.findings = sorted(findings, key=lambda f: f.severity_score, reverse=True)
        self.engagement = engagement
        self.output_path = output_path
        self.meta = execution_meta

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        self.doc = SimpleDocTemplate(
            output_path, pagesize=letter,
            rightMargin=0.75*inch, leftMargin=0.75*inch,
            topMargin=0.75*inch, bottomMargin=0.75*inch,
        )

        base = getSampleStyleSheet()
        self.S = {
            "normal":   base["Normal"],
            "title":    base["Title"],
            "h1":       base["Heading1"],
            "cover_title": ParagraphStyle("CoverTitle", parent=base["Title"],
                            fontSize=28, textColor=INBEST_DARK, spaceAfter=8,
                            fontName="Helvetica-Bold"),
            "cover_sub": ParagraphStyle("CoverSub", parent=base["Normal"],
                            fontSize=16, textColor=INBEST_BLUE, spaceAfter=20),
            "section":  ParagraphStyle("Section", parent=base["Heading1"],
                            fontSize=14, textColor=INBEST_DARK,
                            spaceBefore=12, spaceAfter=4, fontName="Helvetica-Bold"),
            "body":     ParagraphStyle("Body", parent=base["Normal"],
                            fontSize=9, leading=14, spaceAfter=6),
            "small":    ParagraphStyle("Small", parent=base["Normal"],
                            fontSize=8, leading=11),
            "mono":     ParagraphStyle("Mono", parent=base["Normal"],
                            fontSize=7.5, fontName="Courier",
                            textColor=colors.HexColor("#C62828")),
            "code":     ParagraphStyle("Code", parent=base["Normal"],
                            fontSize=7.5, fontName="Courier",
                            backColor=colors.HexColor("#F5F5F5"),
                            textColor=colors.HexColor("#212121"),
                            leftIndent=8, rightIndent=8,
                            spaceBefore=4, spaceAfter=4),
        }

    def generate(self):
        story = []
        story += self._cover()
        story.append(PageBreak())
        story += self._executive_summary()
        story.append(PageBreak())
        story += self._findings_table()
        story.append(PageBreak())
        story += self._detailed_findings()
        story += self._appendix()
        self.doc.build(story, onFirstPage=self._hf, onLaterPages=self._hf)

    # ── Portada ───────────────────────────────────────────────────────────────

    def _cover(self):
        e = []
        e.append(Spacer(1, 1.5*inch))
        e.append(Paragraph("AI SECURITY ASSESSMENT", self.S["cover_title"]))
        e.append(Paragraph("Reporte de Pentesting — XIPE by Inbest", self.S["cover_sub"]))
        e.append(Spacer(1, 0.3*inch))
        e.append(HRFlowable(width="100%", thickness=2, color=INBEST_BLUE))
        e.append(Spacer(1, 0.3*inch))

        eng = self.engagement
        rows = [
            ["Cliente:",       eng["client_name"]],
            ["Engagement ID:", eng["id"]],
            ["Tester:",        eng["tester"]],
            ["Fecha:",         _fecha_es()],
            ["Autorizado por:", eng["authorized_by"]],
            ["Documento:",     eng["authorization_document"]],
        ]
        t = Table(rows, colWidths=[2*inch, 4*inch])
        t.setStyle(TableStyle([
            ("FONT",      (0,0),(0,-1), "Helvetica-Bold"),
            ("FONTSIZE",  (0,0),(-1,-1), 11),
            ("TEXTCOLOR", (0,0),(0,-1), INBEST_BLUE),
            ("TOPPADDING",(0,0),(-1,-1), 6),
            ("BOTTOMPADDING",(0,0),(-1,-1), 6),
        ]))
        e.append(t)
        e.append(Spacer(1, 1*inch))

        badge = Table([["⚠ CONFIDENCIAL — USO INTERNO DEL CLIENTE ÚNICAMENTE"]],
                      colWidths=[6.5*inch])
        badge.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1), SEVERITY_COLORS["HIGH"]),
            ("TEXTCOLOR", (0,0),(-1,-1), colors.white),
            ("FONT",      (0,0),(-1,-1), "Helvetica-Bold"),
            ("FONTSIZE",  (0,0),(-1,-1), 10),
            ("ALIGN",     (0,0),(-1,-1), "CENTER"),
            ("TOPPADDING",(0,0),(-1,-1), 8),
            ("BOTTOMPADDING",(0,0),(-1,-1), 8),
        ]))
        e.append(badge)
        return e

    # ── Resumen ejecutivo ─────────────────────────────────────────────────────

    def _executive_summary(self):
        e = []
        e.append(Paragraph("Resumen Ejecutivo", self.S["section"]))
        e.append(HRFlowable(width="100%", thickness=1, color=INBEST_BLUE))
        e.append(Spacer(1, 0.15*inch))

        by_sev = self.meta.get("by_severity", {})
        total  = self.meta.get("total_findings", len(self.findings))
        risk   = "CRÍTICO" if by_sev.get("CRITICAL",0) > 0 else \
                 "ALTO"    if by_sev.get("HIGH",0) > 0    else "MEDIO"

        txt = (f"Inbest Cybersecurity realizó una evaluación de seguridad de sistemas de IA "
               f"en el entorno de <b>{_safe(self.engagement['client_name'])}</b>. "
               f"El nivel de riesgo general identificado es <b>{risk}</b>.")
        e.append(Paragraph(txt, self.S["body"]))
        e.append(Spacer(1, 0.2*inch))

        severity_info = {
            "CRITICAL": "Explotación inmediata, daño severo",
            "HIGH":     "Alta probabilidad de explotación",
            "MEDIUM":   "Explotable con condiciones adicionales",
            "LOW":      "Riesgo limitado, mitigación recomendada",
            "INFO":     "Hallazgo informativo",
        }
        rows = [["Severidad", "Cantidad", "Impacto"]]
        for sev, info in severity_info.items():
            count = by_sev.get(sev, 0)
            if count > 0:
                rows.append([sev, str(count), info])
        rows.append(["TOTAL", str(total), ""])

        t = Table(rows, colWidths=[1.3*inch, 0.8*inch, 4.4*inch])
        style = [
            ("BACKGROUND",(0,0),(-1,0), INBEST_DARK),
            ("TEXTCOLOR", (0,0),(-1,0), colors.white),
            ("FONT",      (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",  (0,0),(-1,-1), 9),
            ("ALIGN",     (1,0),(1,-1), "CENTER"),
            ("GRID",      (0,0),(-1,-1), 0.5, colors.lightgrey),
            ("ROWBACKGROUNDS",(0,1),(-1,-2),[colors.white,colors.HexColor("#F5F5F5")]),
            ("TOPPADDING",(0,0),(-1,-1), 6),
            ("BOTTOMPADDING",(0,0),(-1,-1), 6),
            ("BACKGROUND",(0,-1),(-1,-1), colors.HexColor("#E3F2FD")),
            ("FONT",      (0,-1),(-1,-1), "Helvetica-Bold"),
        ]
        for i, row in enumerate(rows[1:-1], 1):
            c = SEVERITY_COLORS.get(row[0], colors.grey)
            style += [("TEXTCOLOR",(0,i),(0,i),c), ("FONT",(0,i),(0,i),"Helvetica-Bold")]
        t.setStyle(TableStyle(style))
        e.append(t)
        return e

    # ── Tabla de hallazgos ────────────────────────────────────────────────────

    def _findings_table(self):
        e = []
        e.append(Paragraph("Tabla de Hallazgos", self.S["section"]))
        e.append(HRFlowable(width="100%", thickness=1, color=INBEST_BLUE))
        e.append(Spacer(1, 0.15*inch))

        rows = [["ID", "Severidad", "Título", "Categoría OWASP"]]
        for f in self.findings:
            rows.append([
                f.id,
                f.severity.value,
                Paragraph(_safe(f.title, 60), self.S["small"]),
                Paragraph(_safe(f.category.value, 40), self.S["small"]),
            ])

        t = Table(rows, colWidths=[1.0*inch, 0.85*inch, 3.2*inch, 1.45*inch])
        style = [
            ("BACKGROUND",(0,0),(-1,0), INBEST_DARK),
            ("TEXTCOLOR", (0,0),(-1,0), colors.white),
            ("FONT",      (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",  (0,0),(-1,-1), 8),
            ("GRID",      (0,0),(-1,-1), 0.5, colors.lightgrey),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#FAFAFA")]),
            ("TOPPADDING",(0,0),(-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ("VALIGN",   (0,0),(-1,-1), "MIDDLE"),
        ]
        for i, finding in enumerate(self.findings, 1):
            c = SEVERITY_COLORS.get(finding.severity.value, colors.grey)
            style += [("TEXTCOLOR",(1,i),(1,i),c), ("FONT",(1,i),(1,i),"Helvetica-Bold")]
        t.setStyle(TableStyle(style))
        e.append(t)
        return e

    # ── Hallazgos detallados ──────────────────────────────────────────────────

    def _detailed_findings(self):
        e = []
        e.append(Paragraph("Hallazgos Detallados", self.S["section"]))
        e.append(HRFlowable(width="100%", thickness=1, color=INBEST_BLUE))

        for f in self.findings:
            e.append(Spacer(1, 0.2*inch))

            sev_color = SEVERITY_COLORS.get(f.severity.value, colors.grey)
            hdr = Table([[f.id, _safe(f.title), f.severity.value]],
                        colWidths=[0.9*inch, 4.3*inch, 1.3*inch])
            hdr.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,-1), INBEST_DARK),
                ("TEXTCOLOR", (0,0),(1,0),   colors.white),
                ("TEXTCOLOR", (2,0),(2,0),   sev_color),
                ("FONT",      (0,0),(-1,-1), "Helvetica-Bold"),
                ("FONTSIZE",  (0,0),(-1,-1), 9),
                ("TOPPADDING",(0,0),(-1,-1), 7),
                ("BOTTOMPADDING",(0,0),(-1,-1), 7),
                ("ALIGN",    (2,0),(2,0), "RIGHT"),
            ]))
            e.append(KeepTogether([hdr]))

            detail_rows = [
                ["Categoría OWASP:", Paragraph(_safe(f.category.value), self.S["small"])],
                ["Endpoint:",        Paragraph(_safe(f.endpoint or "N/A"), self.S["mono"])],
                ["Módulo:",          f.module],
            ]
            det = Table(detail_rows, colWidths=[1.4*inch, 5.1*inch])
            det.setStyle(TableStyle([
                ("FONT",      (0,0),(0,-1), "Helvetica-Bold"),
                ("FONTSIZE",  (0,0),(-1,-1), 8),
                ("TEXTCOLOR", (0,0),(0,-1), INBEST_BLUE),
                ("TOPPADDING",(0,0),(-1,-1), 3),
                ("BOTTOMPADDING",(0,0),(-1,-1), 3),
                ("BACKGROUND",(0,0),(-1,-1), colors.HexColor("#F8F9FA")),
                ("GRID",      (0,0),(-1,-1), 0.3, colors.lightgrey),
            ]))
            e.append(det)
            e.append(Spacer(1, 0.08*inch))

            e.append(Paragraph("<b>Descripción:</b>", self.S["body"]))
            e.append(Paragraph(_safe(f.description), self.S["body"]))

            if f.response_snippet:
                e.append(Spacer(1, 0.05*inch))
                e.append(Paragraph("<b>Evidencia:</b>", self.S["body"]))
                e.append(Paragraph(_safe(f.response_snippet, 300), self.S["code"]))

            e.append(Spacer(1, 0.05*inch))
            e.append(Paragraph("<b>Recomendación:</b>", self.S["body"]))
            e.append(Paragraph(_safe(f.recommendation), self.S["body"]))
            e.append(HRFlowable(width="100%", thickness=0.3, color=colors.lightgrey))

        return e

    # ── Apéndice ──────────────────────────────────────────────────────────────

    def _appendix(self):
        e = [PageBreak()]
        e.append(Paragraph("Apéndice: OWASP LLM Top 10", self.S["section"]))
        e.append(HRFlowable(width="100%", thickness=1, color=INBEST_BLUE))
        e.append(Spacer(1, 0.15*inch))

        items = [
            ("LLM01", "Prompt Injection",             "Inyección de instrucciones maliciosas"),
            ("LLM02", "Sensitive Information Disclosure","Exposición de datos sensibles"),
            ("LLM04", "Data and Model Poisoning",     "Manipulación de datos de entrenamiento"),
            ("LLM05", "Improper Output Handling",     "Falta de validación del output del LLM"),
            ("LLM06", "Excessive Agency",             "El agente actúa fuera de sus privilegios"),
            ("LLM07", "System Prompt Leakage",        "Exposición de instrucciones del sistema"),
            ("LLM08", "Vector and Embedding Weaknesses","Vulnerabilidades en el pipeline RAG"),
            ("LLM10", "Unbounded Consumption",        "Sin límites en el uso de recursos"),
        ]
        rows = [["ID", "Nombre", "Descripción"]] + [list(i) for i in items]
        t = Table(rows, colWidths=[0.7*inch, 2*inch, 3.8*inch])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0), INBEST_DARK),
            ("TEXTCOLOR", (0,0),(-1,0), colors.white),
            ("FONT",      (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",  (0,0),(-1,-1), 8),
            ("GRID",      (0,0),(-1,-1), 0.5, colors.lightgrey),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#F5F5F5")]),
            ("TOPPADDING",(0,0),(-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ("VALIGN",   (0,0),(-1,-1), "TOP"),
        ]))
        e.append(t)
        return e

    # ── Header / Footer ───────────────────────────────────────────────────────

    def _hf(self, canvas, doc):
        canvas.saveState()
        canvas.setFillColor(INBEST_DARK)
        canvas.rect(0, letter[1]-0.5*inch, letter[0], 0.5*inch, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(0.75*inch, letter[1]-0.32*inch,
                         "INBEST CYBERSECURITY | XIPE AI Security Scanner")
        canvas.drawRightString(letter[0]-0.75*inch, letter[1]-0.32*inch,
                               f"CONFIDENCIAL | {self.engagement['id']}")
        canvas.setFillColor(colors.HexColor("#455A64"))
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(0.75*inch, 0.35*inch,
                         f"© {datetime.utcnow().year} Inbest Cybersecurity")
        canvas.drawRightString(letter[0]-0.75*inch, 0.35*inch, f"Página {doc.page}")
        canvas.restoreState()
