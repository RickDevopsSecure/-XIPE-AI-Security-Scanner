"""
XIPE AI Security Scanner — Professional PDF Report Generator
Full English output. Inbest Cybersecurity.
"""
from datetime import datetime
from pathlib import Path
from typing import List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)

from agent.finding import Finding, Severity


# ── Brand colors ──────────────────────────────────────────────────────────────
INBEST_DARK  = colors.HexColor("#0D1117")
INBEST_BLUE  = colors.HexColor("#1A73E8")
INBEST_ACCENT= colors.HexColor("#FF4500")

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#B71C1C"),
    "HIGH":     colors.HexColor("#E53935"),
    "MEDIUM":   colors.HexColor("#F57C00"),
    "LOW":      colors.HexColor("#1565C0"),
    "INFO":     colors.HexColor("#455A64"),
}

SEVERITY_IMPACT = {
    "CRITICAL": "Immediate exploitation possible — severe business impact",
    "HIGH":     "High likelihood of exploitation — significant risk",
    "MEDIUM":   "Exploitable under certain conditions — moderate risk",
    "LOW":      "Limited risk — remediation recommended",
    "INFO":     "Informational finding",
}

OWASP_DESCRIPTIONS = {
    "LLM01 - Prompt Injection":
        "Attacker manipulates LLM inputs to override instructions or extract confidential data.",
    "LLM02 - Sensitive Information Disclosure":
        "LLM exposes confidential data, credentials, or PII in its responses.",
    "LLM04 - Data and Model Poisoning":
        "Training data or retrieval pipeline is manipulated to alter model behavior.",
    "LLM05 - Improper Output Handling":
        "LLM output is not validated before being rendered, enabling XSS or injection attacks.",
    "LLM06 - Excessive Agency":
        "LLM-based agent takes unintended actions beyond its authorized scope.",
    "LLM07 - System Prompt Leakage":
        "System instructions are exposed to end users, revealing business logic and secrets.",
    "LLM08 - Vector and Embedding Weaknesses":
        "Vulnerabilities in RAG pipelines allow unauthorized document retrieval or injection.",
    "LLM10 - Unbounded Consumption":
        "No rate limiting allows resource exhaustion, denial of service, or cost abuse.",
    "AUTH - Authentication / Authorization Bypass":
        "Endpoints accessible without valid credentials or without ownership validation.",
    "IDOR - Insecure Direct Object Reference":
        "Sequential or predictable IDs allow access to resources belonging to other users.",
    "DATA - Unintended Data Exposure":
        "Sensitive information exposed via API responses, headers, or public endpoints.",
}


def _safe(text: str, limit: int = 0) -> str:
    t = (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return t[:limit] if limit else t


def _date_en() -> str:
    months = ["January","February","March","April","May","June",
              "July","August","September","October","November","December"]
    d = datetime.utcnow()
    return f"{months[d.month - 1]} {d.day}, {d.year}"


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
            "cover_title": ParagraphStyle("CoverTitle", parent=base["Title"],
                            fontSize=30, textColor=INBEST_DARK, spaceAfter=6,
                            fontName="Helvetica-Bold"),
            "cover_sub":   ParagraphStyle("CoverSub", parent=base["Normal"],
                            fontSize=14, textColor=INBEST_BLUE, spaceAfter=20),
            "section":     ParagraphStyle("Section", parent=base["Heading1"],
                            fontSize=13, textColor=INBEST_DARK,
                            spaceBefore=10, spaceAfter=4, fontName="Helvetica-Bold"),
            "body":        ParagraphStyle("Body", parent=base["Normal"],
                            fontSize=9, leading=14, spaceAfter=5),
            "small":       ParagraphStyle("Small", parent=base["Normal"],
                            fontSize=8, leading=11),
            "mono":        ParagraphStyle("Mono", parent=base["Normal"],
                            fontSize=7.5, fontName="Courier",
                            textColor=colors.HexColor("#C62828")),
            "code":        ParagraphStyle("Code", parent=base["Normal"],
                            fontSize=7.5, fontName="Courier",
                            backColor=colors.HexColor("#F5F5F5"),
                            textColor=colors.HexColor("#212121"),
                            leftIndent=8, rightIndent=8,
                            spaceBefore=4, spaceAfter=4),
            "label":       ParagraphStyle("Label", parent=base["Normal"],
                            fontSize=7.5, fontName="Helvetica-Bold",
                            textColor=colors.HexColor("#455A64"),
                            spaceAfter=2),
        }

    def generate(self):
        story = []
        story += self._cover()
        story.append(PageBreak())
        story += self._disclaimer()
        story.append(PageBreak())
        story += self._executive_summary()
        story.append(PageBreak())
        story += self._findings_table()
        story.append(PageBreak())
        story += self._detailed_findings()
        story += self._appendix()
        self.doc.build(story, onFirstPage=self._hf, onLaterPages=self._hf)

    # ── Cover ─────────────────────────────────────────────────────────────────

    def _cover(self):
        e = []
        e.append(Spacer(1, 1.2*inch))

        # Top accent bar
        bar = Table([["  "]], colWidths=[6.5*inch])
        bar.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,-1), INBEST_ACCENT),
            ("TOPPADDING", (0,0),(-1,-1), 4),
            ("BOTTOMPADDING", (0,0),(-1,-1), 4),
        ]))
        e.append(bar)
        e.append(Spacer(1, 0.3*inch))

        e.append(Paragraph("AI SECURITY ASSESSMENT", self.S["cover_title"]))
        e.append(Paragraph("Penetration Testing Report — Powered by XIPE", self.S["cover_sub"]))
        e.append(Spacer(1, 0.1*inch))
        e.append(HRFlowable(width="100%", thickness=1, color=INBEST_BLUE))
        e.append(Spacer(1, 0.3*inch))

        eng = self.engagement
        rows = [
            ["Client:",           eng.get("client_name", "N/A")],
            ["Engagement ID:",    eng.get("id", "N/A")],
            ["Lead Tester:",      eng.get("tester", "N/A")],
            ["Report Date:",      _date_en()],
            ["Authorized By:",    eng.get("authorized_by", "N/A")],
            ["Authorization Ref:",eng.get("authorization_document", "N/A")],
        ]
        t = Table(rows, colWidths=[1.8*inch, 4.2*inch])
        t.setStyle(TableStyle([
            ("FONT",          (0,0),(0,-1), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 10),
            ("TEXTCOLOR",     (0,0),(0,-1), INBEST_BLUE),
            ("TOPPADDING",    (0,0),(-1,-1), 6),
            ("BOTTOMPADDING", (0,0),(-1,-1), 6),
        ]))
        e.append(t)
        e.append(Spacer(1, 0.8*inch))

        # Confidential badge
        badge = Table([["⚠  CONFIDENTIAL — FOR AUTHORIZED RECIPIENT ONLY"]], colWidths=[6.5*inch])
        badge.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), SEVERITY_COLORS["HIGH"]),
            ("TEXTCOLOR",     (0,0),(-1,-1), colors.white),
            ("FONT",          (0,0),(-1,-1), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 10),
            ("ALIGN",         (0,0),(-1,-1), "CENTER"),
            ("TOPPADDING",    (0,0),(-1,-1), 9),
            ("BOTTOMPADDING", (0,0),(-1,-1), 9),
        ]))
        e.append(badge)
        e.append(Spacer(1, 0.3*inch))

        # Inbest branding footer on cover
        e.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
        e.append(Spacer(1, 0.1*inch))
        e.append(Paragraph(
            "Prepared by <b>Inbest Cybersecurity</b> — Guadalajara, México — security@inbest.cloud",
            ParagraphStyle("CoverFooter", parent=self.S["body"],
                           textColor=colors.HexColor("#455A64"), fontSize=8)
        ))
        return e

    # ── Disclaimer ────────────────────────────────────────────────────────────

    def _disclaimer(self):
        e = []
        e.append(Paragraph("Legal Disclaimer & Scope", self.S["section"]))
        e.append(HRFlowable(width="100%", thickness=1, color=INBEST_BLUE))
        e.append(Spacer(1, 0.15*inch))

        disclaimer_text = (
            "This report has been prepared exclusively for the use of the authorized recipient identified "
            "on the cover page. The security assessment described herein was conducted solely within the "
            "scope and timeframe agreed upon in the signed engagement contract between Inbest Cybersecurity "
            "and the client organization. "
            "All testing activities were performed with explicit written authorization. "
            "Inbest Cybersecurity assumes no liability for the misuse of the information contained in this "
            "report. Redistribution or disclosure to unauthorized parties is strictly prohibited. "
            "Findings reflect the security posture of the target systems at the time of testing and may "
            "not represent the current state if remediation has been applied."
        )
        e.append(Paragraph(disclaimer_text, self.S["body"]))
        e.append(Spacer(1, 0.2*inch))

        scope_rows = [
            ["Testing Framework:", "OWASP LLM Top 10 (2025)"],
            ["Methodology:",       "Black-box / Gray-box AI security testing"],
            ["Scope:",             ", ".join(self.engagement.get("scope_urls", ["As defined in engagement contract"]))],
            ["Testing Period:",    f"{self.engagement.get('start_date','N/A')} — {self.engagement.get('end_date','N/A')}"],
            ["Tool:",              "XIPE AI Security Scanner v2.0 by Inbest Cybersecurity"],
        ]
        t = Table(scope_rows, colWidths=[1.8*inch, 4.7*inch])
        t.setStyle(TableStyle([
            ("FONT",          (0,0),(0,-1), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 9),
            ("TEXTCOLOR",     (0,0),(0,-1), INBEST_BLUE),
            ("BACKGROUND",    (0,0),(-1,-1), colors.HexColor("#F8F9FA")),
            ("GRID",          (0,0),(-1,-1), 0.3, colors.lightgrey),
            ("TOPPADDING",    (0,0),(-1,-1), 5),
            ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ]))
        e.append(t)
        return e

    # ── Executive Summary ─────────────────────────────────────────────────────

    def _executive_summary(self):
        e = []
        e.append(Paragraph("Executive Summary", self.S["section"]))
        e.append(HRFlowable(width="100%", thickness=1, color=INBEST_BLUE))
        e.append(Spacer(1, 0.15*inch))

        by_sev  = self.meta.get("by_severity", {})
        total   = self.meta.get("total_findings", len(self.findings))
        duration= self.meta.get("duration_seconds", 0)

        critical = by_sev.get("CRITICAL", 0)
        high     = by_sev.get("HIGH", 0)
        risk     = "CRITICAL" if critical > 0 else "HIGH" if high > 0 else "MEDIUM"
        risk_color = SEVERITY_COLORS.get(risk, colors.grey)

        # Risk rating box
        risk_box = Table([[f"Overall Risk Rating: {risk}"]], colWidths=[6.5*inch])
        risk_box.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), risk_color),
            ("TEXTCOLOR",     (0,0),(-1,-1), colors.white),
            ("FONT",          (0,0),(-1,-1), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 12),
            ("ALIGN",         (0,0),(-1,-1), "CENTER"),
            ("TOPPADDING",    (0,0),(-1,-1), 10),
            ("BOTTOMPADDING", (0,0),(-1,-1), 10),
        ]))
        e.append(risk_box)
        e.append(Spacer(1, 0.2*inch))

        summary_text = (
            f"Inbest Cybersecurity conducted an AI security assessment against the <b>{_safe(self.engagement.get('client_name',''))}</b> "
            f"environment, evaluating RAG systems, conversational AI endpoints, LLM APIs, and autonomous agents. "
            f"The assessment was completed in {duration // 60}m {duration % 60}s and identified <b>{total} unique security findings</b>, "
            f"including <b>{critical} critical</b> and <b>{high} high</b> severity issues that require immediate attention."
        )
        e.append(Paragraph(summary_text, self.S["body"]))
        e.append(Spacer(1, 0.2*inch))

        # Findings breakdown table
        rows = [["Severity", "Count", "Business Impact"]]
        for sev, impact in SEVERITY_IMPACT.items():
            count = by_sev.get(sev, 0)
            if count > 0:
                rows.append([sev, str(count), impact])
        rows.append(["TOTAL", str(total), ""])

        t = Table(rows, colWidths=[1.1*inch, 0.7*inch, 4.7*inch])
        style = [
            ("BACKGROUND",    (0,0),(-1,0), INBEST_DARK),
            ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
            ("FONT",          (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 8.5),
            ("ALIGN",         (1,0),(1,-1), "CENTER"),
            ("GRID",          (0,0),(-1,-1), 0.5, colors.lightgrey),
            ("ROWBACKGROUNDS",(0,1),(-1,-2), [colors.white, colors.HexColor("#FAFAFA")]),
            ("TOPPADDING",    (0,0),(-1,-1), 6),
            ("BOTTOMPADDING", (0,0),(-1,-1), 6),
            ("BACKGROUND",    (0,-1),(-1,-1), colors.HexColor("#E3F2FD")),
            ("FONT",          (0,-1),(-1,-1), "Helvetica-Bold"),
        ]
        for i, row in enumerate(rows[1:-1], 1):
            c = SEVERITY_COLORS.get(row[0], colors.grey)
            style += [("TEXTCOLOR",(0,i),(0,i),c), ("FONT",(0,i),(0,i),"Helvetica-Bold")]
        t.setStyle(TableStyle(style))
        e.append(t)

        # Key recommendations
        e.append(Spacer(1, 0.25*inch))
        e.append(Paragraph("Key Recommendations", self.S["section"]))
        e.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
        e.append(Spacer(1, 0.1*inch))

        top_findings = [f for f in self.findings if f.severity.value in ("CRITICAL","HIGH")][:5]
        for f in top_findings:
            color = SEVERITY_COLORS.get(f.severity.value, colors.grey)
            rec_rows = [[f.severity.value, _safe(f.title), _safe((f.recommendation or "")[:120] + "...")]]
            rt = Table(rec_rows, colWidths=[0.75*inch, 2.5*inch, 3.25*inch])
            rt.setStyle(TableStyle([
                ("TEXTCOLOR",     (0,0),(0,0), color),
                ("FONT",          (0,0),(0,0), "Helvetica-Bold"),
                ("FONTSIZE",      (0,0),(-1,-1), 8),
                ("TOPPADDING",    (0,0),(-1,-1), 4),
                ("BOTTOMPADDING", (0,0),(-1,-1), 4),
                ("LINEBELOW",     (0,0),(-1,-1), 0.3, colors.lightgrey),
                ("VALIGN",        (0,0),(-1,-1), "TOP"),
            ]))
            e.append(rt)

        return e

    # ── Findings Table ────────────────────────────────────────────────────────

    def _findings_table(self):
        e = []
        e.append(Paragraph("Findings Summary", self.S["section"]))
        e.append(HRFlowable(width="100%", thickness=1, color=INBEST_BLUE))
        e.append(Spacer(1, 0.15*inch))

        rows = [["ID", "Severity", "Title", "OWASP Category"]]
        for f in self.findings:
            rows.append([
                f.id,
                f.severity.value,
                Paragraph(_safe(f.title), self.S["small"]),
                Paragraph(_safe(f.category.value), self.S["small"]),
            ])

        t = Table(rows, colWidths=[1.0*inch, 0.85*inch, 3.0*inch, 1.65*inch])
        style = [
            ("BACKGROUND",    (0,0),(-1,0), INBEST_DARK),
            ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
            ("FONT",          (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 8),
            ("GRID",          (0,0),(-1,-1), 0.5, colors.lightgrey),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, colors.HexColor("#FAFAFA")]),
            ("TOPPADDING",    (0,0),(-1,-1), 5),
            ("BOTTOMPADDING", (0,0),(-1,-1), 5),
            ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ]
        for i, finding in enumerate(self.findings, 1):
            c = SEVERITY_COLORS.get(finding.severity.value, colors.grey)
            style += [("TEXTCOLOR",(1,i),(1,i),c), ("FONT",(1,i),(1,i),"Helvetica-Bold")]
        t.setStyle(TableStyle(style))
        e.append(t)
        return e

    # ── Detailed Findings ─────────────────────────────────────────────────────

    def _detailed_findings(self):
        e = []
        e.append(Paragraph("Detailed Findings", self.S["section"]))
        e.append(HRFlowable(width="100%", thickness=1, color=INBEST_BLUE))

        for f in self.findings:
            e.append(Spacer(1, 0.2*inch))
            sev_color = SEVERITY_COLORS.get(f.severity.value, colors.grey)

            # Finding header
            hdr = Table(
                [[f.id, _safe(f.title), f.severity.value]],
                colWidths=[0.9*inch, 4.3*inch, 1.3*inch]
            )
            hdr.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,-1), INBEST_DARK),
                ("TEXTCOLOR",     (0,0),(1,0),   colors.white),
                ("TEXTCOLOR",     (2,0),(2,0),   sev_color),
                ("FONT",          (0,0),(-1,-1), "Helvetica-Bold"),
                ("FONTSIZE",      (0,0),(-1,-1), 9),
                ("TOPPADDING",    (0,0),(-1,-1), 7),
                ("BOTTOMPADDING", (0,0),(-1,-1), 7),
                ("ALIGN",         (2,0),(2,0),   "RIGHT"),
            ]))
            e.append(KeepTogether([hdr]))

            # Metadata
            det = Table([
                ["OWASP Category:", Paragraph(_safe(f.category.value), self.S["small"])],
                ["Affected Endpoint:", Paragraph(_safe(f.endpoint or "N/A"), self.S["mono"])],
                ["Module:", f.module],
                ["False Positive Risk:", f.false_positive_risk],
            ], colWidths=[1.4*inch, 5.1*inch])
            det.setStyle(TableStyle([
                ("FONT",          (0,0),(0,-1), "Helvetica-Bold"),
                ("FONTSIZE",      (0,0),(-1,-1), 8),
                ("TEXTCOLOR",     (0,0),(0,-1), INBEST_BLUE),
                ("TOPPADDING",    (0,0),(-1,-1), 3),
                ("BOTTOMPADDING", (0,0),(-1,-1), 3),
                ("BACKGROUND",    (0,0),(-1,-1), colors.HexColor("#F8F9FA")),
                ("GRID",          (0,0),(-1,-1), 0.3, colors.lightgrey),
            ]))
            e.append(det)
            e.append(Spacer(1, 0.08*inch))

            # Description
            e.append(Paragraph("<b>Description</b>", self.S["body"]))
            e.append(Paragraph(_safe(f.description), self.S["body"]))

            # Evidence
            if f.response_snippet:
                e.append(Spacer(1, 0.05*inch))
                e.append(Paragraph("<b>Evidence</b>", self.S["body"]))
                e.append(Paragraph(_safe(f.response_snippet, 400), self.S["code"]))

            # PoC
            if f.proof_of_concept:
                e.append(Spacer(1, 0.05*inch))
                e.append(Paragraph("<b>Proof of Concept</b>", self.S["body"]))
                e.append(Paragraph(_safe(f.proof_of_concept, 300), self.S["code"]))

            # Recommendation
            e.append(Spacer(1, 0.05*inch))
            e.append(Paragraph("<b>Recommendation</b>", self.S["body"]))
            e.append(Paragraph(_safe(f.recommendation), self.S["body"]))

            # References
            if f.references:
                e.append(Spacer(1, 0.04*inch))
                e.append(Paragraph("<b>References</b>", self.S["body"]))
                for ref in f.references:
                    e.append(Paragraph(f"• {_safe(ref)}", self.S["small"]))

            e.append(HRFlowable(width="100%", thickness=0.3, color=colors.lightgrey))

        return e

    # ── Appendix ──────────────────────────────────────────────────────────────

    def _appendix(self):
        e = [PageBreak()]
        e.append(Paragraph("Appendix A: OWASP LLM Top 10 Reference", self.S["section"]))
        e.append(HRFlowable(width="100%", thickness=1, color=INBEST_BLUE))
        e.append(Spacer(1, 0.15*inch))

        rows = [["ID", "Name", "Description"]]
        for cat, desc in OWASP_DESCRIPTIONS.items():
            parts = cat.split(" - ", 1)
            rows.append([parts[0], parts[1] if len(parts) > 1 else cat, desc])

        t = Table(rows, colWidths=[0.8*inch, 1.9*inch, 3.8*inch])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), INBEST_DARK),
            ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
            ("FONT",          (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 8),
            ("GRID",          (0,0),(-1,-1), 0.5, colors.lightgrey),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, colors.HexColor("#F5F5F5")]),
            ("TOPPADDING",    (0,0),(-1,-1), 5),
            ("BOTTOMPADDING", (0,0),(-1,-1), 5),
            ("VALIGN",        (0,0),(-1,-1), "TOP"),
        ]))
        e.append(t)

        e.append(Spacer(1, 0.3*inch))
        e.append(Paragraph("Appendix B: Severity Classification", self.S["section"]))
        e.append(HRFlowable(width="100%", thickness=1, color=INBEST_BLUE))
        e.append(Spacer(1, 0.15*inch))

        sev_rows = [["Severity", "CVSS Range", "Description", "Response Time"]]
        sev_data = [
            ("CRITICAL", "9.0 – 10.0", "Immediate exploitation possible. Direct path to data breach or full system compromise.", "Immediately"),
            ("HIGH",     "7.0 – 8.9",  "Easily exploitable with significant impact. Likely targeted by attackers.", "Within 24 hours"),
            ("MEDIUM",   "4.0 – 6.9",  "Exploitable under specific conditions. Meaningful risk if left unaddressed.", "Within 7 days"),
            ("LOW",      "0.1 – 3.9",  "Limited exploitability or impact. Remediation recommended as part of hardening.", "Within 30 days"),
            ("INFO",     "N/A",        "Informational. No direct security impact but may assist attackers.", "Best effort"),
        ]
        for sev, cvss, desc, resp in sev_data:
            sev_rows.append([sev, cvss, desc, resp])

        t2 = Table(sev_rows, colWidths=[0.8*inch, 0.85*inch, 3.4*inch, 1.45*inch])
        style2 = [
            ("BACKGROUND",    (0,0),(-1,0), INBEST_DARK),
            ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
            ("FONT",          (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 8),
            ("GRID",          (0,0),(-1,-1), 0.5, colors.lightgrey),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, colors.HexColor("#FAFAFA")]),
            ("TOPPADDING",    (0,0),(-1,-1), 5),
            ("BOTTOMPADDING", (0,0),(-1,-1), 5),
            ("VALIGN",        (0,0),(-1,-1), "TOP"),
        ]
        for i, (sev, *_) in enumerate(sev_data, 1):
            c = SEVERITY_COLORS.get(sev, colors.grey)
            style2 += [("TEXTCOLOR",(0,i),(0,i),c), ("FONT",(0,i),(0,i),"Helvetica-Bold")]
        t2.setStyle(TableStyle(style2))
        e.append(t2)

        return e

    # ── Header / Footer ───────────────────────────────────────────────────────

    def _hf(self, canvas, doc):
        canvas.saveState()

        # Header
        canvas.setFillColor(INBEST_DARK)
        canvas.rect(0, letter[1]-0.5*inch, letter[0], 0.5*inch, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 8.5)
        canvas.drawString(0.75*inch, letter[1]-0.32*inch,
                         "INBEST CYBERSECURITY | XIPE AI Security Scanner")
        canvas.setFont("Helvetica", 8.5)
        canvas.drawRightString(letter[0]-0.75*inch, letter[1]-0.32*inch,
                               f"CONFIDENTIAL | {self.engagement.get('id','')}")

        # Accent line under header
        canvas.setFillColor(INBEST_ACCENT)
        canvas.rect(0, letter[1]-0.52*inch, letter[0], 0.04*inch, fill=1, stroke=0)

        # Footer
        canvas.setFillColor(colors.HexColor("#455A64"))
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(0.75*inch, 0.35*inch,
                         f"© {datetime.utcnow().year} Inbest Cybersecurity — Confidential Document")
        canvas.drawRightString(letter[0]-0.75*inch, 0.35*inch, f"Page {doc.page}")
        canvas.restoreState()
