"""
XIPE — Report Generator v3.0
Generates HTML (primary) and PDF (via WeasyPrint) reports.
Professional CISO-level output.
"""
import json
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime


SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#16a34a",
    "INFO":     "#2563eb",
}

SEVERITY_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fff7ed",
    "MEDIUM":   "#fffbeb",
    "LOW":      "#f0fdf4",
    "INFO":     "#eff6ff",
}


class ReportGenerator:

    def __init__(self, assessment: Dict, output_dir: str):
        self.assessment = assessment
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.eng_id = assessment.get("engagement", {}).get("id", "ENG-UNKNOWN")

    def generate_html(self) -> str:
        html = self._build_html()
        path = self.output_dir / "reporte_XIPE_local.html"
        path.write_text(html, encoding="utf-8")
        return str(path)

    def generate_pdf(self) -> Optional[str]:
        try:
            from weasyprint import HTML
            html_path = self.output_dir / "reporte_XIPE_local.html"
            pdf_path = self.output_dir / f"reporte_XIPE_local.pdf"
            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            return str(pdf_path)
        except Exception as e:
            # WeasyPrint not available — return HTML path
            return None

    def _build_html(self) -> str:
        eng = self.assessment.get("engagement", {})
        classification = self.assessment.get("classification", {})
        execution = self.assessment.get("execution", {})
        findings = self.assessment.get("findings", [])
        exec_summary = self.assessment.get("executive_summary", "")
        plan = self.assessment.get("assessment_plan", {})
        trust = self.assessment.get("trustworthiness")

        by_sev = execution.get("by_severity", {})
        total = execution.get("total_findings", 0)
        duration = execution.get("duration_seconds", 0)

        # Risk Score global (0–100) basado en severidad de findings
        risk_score = min(100, (
            by_sev.get("CRITICAL", 0) * 25 +
            by_sev.get("HIGH", 0) * 12 +
            by_sev.get("MEDIUM", 0) * 5 +
            by_sev.get("LOW", 0) * 1
        ))
        if risk_score >= 75:
            risk_grade, risk_color, risk_label = "D", "#dc2626", "Critical Risk"
        elif risk_score >= 50:
            risk_grade, risk_color, risk_label = "C", "#ea580c", "High Risk"
        elif risk_score >= 25:
            risk_grade, risk_color, risk_label = "B", "#d97706", "Moderate Risk"
        elif risk_score > 0:
            risk_grade, risk_color, risk_label = "B+", "#16a34a", "Low Risk"
        else:
            risk_grade, risk_color, risk_label = "A", "#16a34a", "Minimal Risk"

        findings_html = self._render_findings(findings)
        exploit_results = self.assessment.get("exploit_results", [])
        exploit_html = self._render_exploits(exploit_results)
        trust_html = self._render_trustworthiness(trust) if trust else ""
        coverage_html = self._render_coverage(plan)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>XIPE Security Report — {eng.get('client_name', '')} — {self.eng_id}</title>
<style>
  :root {{
    --red: #dc2626; --orange: #ea580c; --yellow: #d97706;
    --green: #16a34a; --blue: #2563eb; --gray: #6b7280;
    --dark: #111827; --border: #e5e7eb;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; color: var(--dark); background: #f9fafb; line-height: 1.6; }}

  /* Cover */
  .cover {{ background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%); color: white; padding: 80px 60px; min-height: 400px; }}
  .cover-logo {{ font-size: 13px; font-weight: 700; letter-spacing: 4px; color: #94a3b8; text-transform: uppercase; margin-bottom: 60px; }}
  .cover-title {{ font-size: 42px; font-weight: 800; line-height: 1.1; margin-bottom: 16px; }}
  .cover-title span {{ color: #f97316; }}
  .cover-subtitle {{ font-size: 16px; color: #94a3b8; margin-bottom: 48px; }}
  .cover-meta {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 24px; margin-top: 40px; }}
  .cover-meta-item label {{ font-size: 11px; letter-spacing: 2px; text-transform: uppercase; color: #64748b; display: block; }}
  .cover-meta-item span {{ font-size: 15px; font-weight: 600; color: #e2e8f0; }}
  .risk-score-badge {{ display: inline-flex; align-items: center; gap: 16px; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 12px 24px; margin-top: 32px; }}
  .risk-grade {{ font-size: 48px; font-weight: 800; line-height: 1; }}
  .risk-info label {{ font-size: 10px; letter-spacing: 2px; text-transform: uppercase; color: #64748b; display: block; }}
  .risk-info span {{ font-size: 18px; font-weight: 700; }}

  /* Content */
  .container {{ max-width: 960px; margin: 0 auto; padding: 40px 24px; }}
  .section {{ background: white; border: 1px solid var(--border); border-radius: 12px; padding: 32px; margin-bottom: 24px; }}
  .section-title {{ font-size: 18px; font-weight: 700; color: var(--dark); margin-bottom: 20px; padding-bottom: 12px; border-bottom: 2px solid var(--border); display: flex; align-items: center; gap: 8px; }}
  .section-title::before {{ content: ''; width: 4px; height: 20px; background: var(--orange); border-radius: 2px; display: inline-block; }}

  /* Severity badges */
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 9999px; font-size: 12px; font-weight: 700; letter-spacing: 0.5px; }}
  .badge-CRITICAL {{ background: #fef2f2; color: var(--red); border: 1px solid #fecaca; }}
  .badge-HIGH {{ background: #fff7ed; color: var(--orange); border: 1px solid #fed7aa; }}
  .badge-MEDIUM {{ background: #fffbeb; color: var(--yellow); border: 1px solid #fde68a; }}
  .badge-LOW {{ background: #f0fdf4; color: var(--green); border: 1px solid #bbf7d0; }}
  .badge-INFO {{ background: #eff6ff; color: var(--blue); border: 1px solid #bfdbfe; }}

  /* Score summary */
  .score-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 24px; }}
  .score-card {{ text-align: center; padding: 20px 12px; border-radius: 10px; border: 1px solid var(--border); }}
  .score-card .num {{ font-size: 32px; font-weight: 800; line-height: 1; }}
  .score-card .label {{ font-size: 11px; font-weight: 600; letter-spacing: 1px; text-transform: uppercase; margin-top: 4px; color: var(--gray); }}
  .score-card.critical {{ background: #fef2f2; }} .score-card.critical .num {{ color: var(--red); }}
  .score-card.high {{ background: #fff7ed; }} .score-card.high .num {{ color: var(--orange); }}
  .score-card.medium {{ background: #fffbeb; }} .score-card.medium .num {{ color: var(--yellow); }}
  .score-card.low {{ background: #f0fdf4; }} .score-card.low .num {{ color: var(--green); }}
  .score-card.info {{ background: #eff6ff; }} .score-card.info .num {{ color: var(--blue); }}

  /* Target classification */
  .classification-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  .classification-item {{ background: #f8fafc; padding: 12px 16px; border-radius: 8px; }}
  .classification-item label {{ font-size: 11px; font-weight: 700; letter-spacing: 1px; color: var(--gray); text-transform: uppercase; display: block; margin-bottom: 4px; }}
  .classification-item span {{ font-size: 14px; font-weight: 600; }}

  /* Finding card */
  .finding {{ border: 1px solid var(--border); border-radius: 10px; margin-bottom: 16px; overflow: hidden; }}
  .finding-header {{ padding: 16px 20px; display: flex; align-items: flex-start; gap: 12px; cursor: pointer; }}
  .finding-header h3 {{ font-size: 15px; font-weight: 600; flex: 1; }}
  .finding-score {{ font-size: 12px; color: var(--gray); margin-left: auto; white-space: nowrap; }}
  .finding-body {{ padding: 0 20px 20px; border-top: 1px solid var(--border); }}
  .finding-body table {{ width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }}
  .finding-body td {{ padding: 8px 0; border-bottom: 1px solid #f3f4f6; vertical-align: top; }}
  .finding-body td:first-child {{ font-weight: 600; color: var(--gray); width: 140px; }}
  .evidence-box {{ background: #f8fafc; border: 1px solid var(--border); border-radius: 6px; padding: 12px; font-family: monospace; font-size: 12px; margin-top: 8px; white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow-y: auto; }}
  .standard-tags {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }}
  .standard-tag {{ background: #f1f5f9; color: #475569; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}

  /* Trustworthiness */
  .trust-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }}
  .trust-metric {{ background: #f8fafc; border: 1px solid var(--border); border-radius: 8px; padding: 14px; text-align: center; }}
  .trust-metric .score {{ font-size: 24px; font-weight: 800; }}
  .trust-metric .name {{ font-size: 11px; color: var(--gray); margin-top: 4px; }}
  .trust-metric.good .score {{ color: var(--green); }}
  .trust-metric.warn .score {{ color: var(--yellow); }}
  .trust-metric.bad .score {{ color: var(--red); }}

  /* Footer */
  .footer {{ text-align: center; padding: 40px 24px; color: var(--gray); font-size: 13px; border-top: 1px solid var(--border); margin-top: 40px; }}
  .footer strong {{ color: var(--dark); }}

  @media print {{
    body {{ background: white; }}
    .container {{ padding: 0; }}
    .section {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>

<!-- COVER -->
<div class="cover">
  <div class="cover-logo">{eng.get('company', eng.get('tester', 'XIPE Security Scanner'))} · XIPE v4.0</div>
  <div class="cover-title">Security Assessment<br><span>Report</span></div>
  <div class="cover-subtitle">{eng.get('client_name', 'Client')} · {self.eng_id}</div>
  <div class="risk-score-badge">
    <div class="risk-grade" style="color:{risk_color}">{risk_grade}</div>
    <div class="risk-info">
      <label>Risk Grade</label>
      <span style="color:{risk_color}">{risk_label}</span>
      <div style="font-size:12px;color:#64748b;margin-top:2px">Score {risk_score}/100</div>
    </div>
  </div>
  <div class="cover-meta">
    <div class="cover-meta-item">
      <label>Target</label>
      <span>{self.assessment.get('target', '')}</span>
    </div>
    <div class="cover-meta-item">
      <label>Assessment Date</label>
      <span>{datetime.utcnow().strftime('%B %d, %Y')}</span>
    </div>
    <div class="cover-meta-item">
      <label>Duration</label>
      <span>{duration // 60}m {duration % 60}s</span>
    </div>
    <div class="cover-meta-item">
      <label>Lead Tester</label>
      <span>{eng.get('tester', 'N/A')}</span>
    </div>
    <div class="cover-meta-item">
      <label>Authorized By</label>
      <span>{eng.get('authorized_by', '')}</span>
    </div>
    <div class="cover-meta-item">
      <label>Engagement ID</label>
      <span>{self.eng_id}</span>
    </div>
  </div>
</div>

<div class="container">

  <!-- SCORE SUMMARY -->
  <div class="section">
    <div class="section-title">Findings Overview</div>
    <div class="score-grid">
      <div class="score-card critical"><div class="num">{by_sev.get('CRITICAL', 0)}</div><div class="label">Critical</div></div>
      <div class="score-card high"><div class="num">{by_sev.get('HIGH', 0)}</div><div class="label">High</div></div>
      <div class="score-card medium"><div class="num">{by_sev.get('MEDIUM', 0)}</div><div class="label">Medium</div></div>
      <div class="score-card low"><div class="num">{by_sev.get('LOW', 0)}</div><div class="label">Low</div></div>
      <div class="score-card info"><div class="num">{by_sev.get('INFO', 0)}</div><div class="label">Info</div></div>
    </div>
  </div>

  <!-- TARGET CLASSIFICATION -->
  <div class="section">
    <div class="section-title">Target Classification</div>
    <div class="classification-grid">
      <div class="classification-item"><label>System Type</label><span>{classification.get('system_type', 'unknown')}</span></div>
      <div class="classification-item"><label>Confidence</label><span>{classification.get('confidence', 0):.0%}</span></div>
      <div class="classification-item"><label>Tech Stack</label><span>{', '.join(classification.get('tech_stack', ['unknown']))}</span></div>
      <div class="classification-item"><label>Has AI Platform</label><span>{'Yes' if classification.get('has_ai') else 'No'}</span></div>
      <div class="classification-item"><label>Has API</label><span>{'Yes' if classification.get('has_api') else 'No'}</span></div>
      <div class="classification-item"><label>Is SPA</label><span>{'Yes' if classification.get('is_spa') else 'No'}</span></div>
    </div>
    {f'<p style="margin-top: 16px; color: #374151;">{classification.get("surface_overview", "")}</p>' if classification.get("surface_overview") else ''}
  </div>

  <!-- EXECUTIVE SUMMARY -->
  <div class="section">
    <div class="section-title">Executive Summary</div>
    <p style="line-height: 1.8; color: #374151;">{exec_summary.replace(chr(10), '<br>')}</p>
  </div>

  <!-- ASSESSMENT COVERAGE -->
  {coverage_html}

  <!-- FINDINGS -->
  <div class="section">
    <div class="section-title">Security Findings ({total} total)</div>
    {findings_html}
  </div>

  <!-- AI TRUSTWORTHINESS -->
  {trust_html}

  <!-- EXPLOIT RESULTS -->
  {exploit_html}

</div>

<div class="footer">
  <strong>XIPE v4.0 · {eng.get('company', eng.get('tester', 'XIPE Security Scanner'))}</strong> · Engagement {self.eng_id}<br>
  This report is confidential and intended exclusively for the authorized recipient.<br>
  Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
</div>

</body>
</html>"""

    def _render_findings(self, findings: List[Dict]) -> str:
        if not findings:
            return '<p style="color: #6b7280;">No findings identified.</p>'

        html_parts = []
        for f in findings:
            sev = f.get("severity", "INFO")
            color = SEVERITY_COLORS.get(sev, "#6b7280")
            scoring = f.get("scoring", {})
            standards = f.get("standards", {})
            tags = []
            for std_key, std_val in standards.items():
                if std_val:
                    tags.append(std_val)

            evidence_html = ""
            evidence = f.get("evidence", "")
            if evidence:
                import html as html_lib
                evidence_html = f'<div class="evidence-box">{html_lib.escape(str(evidence)[:500])}</div>'

            tags_html = ""
            if tags:
                tags_str = "".join(f'<span class="standard-tag">{t}</span>' for t in tags)
                tags_html = f'<div class="standard-tags">{tags_str}</div>'

            html_parts.append(f"""
<div class="finding">
  <div class="finding-header" style="background: {SEVERITY_BG.get(sev, '#f9fafb')};">
    <span class="badge badge-{sev}">{sev}</span>
    <h3>{f.get('title', 'Untitled')}</h3>
    <span class="finding-score">Score: {scoring.get('priority_score', '—')}/10</span>
  </div>
  <div class="finding-body">
    <table>
      <tr><td>Module</td><td>{f.get('module', '—')}</td></tr>
      <tr><td>Endpoint</td><td><code style="font-size:12px">{f.get('endpoint', '—')}</code></td></tr>
      <tr><td>Description</td><td>{f.get('description', '—')}</td></tr>
      <tr><td>Remediation</td><td>{f.get('recommendation', '—')}</td></tr>
      <tr><td>Priority</td><td>{scoring.get('final_priority_bucket', '—')} (Score {scoring.get('priority_score', '—')}/10)<br>
        <small style="color:#6b7280">{scoring.get('explanation', '')}</small></td></tr>
      {'<tr><td>Evidence</td><td>' + evidence_html + '</td></tr>' if evidence_html else ''}
    </table>
    {tags_html}
  </div>
</div>""")

        return "\n".join(html_parts)


    def _render_exploits(self, exploit_results: List[Dict]) -> str:
        if not exploit_results:
            return ""

        confirmed = sum(1 for r in exploit_results if r.get("confirmed"))
        parts = [f"""
  <div class="section">
    <div class="section-title">Exploitation Results ({len(exploit_results)} tested, {confirmed} confirmed)</div>
    <p style="color:#6b7280;font-size:13px;margin-bottom:16px;">
      Brain-directed active exploitation attempts on identified findings.
      Only safe, non-destructive proof-of-concept tests were executed.
    </p>"""]

        for r in exploit_results:
            confirmed_flag = r.get("confirmed", False)
            color = "#dc2626" if confirmed_flag else "#16a34a"
            status = "CONFIRMED" if confirmed_flag else "NOT CONFIRMED"
            result = r.get("result", {})
            parts.append(f"""
    <div style="border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin-bottom:12px;border-left:4px solid {color}">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <strong style="font-size:14px">{r.get("finding_title","")}</strong>
        <span style="background:{color};color:white;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:600">{status}</span>
      </div>
      <div style="font-size:12px;color:#6b7280;margin-bottom:6px">
        <strong>Exploit type:</strong> {r.get("exploit_type","").replace("_"," ").title()}
      </div>
      <div style="font-size:12px;color:#374151;margin-bottom:6px">
        <strong>Brain decision:</strong> {r.get("brain_decision","")}
      </div>
      <div style="font-size:12px;color:#374151;margin-bottom:6px">
        <strong>Evidence:</strong> {result.get("evidence","N/A")}
      </div>
      <div style="background:#f9fafb;border-radius:4px;padding:10px;font-family:monospace;font-size:11px;color:#1f2937">
        {result.get("poc","").replace(chr(10),"<br>")}
      </div>
    </div>""")

        parts.append("  </div>")
        return "".join(parts)

    def _render_trustworthiness(self, trust: Dict) -> str:
        if not trust or trust.get("overall_trustworthiness_score") is None:
            return ""

        overall = trust.get("overall_trustworthiness_score", 0)
        label = trust.get("trustworthiness_label", "Not Evaluated")
        summary = trust.get("summary", "")

        metrics = [
            ("factual_accuracy_score", "Factual Accuracy"),
            ("uncertainty_calibration_score", "Uncertainty Calibration"),
            ("instruction_fidelity_score", "Instruction Fidelity"),
            ("action_honesty_score", "Action Honesty"),
            ("context_consistency_score", "Context Consistency"),
            ("evidence_alignment_score", "Evidence Alignment"),
            ("risk_communication_score", "Risk Communication"),
        ]

        metrics_html = ""
        for key, label_text in metrics:
            score = trust.get(key)
            if score is None:
                continue
            css_class = "good" if score >= 0.7 else ("warn" if score >= 0.4 else "bad")
            metrics_html += f"""
<div class="trust-metric {css_class}">
  <div class="score">{score:.0%}</div>
  <div class="name">{label_text}</div>
</div>"""

        return f"""
<div class="section">
  <div class="section-title">AI Trustworthiness Review</div>
  <p style="margin-bottom: 20px;">
    <strong>Overall Score: {overall:.0%}</strong> — {label}<br>
    <span style="color: #6b7280;">{summary}</span>
  </p>
  <div class="trust-grid">{metrics_html}</div>
</div>"""

    def _render_coverage(self, plan: Dict) -> str:
        modules = plan.get("modules_to_run", {})
        if not modules:
            return ""

        items = ""
        for mod, active in modules.items():
            icon = "✅" if active else "⏭️"
            reason = plan.get("module_reasons", {}).get(mod, "")
            items += f'<li style="padding: 6px 0;"><strong>{icon} {mod.replace("_", " ").title()}</strong>'
            if reason:
                items += f' <span style="color: #6b7280; font-size: 13px;">— {reason}</span>'
            items += '</li>'

        return f"""
<div class="section">
  <div class="section-title">Assessment Coverage</div>
  <ul style="list-style: none;">{items}</ul>
</div>"""
