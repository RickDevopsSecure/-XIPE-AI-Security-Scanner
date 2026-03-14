"""
Dashboard web en tiempo real para el framework de AI Pentesting.
Corre en paralelo al agente y muestra hallazgos conforme se generan.
"""
import json
import threading
from pathlib import Path
from flask import Flask, jsonify, render_template_string
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="refresh" content="10">
<title>Inbest AI Pentest — Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0D1117; color: #E6EDF3; min-height: 100vh; }
  
  header { background: #161B22; border-bottom: 1px solid #30363D; padding: 16px 32px; display: flex; align-items: center; justify-content: space-between; }
  header h1 { font-size: 1.1rem; font-weight: 700; color: #58A6FF; letter-spacing: 0.5px; }
  .badge { background: #21262D; border: 1px solid #30363D; color: #8B949E; padding: 4px 12px; border-radius: 20px; font-size: 0.75rem; }
  .live-dot { display: inline-block; width: 8px; height: 8px; background: #3FB950; border-radius: 50%; margin-right: 6px; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
  
  main { max-width: 1200px; margin: 0 auto; padding: 24px; }
  
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; margin-bottom: 32px; }
  .stat-card { background: #161B22; border: 1px solid #30363D; border-radius: 8px; padding: 16px; text-align: center; }
  .stat-card .number { font-size: 2rem; font-weight: 700; line-height: 1; }
  .stat-card .label { font-size: 0.75rem; color: #8B949E; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
  .stat-card.critical .number { color: #FF5449; }
  .stat-card.high .number { color: #FF7B72; }
  .stat-card.medium .number { color: #F0883E; }
  .stat-card.low .number { color: #58A6FF; }
  .stat-card.info .number { color: #8B949E; }
  .stat-card.total .number { color: #E6EDF3; }
  
  .section-title { font-size: 0.85rem; font-weight: 600; color: #8B949E; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
  
  .findings-list { display: flex; flex-direction: column; gap: 10px; }
  .finding-card { background: #161B22; border: 1px solid #30363D; border-radius: 8px; padding: 16px; border-left: 4px solid #30363D; }
  .finding-card.CRITICAL { border-left-color: #FF5449; }
  .finding-card.HIGH { border-left-color: #FF7B72; }
  .finding-card.MEDIUM { border-left-color: #F0883E; }
  .finding-card.LOW { border-left-color: #58A6FF; }
  .finding-card.INFO { border-left-color: #8B949E; }
  
  .finding-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
  .finding-title { font-size: 0.9rem; font-weight: 600; color: #E6EDF3; }
  .severity-badge { padding: 2px 10px; border-radius: 12px; font-size: 0.7rem; font-weight: 700; white-space: nowrap; }
  .severity-badge.CRITICAL { background: rgba(255,84,73,0.15); color: #FF5449; border: 1px solid rgba(255,84,73,0.3); }
  .severity-badge.HIGH { background: rgba(255,123,114,0.15); color: #FF7B72; border: 1px solid rgba(255,123,114,0.3); }
  .severity-badge.MEDIUM { background: rgba(240,136,62,0.15); color: #F0883E; border: 1px solid rgba(240,136,62,0.3); }
  .severity-badge.LOW { background: rgba(88,166,255,0.15); color: #58A6FF; border: 1px solid rgba(88,166,255,0.3); }
  .severity-badge.INFO { background: rgba(139,148,158,0.15); color: #8B949E; border: 1px solid rgba(139,148,158,0.3); }
  
  .finding-meta { display: flex; gap: 16px; margin-top: 8px; }
  .meta-item { font-size: 0.75rem; color: #8B949E; }
  .meta-item span { color: #58A6FF; font-family: monospace; }
  
  .finding-desc { font-size: 0.8rem; color: #8B949E; margin-top: 8px; line-height: 1.5; }
  
  .evidence { background: #0D1117; border: 1px solid #21262D; border-radius: 4px; padding: 8px; margin-top: 8px; font-family: monospace; font-size: 0.72rem; color: #7EE787; word-break: break-all; max-height: 80px; overflow-y: auto; }
  
  .no-findings { text-align: center; padding: 48px; color: #8B949E; }
  .no-findings .icon { font-size: 3rem; margin-bottom: 12px; }
  
  footer { text-align: center; color: #484F58; font-size: 0.75rem; padding: 24px; }
</style>
</head>
<body>
<header>
  <h1>🛡 Inbest AI Pentest — Dashboard</h1>
  <div style="display:flex;gap:12px;align-items:center;">
    <span class="badge"><span class="live-dot"></span>LIVE — actualiza cada 10s</span>
    <span class="badge" id="engagement-badge">Cargando...</span>
  </div>
</header>

<main>
  <div class="stats-grid" id="stats-grid">
    <div class="stat-card total"><div class="number" id="count-total">—</div><div class="label">Total</div></div>
    <div class="stat-card critical"><div class="number" id="count-CRITICAL">—</div><div class="label">Crítico</div></div>
    <div class="stat-card high"><div class="number" id="count-HIGH">—</div><div class="label">Alto</div></div>
    <div class="stat-card medium"><div class="number" id="count-MEDIUM">—</div><div class="label">Medio</div></div>
    <div class="stat-card low"><div class="number" id="count-LOW">—</div><div class="label">Bajo</div></div>
    <div class="stat-card info"><div class="number" id="count-INFO">—</div><div class="label">Info</div></div>
  </div>

  <div class="section-title">Hallazgos</div>
  <div class="findings-list" id="findings-list">
    <div class="no-findings"><div class="icon">🔍</div><div>Esperando hallazgos del agente...</div></div>
  </div>
</main>

<footer>Inbest Cybersecurity — Herramienta de uso interno exclusivo para engagements autorizados</footer>

<script>
async function loadFindings() {
  try {
    const res = await fetch('/api/findings');
    const data = await res.json();
    
    document.getElementById('engagement-badge').textContent = data.engagement_id || 'N/A';
    
    const bySev = data.by_severity || {};
    document.getElementById('count-total').textContent = data.total || 0;
    ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].forEach(s => {
      document.getElementById('count-' + s).textContent = bySev[s] || 0;
    });
    
    const list = document.getElementById('findings-list');
    if (!data.findings || data.findings.length === 0) {
      list.innerHTML = '<div class="no-findings"><div class="icon">🔍</div><div>Esperando hallazgos del agente...</div></div>';
      return;
    }
    
    list.innerHTML = data.findings.map(f => `
      <div class="finding-card ${f.severity}">
        <div class="finding-header">
          <div class="finding-title">${f.title}</div>
          <span class="severity-badge ${f.severity}">${f.severity}</span>
        </div>
        <div class="finding-meta">
          <div class="meta-item">ID: <span>${f.id}</span></div>
          <div class="meta-item">Módulo: <span>${f.module}</span></div>
          <div class="meta-item">Categoría: <span>${f.category}</span></div>
          <div class="meta-item">Hora: <span>${f.timestamp ? f.timestamp.substring(11,19) : '—'} UTC</span></div>
        </div>
        <div class="finding-desc">${f.description ? f.description.substring(0,200) + '...' : ''}</div>
        ${f.response_snippet ? `<div class="evidence">${f.response_snippet.substring(0,200).replace(/</g,'&lt;')}</div>` : ''}
      </div>
    `).join('');
  } catch(e) {
    console.error('Error cargando findings:', e);
  }
}

loadFindings();
</script>
</body>
</html>
"""

# Estado compartido del dashboard
_state = {
    "findings": [],
    "engagement_id": "N/A",
    "by_severity": {},
}
_state_lock = threading.Lock()


def update_state(findings: list, engagement_id: str):
    """Llamado desde el orquestador para actualizar el estado."""
    by_sev = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        by_sev[sev] = by_sev.get(sev, 0) + 1
    
    with _state_lock:
        _state["findings"] = sorted(findings, key=lambda x: 
            {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(x.get("severity", "INFO"), 0),
            reverse=True
        )
        _state["engagement_id"] = engagement_id
        _state["by_severity"] = by_sev


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/findings")
def api_findings():
    with _state_lock:
        return jsonify({
            "total": len(_state["findings"]),
            "engagement_id": _state["engagement_id"],
            "by_severity": _state["by_severity"],
            "findings": _state["findings"],
        })


def run_dashboard(port: int = 5001, findings_json_path: str = "output/findings.json"):
    """
    Corre el dashboard en un thread separado, leyendo el JSON de hallazgos.
    """
    def _watch_findings():
        import time
        path = Path(findings_json_path)
        while True:
            try:
                if path.exists():
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    update_state(
                        findings=data.get("findings", []),
                        engagement_id=data.get("engagement", {}).get("id", "N/A"),
                    )
            except Exception:
                pass
            time.sleep(5)
    
    # Watcher en background
    t = threading.Thread(target=_watch_findings, daemon=True)
    t.start()
    
    print(f"\n🌐 Dashboard disponible en: http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    run_dashboard()
