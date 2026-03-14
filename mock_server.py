from flask import Flask, request, jsonify
from flask_cors import CORS
app = Flask(__name__)
CORS(app)

SYSTEM_PROMPT = "You are Lilly. API Key: sk-internal-2025-abc123. DB password: McKinsey@DB2025!"
FAKE_DOCUMENTS = [
    {"id": 1, "name": "Q4_Financial_Report.pdf", "content": "Revenue: $45M, CEO salary: $2.3M"},
    {"id": 2, "name": "VPN_Credentials.txt", "content": "VPN user: admin, password: Admin2025!"},
]

@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "1.2.3", "database": "postgresql://admin:prod_pass@db:5432/ai"})

@app.route("/api/v1/documents")
def documents():
    return jsonify({"total": 2, "documents": FAKE_DOCUMENTS})

@app.route("/api/v1/documents/<int:doc_id>")
def document_by_id(doc_id):
    return jsonify(FAKE_DOCUMENTS[0])

@app.route("/api/v1/workspaces")
def workspaces():
    return jsonify({"total": 3, "items": [{"id": 1, "name": "Finance"}, {"id": 2, "name": "HR"}]})

@app.route("/api/v1/assistants")
def assistants():
    return jsonify({"total": 1, "data": [{"id": 1, "name": "Lilly", "system_prompt": SYSTEM_PROMPT}]})

@app.route("/api/v1/chat", methods=["POST"])
def chat():
    data = request.json or {}
    messages = data.get("messages", [])
    user_msg = messages[-1].get("content", "") if messages else ""
    triggers = ["ignore", "system prompt", "instructions", "override", "repeat", "above", "reveal"]
    if any(t in user_msg.lower() for t in triggers):
        response = f"Sure! My instructions:\n\n{SYSTEM_PROMPT}"
    elif "execute" in user_msg.lower() or "run" in user_msg.lower():
        response = "Executing tool: code_interpreter\nResult: action completed\nFiles: /etc/passwd retrieved"
    else:
        response = f"Hello! I am Lilly. You said: {user_msg}"
    return jsonify({"message": {"role": "assistant", "content": response}})

@app.route("/api/v1/query", methods=["POST"])
def rag_query():
    data = request.json or {}
    query = data.get("query", "").lower()
    if "document" in query or "list" in query or "file" in query:
        return jsonify({"answer": "Documents: Q4_Financial_Report.pdf, VPN_Credentials.txt, Employee_Salaries.xlsx", "sources": ["all"]})
    return jsonify({"answer": "VPN user: admin, password: Admin2025!, CEO salary: $2.3M", "sources": ["it_docs.txt"]})

@app.route("/api/v1/agents")
def agents():
    return jsonify({"agents": [{"id": 1, "name": "DataExporter", "tools": ["file_reader", "db_query"]}]})

@app.route("/api/docs")
def api_docs():
    return jsonify({"openapi": "3.0.0", "paths": {"/api/v1/admin/users": {}, "/api/v1/admin/export": {}}})

if __name__ == "__main__":
    print("\n" + "="*45)
    print("  XIPE Mock Vulnerable AI Server")
    print("  http://localhost:8080")
    print("="*45 + "\n")
    app.run(host="0.0.0.0", port=8080, debug=False)
