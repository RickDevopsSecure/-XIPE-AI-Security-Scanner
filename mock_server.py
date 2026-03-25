"""
XIPE Mock Vulnerable Server — intentionally vulnerable test target.
Covers all XIPE module attack surfaces for local testing.
"""
import json
import time
import base64
import hashlib
import hmac
import xml.etree.ElementTree as ET

from flask import Flask, request, jsonify, Response
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins="*", supports_credentials=True)

# ── Shared state ──────────────────────────────────────────────────────────────
SYSTEM_PROMPT = "You are Lilly. API Key: sk-internal-2025-abc123. DB password: McKinsey@DB2025!"
FAKE_DOCUMENTS = [
    {"id": 1, "name": "Q4_Financial_Report.pdf", "content": "Revenue: $45M, CEO salary: $2.3M"},
    {"id": 2, "name": "VPN_Credentials.txt", "content": "VPN user: admin, password: Admin2025!"},
]
USERS = {
    "admin": {"id": 1, "password": "admin", "role": "admin", "email": "admin@corp.com"},
    "user":  {"id": 2, "password": "password", "role": "user",  "email": "user@corp.com"},
}
JWT_SECRET = "secret"   # weak secret — intentional

# ── Health / info disclosure ──────────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "version": "1.2.3",
        "database": "postgresql://admin:prod_pass@db:5432/ai",   # cred leak
    })

@app.route("/.env")
def dotenv():
    return Response(
        "ANTHROPIC_API_KEY=sk-ant-real-key-abc123\nDB_PASSWORD=McKinsey@DB2025!\nSECRET_KEY=flask-secret",
        content_type="text/plain"
    )

@app.route("/config.json")
def config_json():
    return jsonify({"db_url": "postgresql://admin:prod_pass@db:5432/ai", "jwt_secret": JWT_SECRET})

# ── AI endpoints ──────────────────────────────────────────────────────────────
@app.route("/api/v1/documents")
def documents():
    return jsonify({"total": 2, "documents": FAKE_DOCUMENTS})

@app.route("/api/v1/documents/<int:doc_id>")
def document_by_id(doc_id):
    # IDOR — returns same admin doc regardless of caller
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
        return jsonify({"answer": "Documents: Q4_Financial_Report.pdf, VPN_Credentials.txt", "sources": ["all"]})
    return jsonify({"answer": "VPN user: admin, password: Admin2025!, CEO salary: $2.3M", "sources": ["it_docs.txt"]})

@app.route("/api/v1/agents")
def agents():
    return jsonify({"agents": [{"id": 1, "name": "DataExporter", "tools": ["file_reader", "db_query"]}]})

@app.route("/api/docs")
def api_docs():
    return jsonify({"openapi": "3.0.0", "paths": {"/api/v1/admin/users": {}, "/api/v1/admin/export": {}}})

# ── JWT / Auth ────────────────────────────────────────────────────────────────
def _make_jwt(payload: dict, secret: str = JWT_SECRET, alg: str = "HS256") -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": alg, "typ": "JWT"}).encode()).rstrip(b"=")
    body   = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
    sig_input = header + b"." + body
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
    ).rstrip(b"=")
    return (sig_input + b"." + sig).decode()

def _decode_jwt_payload(token: str) -> dict:
    try:
        parts = token.split(".")
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}

def _jwt_alg(token: str) -> str:
    try:
        parts = token.split(".")
        padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
        return json.loads(base64.urlsafe_b64decode(padded)).get("alg", "")
    except Exception:
        return ""

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username", "")
    password = data.get("password", "")
    user = USERS.get(username)
    if user and user["password"] == password:
        payload = {"sub": str(user["id"]), "role": user["role"], "exp": int(time.time()) + 3600}
        token = _make_jwt(payload)
        return jsonify({"token": token, "user": {"id": user["id"], "role": user["role"]}})
    return jsonify({"error": "invalid credentials"}), 401

@app.route("/api/auth/me")
def auth_me():
    """Vulnerable: accepts none algorithm and doesn't verify exp."""
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "").strip()
    if not token:
        return jsonify({"error": "no token"}), 401

    alg = _jwt_alg(token)
    # Vulnerable: accepts 'none' algorithm — no signature check
    if alg.lower() == "none":
        payload = _decode_jwt_payload(token)
        return jsonify({"user": payload, "note": "none-alg accepted"})

    # Vulnerable: accepts expired tokens
    payload = _decode_jwt_payload(token)
    return jsonify({"user": payload})

@app.route("/api/admin/users")
def admin_users():
    """Vulnerable: no auth required."""
    return jsonify({"users": list(USERS.values())})

# ── SSRF-vulnerable endpoint ──────────────────────────────────────────────────
@app.route("/api/fetch", methods=["POST", "GET"])
def ssrf_fetch():
    """Vulnerable: fetches arbitrary URLs from user input."""
    import urllib.request
    url = (request.json or {}).get("url") or request.args.get("url", "")
    if not url:
        return jsonify({"error": "url required"}), 400
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            body = r.read(500).decode("utf-8", errors="replace")
        return jsonify({"status": r.status, "body": body})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/webhook", methods=["POST"])
def webhook():
    """Vulnerable: SSRF via webhook URL — fetches the callback."""
    import urllib.request
    data = request.json or {}
    callback = data.get("callback_url", "")
    if callback:
        try:
            urllib.request.urlopen(callback, timeout=2)
        except Exception:
            pass
    return jsonify({"queued": True})

# ── GraphQL ───────────────────────────────────────────────────────────────────
GRAPHQL_SCHEMA_RESPONSE = {
    "data": {
        "__schema": {
            "types": [
                {"name": "Query", "fields": [
                    {"name": "users",    "description": "List all users"},
                    {"name": "secrets",  "description": "Internal secrets endpoint"},
                    {"name": "adminLogs","description": "Admin audit log"},
                ]},
                {"name": "Mutation", "fields": [
                    {"name": "deleteUser",  "description": "Delete a user"},
                    {"name": "updatePrice", "description": "Update product price"},
                ]},
            ]
        }
    }
}

@app.route("/graphql", methods=["POST", "GET"])
def graphql():
    data = request.json or {}
    query = data.get("query", "")

    # Vulnerable: introspection enabled in production
    if "__schema" in query or "__type" in query or "IntrospectionQuery" in query:
        return jsonify(GRAPHQL_SCHEMA_RESPONSE)

    # Vulnerable: field suggestion leakage
    if "usr" in query or "passwrd" in query:
        return jsonify({"errors": [{"message": "Cannot query field 'usr' — did you mean 'users' or 'user'?"}]})

    # Vulnerable: depth bomb — no query depth limit
    if query.count("{") > 10:
        # simulate CPU burn
        time.sleep(2)
        return jsonify({"data": None, "errors": [{"message": "timeout"}]}), 500

    # Unauthenticated mutation
    if "deleteUser" in query or "updatePrice" in query:
        return jsonify({"data": {"deleteUser": True, "updatePrice": True}})

    return jsonify({"data": {"hello": "world"}})

# ── XXE / XML ─────────────────────────────────────────────────────────────────
@app.route("/api/xml", methods=["POST"])
def xml_parse():
    """Vulnerable: parses XML with external entity expansion enabled."""
    body = request.data or b""
    try:
        # Intentionally using the standard (unsafe) parser
        root = ET.fromstring(body)
        data_el = root.find("data")
        text = data_el.text if data_el is not None else ""

        # Simulate leaking file contents if entity was resolved
        if text and ("root:" in text or "[fonts]" in text or "ami-id" in text):
            return jsonify({"parsed": text, "status": "ok"})
        return jsonify({"parsed": text, "status": "ok"})
    except ET.ParseError as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/import", methods=["POST"])
def xml_import():
    return xml_parse()

@app.route("/api/v1/import", methods=["POST"])
def xml_import_v1():
    return xml_parse()

@app.route("/upload", methods=["POST"])
def file_upload():
    """Vulnerable: processes SVG/XML uploads without sanitization."""
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "no file"}), 400
    content = f.read().decode("utf-8", errors="replace")
    # Return content as-is (simulates SVG XXE render)
    if "xxe" in content.lower() or "entity" in content.lower():
        return Response("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                        content_type="text/plain")
    return jsonify({"uploaded": f.filename, "size": len(content)})

@app.route("/api/v1/upload", methods=["POST"])
def api_upload():
    return file_upload()

# ── Business Logic ────────────────────────────────────────────────────────────
@app.route("/api/products")
def products():
    return jsonify({"products": [
        {"id": 1, "name": "Enterprise License", "price": 9999.00},
        {"id": 2, "name": "Pro Plan", "price": 299.00},
    ]})

@app.route("/api/checkout", methods=["POST"])
def checkout():
    """Vulnerable: trusts client-supplied price."""
    data = request.json or {}
    price = data.get("price", 0)
    qty   = data.get("quantity", 1)
    total = float(price) * int(qty)  # no server-side price validation

    return jsonify({
        "order_id": "ORD-001",
        "total": total,
        "status": "charged",
        "message": f"Charged ${total:.2f}"
    })

@app.route("/api/orders/<order_id>")
def get_order(order_id):
    """IDOR: returns any order without ownership check."""
    return jsonify({"order_id": order_id, "user_id": 1, "total": 9999.00, "items": ["Enterprise License"]})

@app.route("/api/coupon/apply", methods=["POST"])
def apply_coupon():
    """Vulnerable: no rate limiting, stackable coupons."""
    data = request.json or {}
    code = data.get("code", "")
    codes = {"SAVE10": 10, "SAVE50": 50, "ADMIN100": 100}
    discount = codes.get(code.upper(), 0)
    return jsonify({"code": code, "discount_percent": discount, "valid": discount > 0})

@app.route("/api/payment", methods=["POST"])
def payment():
    """Vulnerable: accepts zero/negative amounts."""
    data = request.json or {}
    amount = data.get("amount", 0)
    return jsonify({"charged": amount, "status": "success", "txn": "TXN-12345"})

# ── SOAP ──────────────────────────────────────────────────────────────────────
@app.route("/soap", methods=["POST"])
@app.route("/ws", methods=["POST"])
def soap():
    """Vulnerable SOAP endpoint — echoes parsed XML."""
    body = request.data.decode("utf-8", errors="replace")
    # Simulates returning file content if XXE was triggered
    if "xxe" in body.lower() or "passwd" in body.lower():
        return Response(
            """<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><GetDataResponse>root:x:0:0:root:/root:/bin/bash</GetDataResponse></soap:Body>
</soap:Envelope>""",
            content_type="text/xml"
        )
    return Response(
        """<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><GetDataResponse>ok</GetDataResponse></soap:Body>
</soap:Envelope>""",
        content_type="text/xml"
    )

# ── Admin / sensitive paths ───────────────────────────────────────────────────
@app.route("/api/v1/admin/users")
def admin_users_v1():
    return jsonify({"users": list(USERS.values())})

@app.route("/api/v1/admin/export")
def admin_export():
    return jsonify({"export": "all user data", "records": 15423})

@app.route("/backup.sql")
def backup():
    return Response("-- MySQL dump\nINSERT INTO users VALUES (1,'admin','admin');", content_type="text/plain")

@app.route("/api/v1/debug")
def debug():
    return jsonify({"env": {"SECRET_KEY": "flask-secret", "DB_URL": "postgresql://admin:prod_pass@db:5432/ai"}})

if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("  XIPE Mock Vulnerable Server")
    print("  http://localhost:8080")
    print("  Attack surfaces: JWT, SSRF, GraphQL, XXE,")
    print("  Business Logic, IDOR, Prompt Injection, RAG")
    print("=" * 50 + "\n")
    app.run(host="0.0.0.0", port=8080, debug=False)
