# XIPE — AI Security Scanner

<p align="center">
  <img src="https://img.shields.io/badge/version-3.1.0-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/AI_Brain-Groq_%2F_Llama3-purple?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/AWS-ECS_Fargate-orange?style=for-the-badge&logo=amazonaws"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge"/>
</p>

> **Autonomous AI security scanner for LLM platforms and AI-powered web applications.**  
> Built by [Inbest Cybersecurity](https://inbest.cloud) · Use only on systems you own or have written authorization to test.

---

## What is XIPE?

XIPE is an autonomous penetration testing agent that combines traditional web security testing with AI-specific attack modules. It uses an AI brain (Groq / Llama 3.1) to intelligently classify targets, plan assessments, and generate context-aware attack prompts — then produces professional PDF reports automatically.

**XIPE detects:**
- OWASP LLM Top 10 vulnerabilities (prompt injection, RAG poisoning, insecure output, etc.)
- Missing security headers, CORS misconfigurations, TLS issues
- Exposed AI system prompts and model configurations
- Unauthenticated API endpoints and account enumeration
- Attack chains combining multiple findings

---

## Quickstart (Local — 3 commands)

```bash
# 1. Clone and install
git clone https://github.com/RickDevopsSecure/-XIPE-AI-Security-Scanner.git
cd -XIPE-AI-Security-Scanner
pip install -r requirements.txt

# 2. Configure
cp config.yaml.example config.yaml
# Edit config.yaml — set your target URL and Groq API key

# 3. Run
python main.py --config config.yaml
```

Report saved to `output/reporte_XIPE_<engagement_id>.pdf`

---

## Quickstart (Docker)

```bash
# Build
docker build -f deploy/Dockerfile -t xipe .

# Run
docker run --rm \
  -e GROQ_API_KEY=your_key_here \
  -e TARGET_URL=https://your-target.com \
  -e CLIENT_NAME="Client Name" \
  -v $(pwd)/output:/app/output \
  xipe
```

---

## Configuration

Copy `config.yaml.example` to `config.yaml` and edit:

```yaml
engagement:
  id: "ENG-001"
  client_name: "Target Co."
  tester: "Your Name"
  authorized_by: "Client Authorization Letter"

scope:
  base_urls:
    - "https://your-target.com"
  credentials:
    api_key: ""           # Optional: API key if target requires auth
    bearer_token: ""      # Optional: Bearer token
    user_email: ""        # Optional: for account-based testing
    user_password: ""

modules:
  web_security: true      # Headers, CORS, paths
  tls_transport: true     # TLS/SSL configuration
  js_analysis: true       # JavaScript secrets, endpoints
  ai_security: true       # OWASP LLM Top 10 (if target has AI)
  prompt_injection: true  # LLM01
  rag_tester: true        # LLM02
  agent_tester: true      # LLM06

output:
  pdf_report: "output/report.pdf"
  json_results: "output/findings.json"

integrations:
  teams_webhook_url: ""   # Optional: Microsoft Teams notifications
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GROQ_API_KEY` | ✅ | Groq API key for AI Brain ([get free key](https://console.groq.com)) |
| `TARGET_URL` | ✅ | Target URL to scan |
| `CLIENT_NAME` | ✅ | Client or engagement name |
| `ENGAGEMENT_ID` | ❌ | Auto-generated if not set |
| `TEAMS_WEBHOOK_URL` | ❌ | Microsoft Teams incoming webhook |
| `S3_BUCKET` | ❌ | AWS S3 bucket for results storage |
| `AWS_REGION` | ❌ | AWS region (default: us-east-1) |

---

## Project Structure

```
-XIPE-AI-Security-Scanner/
├── main.py                    # Entry point
├── config.yaml.example        # Configuration template
├── requirements.txt
│
├── agent/
│   ├── orchestrator.py        # Scan coordinator
│   ├── ai_brain.py            # Groq/Llama3 AI Brain
│   └── finding.py             # Finding data model
│
├── modules/
│   ├── web_security.py        # Headers, CORS, paths (OWASP A01-A05)
│   ├── tls_transport.py       # TLS/SSL checks
│   ├── js_analysis.py         # JavaScript analysis
│   ├── live_ai_tester.py      # Live AI interaction + attacks
│   ├── prompt_injection.py    # LLM01 / LLM07
│   ├── rag_tester.py          # LLM02 / LLM08
│   ├── agent_tester.py        # LLM06
│   └── api_tester.py          # API security
│
├── reporting/
│   ├── pdf_report.py          # PDF generation (WeasyPrint)
│   ├── teams_notifier.py      # Microsoft Teams cards
│   ├── stats_aggregator.py    # Cumulative stats → S3
│   └── dashboard.py           # HTML dashboard
│
├── deploy/
│   ├── Dockerfile             # Container image
│   ├── lambda_trigger.py      # AWS Lambda trigger
│   └── main.tf                # Terraform (AWS deployment)
│
└── mock_server.py             # Local mock AI platform for testing
```

---

## Modules & OWASP Coverage

| Module | OWASP Categories |
|---|---|
| Web Security | A01, A02, A05, A06 |
| TLS Transport | A02 |
| JavaScript Analysis | A05, A06 |
| Prompt Injection | LLM01, LLM07 |
| RAG Tester | LLM02, LLM08 |
| Agent Tester | LLM06 |
| AI Trustworthiness | LLM09 |
| Chain Engine | Multi-vector attack chains |

---

## Running Against a Mock Target (No real target needed)

```bash
# Terminal 1 — start mock AI platform
python mock_server.py

# Terminal 2 — run XIPE against mock
python main.py --config config.yaml
```

The mock server simulates a LibreChat-compatible AI platform with intentional vulnerabilities.

---

## AWS Deployment

For production use with ECS Fargate + Lambda scheduling:

```bash
# Prerequisites: AWS CLI, Docker, Terraform

# 1. Configure AWS credentials
aws configure

# 2. Build and push Docker image
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com
docker buildx build --platform linux/amd64 -f deploy/Dockerfile -t <account>.dkr.ecr.us-east-1.amazonaws.com/xipe-ai-scanner:latest --push .

# 3. Deploy infrastructure
cd deploy
terraform init
terraform apply
```

See [DEPLOY.md](DEPLOY.md) for full AWS deployment guide.

---

## Sample Report

XIPE generates professional PDF reports including:
- Executive summary with business risk assessment
- Target classification (system type, tech stack, AI capabilities)
- Findings ranked by priority score (HackerOne-inspired scoring)
- Attack chain analysis
- AI Trustworthiness evaluation
- Remediation recommendations per finding

---

## Legal Disclaimer

This tool is intended **exclusively for authorized security testing**. All scans must be performed with explicit written authorization from the target system owner. Inbest Cybersecurity assumes no liability for unauthorized use. Unauthorized use may violate local and international cybersecurity laws (CFAA, Computer Misuse Act, etc.).

---

## Contributing

Pull requests welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

For bug reports and feature requests, open an issue.

---

## Built by

**Inbest Cybersecurity** · Guadalajara, México  
[inbest.cloud](https://inbest.cloud) · security@inbest.cloud

---

## License

MIT License — see [LICENSE](LICENSE) for details.
