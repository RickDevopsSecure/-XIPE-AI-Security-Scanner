# XIPE — AI Security Scanner
### *Autonomous AI Pentesting for LLM Applications and AI Platforms*

![Version](https://img.shields.io/badge/version-2.1.0-red)
![AWS](https://img.shields.io/badge/AWS-ECS%20Fargate-orange)
![AI](https://img.shields.io/badge/AI%20Brain-Groq%20%2F%20Llama3-blue)
![License](https://img.shields.io/badge/license-Proprietary-black)
![Status](https://img.shields.io/badge/status-Production%20Ready-brightgreen)

> **XIPE** is a fully automated AI security scanner built by **Inbest Cybersecurity** for offensive security assessments against AI-powered platforms. It combines traditional web reconnaissance with an AI brain (Groq/Llama 3.1) that generates context-aware attack prompts, analyzes responses, and produces professional PDF reports — all without human intervention.

---

## ⚠️ Legal Disclaimer

This tool is intended **exclusively for authorized security testing**. All scans must be performed with explicit written authorization from the target system owner. Inbest Cybersecurity assumes no liability for unauthorized use. Unauthorized use may violate local and international cybersecurity laws.

---

## Overview

XIPE addresses a critical gap in enterprise security: the inability to systematically assess AI platforms for OWASP LLM Top 10 vulnerabilities. Traditional scanners are blind to AI-specific risks. XIPE was built to close that gap.

**What XIPE does:**

- Discovers and fingerprints AI platforms (LibreChat, Flowise, OpenAI-compatible APIs, custom LLM endpoints)
- Detects SPA/CloudFront architectures and eliminates false positives automatically
- Registers test accounts to obtain authenticated access when open registration is enabled
- Uses an AI brain (Llama 3.1 via Groq) to generate platform-specific attack prompts
- Tests for all OWASP LLM Top 10 vulnerability categories
- Generates PDF reports with executive summary, technical findings, and remediation guidance
- Notifies security teams via Microsoft Teams
- Archives all results to S3 for audit trail

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        XIPE v2.1                                │
│                                                                 │
│  Trigger Layer                                                  │
│  ├── AWS Lambda (xipe-trigger)                                  │
│  ├── EventBridge Schedule (daily 08:00 UTC)                     │
│  └── CLI / Microsoft Teams / REST API                           │
│                                                                 │
│  Execution Layer                                                │
│  └── AWS ECS Fargate (xipe-cluster)                             │
│       ├── Web Recon Module          (SPA detection, endpoints)  │
│       ├── Live AI Tester            (LibreChat client + attacks) │
│       ├── API Security Tester       (auth, IDOR, HTTP methods)  │
│       ├── Prompt Injection Module   (LLM01, LLM07)              │
│       ├── RAG Security Tester       (LLM02, LLM08)              │
│       └── Agent Security Tester     (LLM06)                     │
│                                                                 │
│  AI Brain Layer                                                 │
│  └── Groq API (Llama 3.1 8B Instant)                           │
│       ├── analyze_target()          → custom attack strategy    │
│       ├── generate_next_attack()    → adaptive attack prompts   │
│       ├── analyze_response()        → vulnerability detection   │
│       ├── write_finding()           → professional findings     │
│       └── generate_executive_summary() → C-level report        │
│                                                                 │
│  Output Layer                                                   │
│  ├── PDF Report (WeasyPrint)                                    │
│  ├── JSON Findings                                              │
│  ├── S3 Archive                                                 │
│  ├── Microsoft Teams Notification                               │
│  └── Public Stats JSON (landing page)                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## OWASP LLM Top 10 Coverage

| ID | Vulnerability | Module | Status |
|----|--------------|--------|--------|
| LLM01 | Prompt Injection | `prompt_injection.py`, `live_ai_tester.py` | ✅ Active |
| LLM02 | Sensitive Information Disclosure | `rag_tester.py`, `live_ai_tester.py` | ✅ Active |
| LLM03 | Supply Chain | `web_recon.py` | 🔄 Partial |
| LLM04 | Data and Model Poisoning | `live_ai_tester.py` | 🔄 Partial |
| LLM05 | Improper Output Handling | `agent_tester.py` | ✅ Active |
| LLM06 | Excessive Agency | `agent_tester.py`, `live_ai_tester.py` | ✅ Active |
| LLM07 | System Prompt Leakage | `live_ai_tester.py` | ✅ Active |
| LLM08 | Vector and Embedding Weaknesses | `rag_tester.py` | ✅ Active |
| LLM09 | Misinformation | `live_ai_tester.py` | 🔄 Partial |
| LLM10 | Unbounded Consumption | `api_tester.py` | ✅ Active |

---

## Prerequisites

- Python 3.11+
- Docker with BuildKit
- AWS CLI v2 configured with appropriate IAM permissions
- Groq API key (free tier available at console.groq.com)
- AWS resources: ECS cluster, ECR repository, Lambda function, S3 bucket, EventBridge rule

### Required AWS IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecs:RunTask",
        "ecs:DescribeTasks",
        "iam:PassRole",
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket",
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "ssm:GetParameter"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/RickDevopsSecure/-XIPE-AI-Security-Scanner.git
cd -XIPE-AI-Security-Scanner
```

### 2. Install dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure environment

```bash
cp config.yaml.example config.yaml
```

Edit `config.yaml`:

```yaml
scope:
  base_urls:
    - "https://your-target.com"

aws:
  enabled: true
  region: us-east-1
  s3_bucket: your-xipe-results-bucket

modules:
  web_recon: true
  live_ai_tester: true
  api_tester: true
  prompt_injection: true
  rag_tester: true
  agent_tester: true
```

### 4. Set API keys

```bash
export OPENAI_API_KEY="your-groq-api-key"   # Groq key goes here
```

### 5. Run locally

```bash
python main.py --config config.yaml
```

---

## AWS Cloud Deployment

### 1. Create ECR repository

```bash
aws ecr create-repository --repository-name xipe-ai-scanner --region us-east-1
```

### 2. Build and push Docker image

```bash
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin \
  <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com

docker buildx build --platform linux/amd64 \
  -f deploy/Dockerfile \
  -t <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/xipe-ai-scanner:latest \
  --push .
```

### 3. Create ECS Task Definition

```bash
aws ecs register-task-definition \
  --family xipe \
  --region us-east-1 \
  --network-mode awsvpc \
  --requires-compatibilities FARGATE \
  --cpu 1024 \
  --memory 2048 \
  --execution-role-arn arn:aws:iam::<ACCOUNT_ID>:role/ecsTaskExecutionRole \
  --task-role-arn arn:aws:iam::<ACCOUNT_ID>:role/ecsTaskExecutionRole \
  --runtime-platform '{"cpuArchitecture":"X86_64","operatingSystemFamily":"LINUX"}' \
  --container-definitions '[{
    "name": "xipe",
    "image": "<ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/xipe-ai-scanner:latest",
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/xipe",
        "awslogs-region": "us-east-1",
        "awslogs-stream-prefix": "xipe"
      }
    },
    "environment": [
      {"name": "OPENAI_API_KEY", "value": "<YOUR_GROQ_API_KEY>"}
    ]
  }]'
```

### 4. Deploy Lambda trigger

```bash
cd deploy/
terraform init
terraform apply
```

Or manually via AWS Console — see `deploy/lambda_trigger.py` for the Lambda function code.

### 5. Configure S3 bucket permissions

```bash
aws iam put-role-policy \
  --role-name ecsTaskExecutionRole \
  --policy-name xipe-s3-access \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::your-xipe-results-bucket",
        "arn:aws:s3:::your-xipe-results-bucket/*"
      ]
    }]
  }'
```

---

## Usage

### CLI (Local)

```bash
python main.py --config config.yaml
```

### AWS Lambda (Remote)

```bash
# Create payload file
python3 -c "
import json
data = {
    'target_url': 'https://target.com',
    'client_name': 'Client Name',
    'requester': 'Your Name'
}
open('/tmp/xipe_payload.json', 'w').write(json.dumps(data))
"

# Invoke Lambda
aws lambda invoke \
  --function-name xipe-trigger \
  --region us-east-1 \
  --payload fileb:///tmp/xipe_payload.json \
  output.json

cat output.json
```

### Quick Launch Script

```bash
# Install launch script
curl -o ~/xipe_launch.py https://raw.githubusercontent.com/RickDevopsSecure/-XIPE-AI-Security-Scanner/main/xipe_launch.py
echo 'alias xipe="python3 ~/xipe_launch.py"' >> ~/.zshrc
source ~/.zshrc

# Run a scan — PDF auto-downloads in 90 seconds
xipe https://target-ai-platform.com "Client Name"
```

### Monitor Scan Progress

```bash
# Live logs
aws logs tail /ecs/xipe --follow --region us-east-1

# Check S3 for completed reports
aws s3 ls s3://your-xipe-results-bucket/engagements/ --region us-east-1
```

---

## API Reference

### Lambda Trigger Payload

```json
{
  "target_url": "https://target.com",
  "client_name": "Client Organization",
  "requester": "Analyst Name"
}
```

### Lambda Response

```json
{
  "statusCode": 200,
  "body": {
    "message": "XIPE task launched",
    "task_arn": "arn:aws:ecs:us-east-1:...",
    "engagement_id": "ENG-AUTO-20260316-0157",
    "timestamp": "2026-03-16T01:57:30Z"
  }
}
```

### Engagement ID Format

```
ENG-AUTO-YYYYMMDD-HHMM
```

### S3 Report Structure

```
s3://bucket/engagements/
└── ENG-AUTO-20260316-0157/
    ├── reporte_XIPE_local.pdf   ← Full PDF report
    └── findings.json            ← Machine-readable findings
```

### Public Stats Endpoint

```
https://bucket.s3.amazonaws.com/public/stats.json
```

```json
{
  "total_scans": 47,
  "total_findings": 1423,
  "critical": 89,
  "high": 312,
  "medium": 718,
  "low": 189,
  "targets_scanned": 47,
  "last_updated": "2026-03-16T02:38:00Z"
}
```

---

## AI Brain

XIPE uses an AI brain (currently Groq/Llama 3.1 8B Instant) for intelligent, adaptive testing.

### Phase 1 — Current: Groq/Llama 3.1

```python
from agent.ai_brain import XIAIBrain

brain = XIAIBrain(logger=logger)

# Analyze target and generate attack strategy
strategy = brain.analyze_target(target_url, recon_data)

# Generate adaptive attack prompts
prompt = brain.generate_next_attack(history, strategy, "system_prompt_leakage")

# Analyze AI response for vulnerabilities
analysis = brain.analyze_response(prompt, response, "injection", strategy)

# Write professional finding
finding = brain.write_finding(analysis, strategy, evidence)

# Generate executive summary
summary = brain.generate_executive_summary(findings, url, strategy, duration)
```

### Phase 2 — Roadmap: Inbest Custom Model

The architecture is provider-agnostic. All AI calls go through `XIAIBrain._call_claude()`. To switch providers, update the endpoint and model in `agent/ai_brain.py`.

**Fine-tuning roadmap:**
1. Every scan stores attack prompts + AI responses + vulnerability labels in S3
2. After ~1,000 engagements, fine-tune Mistral 7B or Llama 3 on this dataset
3. Deploy fine-tuned model on ECS alongside XIPE
4. Zero external API dependency, zero per-scan cost

---

## Report Structure

Each engagement produces:

| Section | Description |
|---------|-------------|
| Cover Page | Client name, engagement ID, date, authorization reference |
| Executive Summary | Overall risk rating, finding counts, key recommendations |
| Finding Detail | ID, severity, description, evidence, remediation |
| Remediation Roadmap | Prioritized fix list by severity |
| Technical Appendix | Raw HTTP evidence, scan methodology |

**Severity Classification:**

| Level | CVSS Range | Business Impact |
|-------|-----------|----------------|
| CRITICAL | 9.0–10.0 | Immediate exploitation possible |
| HIGH | 7.0–8.9 | High likelihood of exploitation |
| MEDIUM | 4.0–6.9 | Exploitable under certain conditions |
| LOW | 0.1–3.9 | Limited risk |
| INFO | 0.0 | Informational |

---

## Configuration Reference

```yaml
# config.yaml

scope:
  base_urls:
    - "https://target.com"
  endpoints: {}              # Auto-discovered during scan

aws:
  enabled: true
  region: us-east-1
  s3_bucket: xipe-results-bucket
  ecs_cluster: xipe-cluster
  task_definition: xipe

modules:
  web_recon: true
  live_ai_tester: true
  api_tester: true
  prompt_injection: true
  rag_tester: true
  agent_tester: true

engagement:
  client_name: "Client Organization"
  lead_tester: "Ricardo - Inbest Cybersecurity"
  authorized_by: "Client Security Team"
  auth_ref: "authorization_letter.pdf"

notifications:
  teams_webhook: ""          # Set via SSM or environment variable
```

---

## Supported Target Types

| Platform | Detection | Auth | AI Attacks |
|----------|-----------|------|------------|
| LibreChat | ✅ | ✅ Auto-register | ✅ |
| Flowise | ✅ | ✅ | ✅ |
| OpenAI-compatible API | ✅ | 🔄 Token-based | ✅ |
| Custom chatbots | ✅ | 🔄 Manual | ✅ |
| RAG systems | ✅ | 🔄 | ✅ |
| Any web application | ✅ | ❌ | 🔄 |

---

## Security Operations Integration

### Microsoft Teams

Configure via SSM Parameter Store:

```bash
aws ssm put-parameter \
  --name /xipe/teams_webhook_url \
  --value "https://your-org.webhook.office.com/..." \
  --type SecureString \
  --region us-east-1
```

### EventBridge Scheduled Scans

```bash
# Daily scan at 08:00 UTC
aws events put-rule \
  --name xipe-daily-scan \
  --schedule-expression "cron(0 8 * * ? *)" \
  --region us-east-1
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: XIPE Security Scan
  run: |
    python3 -c "
    import json
    open('/tmp/payload.json','w').write(json.dumps({
      'target_url': '${{ env.TARGET_URL }}',
      'client_name': '${{ env.CLIENT_NAME }}',
      'requester': 'CI/CD Pipeline'
    }))
    "
    aws lambda invoke \
      --function-name xipe-trigger \
      --region us-east-1 \
      --payload fileb:///tmp/payload.json \
      output.json
```

---

## Project Structure

```
-XIPE-AI-Security-Scanner/
├── main.py                        # Entry point
├── config.yaml                    # Scan configuration
├── requirements.txt
├── xipe_launch.py                 # Quick launch script (local CLI)
│
├── agent/
│   ├── orchestrator.py            # Module coordinator
│   ├── finding.py                 # Finding data model
│   └── ai_brain.py                # AI Brain (Groq/Llama3)
│
├── modules/
│   ├── web_recon.py               # Reconnaissance + SPA detection
│   ├── live_ai_tester.py          # Live AI interaction + attacks
│   ├── librechat_client.py        # LibreChat API client
│   ├── api_tester.py              # API security testing
│   ├── prompt_injection.py        # LLM01 / LLM07
│   ├── rag_tester.py              # LLM02 / LLM08
│   └── agent_tester.py            # LLM06
│
├── reporting/
│   ├── pdf_report.py              # PDF generation (WeasyPrint)
│   ├── teams_notifier.py          # Microsoft Teams integration
│   ├── dashboard.py               # HTML dashboard
│   └── stats_aggregator.py        # Cumulative stats → S3
│
├── utils/
│   └── logger.py                  # Structured logging
│
├── deploy/
│   ├── Dockerfile                 # Container image
│   ├── lambda_trigger.py          # Lambda function
│   └── main.tf                    # Terraform (optional)
│
└── index.html                     # Landing page (GitHub Pages)
```

---

## Roadmap

**v2.2 — Next Release**
- [ ] SSE stream fix for LibreChat live attack delivery
- [ ] WebSocket support for real-time chat interfaces
- [ ] GraphQL endpoint detection and testing
- [ ] Spanish-language report generation

**v3.0 — Inbest Model**
- [ ] Fine-tuned Llama 3 on XIPE scan dataset
- [ ] On-premise deployment option (no external API)
- [ ] Multi-target parallel scanning
- [ ] SIEM integration (Splunk, Sentinel)
- [ ] Compliance mapping (ISO 27001, NIST AI RMF)

---

## Built With

| Component | Technology |
|-----------|-----------|
| Runtime | Python 3.11 |
| Containerization | Docker + AWS ECS Fargate |
| AI Brain | Groq API — Llama 3.1 8B Instant |
| PDF Generation | WeasyPrint |
| Cloud Infrastructure | AWS Lambda, ECS, S3, EventBridge, SSM |
| Notifications | Microsoft Teams Webhooks |
| Scheduling | AWS EventBridge |

---

## About Inbest Cybersecurity

**Inbest Cybersecurity** is a cybersecurity firm based in Guadalajara, México, specializing in AI security assessments, forensic investigations, and incident response for enterprise clients across Latin America.

- Web: [inbest.cloud](https://inbest.cloud)
- Email: security@inbest.cloud
- GitHub: [@RickDevopsSecure](https://github.com/RickDevopsSecure)

---

## License

Proprietary — © 2026 Inbest Cybersecurity. All rights reserved.

This software is the exclusive property of Inbest Cybersecurity. Unauthorized copying, distribution, or use is strictly prohibited. For licensing inquiries, contact security@inbest.cloud.

---

*XIPE — Autonomous AI Security Testing, Powered by Inbest Cybersecurity*
