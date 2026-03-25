# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is XIPE

XIPE is an autonomous AI security scanner for penetration testing of web applications and AI-powered platforms. It covers OWASP Top 10, OWASP API Top 10, and OWASP LLM Top 10. Outputs include JSON findings, HTML/PDF reports, and Microsoft Teams notifications.

## Running the Scanner

```bash
# Install dependencies
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Copy and configure engagement
cp config.yaml.example config.yaml
# Edit config.yaml with target URL, engagement details, API keys

# Run scan
python main.py --config config.yaml

# Run with real-time web dashboard (port 5001)
python main.py --config config.yaml --dashboard

# Run specific modules only
python main.py --config config.yaml --modules api,prompt_injection,rag
```

## Testing Against Mock Target

```bash
# Terminal 1: Start intentionally-vulnerable mock server (localhost:8080)
python mock_server.py

# Terminal 2: Run scanner against it
python main.py --config config.yaml
```

## Docker

```bash
docker-compose up --build   # Starts XIPE + mock target together
```

## No Automated Test Suite

There are no unit or integration tests. Validation is done by running against `mock_server.py` and inspecting `output/findings.json` and generated reports.

## Architecture: 4-Phase Assessment Flow

The orchestrator (`agent/orchestrator.py`) drives everything in four sequential phases:

**Phase 1 — Reconnaissance:** HTTP probing, tech fingerprinting (WordPress, React, Django, OpenAI/Anthropic presence), API and SPA detection, security header inspection.

**Phase 2 — Classification & Planning:** `XIPEBrain` (in `agent/brain.py`) classifies the target (`web_app | api | ai_platform | cms | spa`) and decides which modules to activate and in what order.

**Phase 3 — Parallel Module Execution:** Each module returns `List[Finding]` independently. Key modules:
- `modules/web_security.py` — headers, CORS, cookies, sensitive paths, TLS
- `modules/api_mapper.py` + `modules/api_tester.py` — endpoint discovery and auth/injection testing
- `modules/prompt_injection.py`, `modules/rag_tester.py`, `modules/agent_tester.py` — OWASP LLM Top 10 attacks
- `modules/exploit_engine.py` — active exploitation triggered by prior findings; uses deterministic rules with optional Claude Sonnet reasoning
- `modules/wordpress_scanner.py` — only activated when WordPress is detected

**Phase 4 — Scoring, Chain Analysis & Reporting:**
- `agent/chain_engine.py` links related findings into multi-step attack paths
- `XIPEBrain.score_finding()` applies HackerOne-style composite scoring (severity, exploitability, exposure, business risk, asset criticality, confidence) → `priority_score` 0–10 → bucket `CRITICAL|HIGH|MEDIUM|LOW|INFO`
- `reporting/report_generator.py` produces HTML+PDF; `reporting/teams_notifier.py` sends summary

## Key Components

| File | Role |
|---|---|
| `agent/orchestrator.py` | Entry: `PentestOrchestrator.run()` drives all 4 phases |
| `agent/brain.py` | `XIPEBrain` — classification, planning, scoring, executive summary |
| `agent/ai_brain.py` | Anthropic/Claude integration for advanced reasoning |
| `agent/finding.py` | `Finding` dataclass with `ScoringDetail`; used everywhere |
| `modules/exploit_engine.py` | Active exploitation; deterministic rules + optional Claude |
| `reporting/pdf_report.py` | ReportLab-based professional PDF with cover page |
| `utils/logger.py` | Engagement-aware colored logger |

## XIPEBrain Fallback Behavior

`XIPEBrain` uses Groq (Llama 3.1) or Anthropic (Claude) for reasoning. If no API keys are available, all methods fall back to deterministic rules so the scanner still works without AI.

## config.yaml Structure

Key sections:
- `engagement` — ID, client name, tester, authorization record
- `scope.base_urls` — list of target URLs to scan
- `scope.credentials` — optional API key / bearer token for authenticated testing
- `modules` — boolean toggles per module
- `testing` — rate limits, timeouts, retry counts
- `output` — paths for log, JSON, HTML, PDF
- `aws` — S3 bucket, region (optional, for stat aggregation)
- `integrations` — Teams/Slack webhook URLs (optional)

**`config.yaml` contains secrets and must not be committed.** It is gitignored.

## AWS Deployment

Infrastructure is defined in `deploy/main.tf` (Terraform). The production flow is:

```
EventBridge (schedule) → Lambda (xipe-trigger) → ECS Fargate (runs scanner) → S3 + Teams
```

See `DEPLOY.md` for step-by-step instructions including ECR push and Terraform apply.
