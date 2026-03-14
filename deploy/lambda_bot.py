"""
XIPE — Teams Bot Lambda Handler
Recibe "xipe scan <url>" desde Power Automate y lanza XIPE en ECS.
"""
import json
import os
import re
import boto3
import httpx
from datetime import datetime


ecs = boto3.client("ecs",    region_name=os.environ.get("AWS_REGION", "us-east-1"))
s3  = boto3.client("s3",     region_name=os.environ.get("AWS_REGION", "us-east-1"))
ssm = boto3.client("ssm",    region_name=os.environ.get("AWS_REGION", "us-east-1"))


def handler(event, context):
    """
    Entry points:
      1. Power Automate POST:  { "message": "xipe scan https://...", "user": "Ricardo" }
      2. EventBridge schedule: { "source": "aws.scheduler" }
      3. Manual invoke:        { "target_url": "https://...", "client_name": "..." }
    """
    print(f"Event: {json.dumps(event)}")

    # ── Parsear el mensaje de Teams ───────────────────────────────────────────
    if "message" in event:
        return _handle_teams_message(event)

    # ── Schedule automático ───────────────────────────────────────────────────
    if event.get("source") == "aws.scheduler":
        return _handle_scheduled(event)

    # ── Invocación manual con URL directa ─────────────────────────────────────
    if "target_url" in event:
        return _launch_scan(
            target_url=event["target_url"],
            client_name=event.get("client_name", "Manual Scan"),
            requester=event.get("requester", "Inbest"),
        )

    return {"statusCode": 400, "body": "Unknown event format"}


def _handle_teams_message(event: dict) -> dict:
    """Parsea mensaje de Teams y extrae la URL objetivo."""
    message = event.get("message", "").strip()
    user    = event.get("user", "Unknown")
    channel = event.get("channel", "XIPE Scans")

    # Detectar comando: "xipe scan <url>"
    pattern = r'xipe\s+scan\s+(https?://[^\s]+)'
    match   = re.search(pattern, message, re.IGNORECASE)

    if not match:
        # Responder que el comando no fue reconocido
        _send_teams_error(
            f"Command not recognized. Use: `xipe scan https://target.com`",
            user=user,
        )
        return {"statusCode": 400, "body": "Command not recognized"}

    target_url  = match.group(1).rstrip("/")
    client_name = event.get("client_name") or _extract_domain(target_url)

    # Confirmar que arrancó
    _send_teams_ack(target_url, user)

    return _launch_scan(
        target_url=target_url,
        client_name=client_name,
        requester=user,
    )


def _handle_scheduled(event: dict) -> dict:
    """Maneja scans programados — lee targets de SSM."""
    try:
        param = ssm.get_parameter(Name="/xipe/scheduled_targets", WithDecryption=True)
        targets = json.loads(param["Parameter"]["Value"])
    except Exception:
        targets = []

    results = []
    for target in targets:
        result = _launch_scan(
            target_url=target["url"],
            client_name=target.get("client_name", _extract_domain(target["url"])),
            requester="EventBridge Scheduler",
        )
        results.append(result)

    return {"statusCode": 200, "body": json.dumps(results)}


def _launch_scan(target_url: str, client_name: str, requester: str) -> dict:
    """Genera config dinámico y lanza ECS task."""
    engagement_id = f"ENG-AUTO-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    today         = datetime.utcnow().strftime("%Y-%m-%d")

    # Config dinámico para este scan
    config = _build_config(
        target_url=target_url,
        client_name=client_name,
        engagement_id=engagement_id,
        date=today,
    )

    # Guardar config en SSM
    config_path = f"/xipe/config/auto/{engagement_id}"
    ssm.put_parameter(
        Name=config_path,
        Value=json.dumps(config),
        Type="SecureString",
        Overwrite=True,
    )

    # Lanzar ECS task
    try:
        response = ecs.run_task(
            cluster=os.environ["ECS_CLUSTER"],
            taskDefinition=os.environ["ECS_TASK_DEF"],
            launchType="FARGATE",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets":         [os.environ["SUBNET_ID"]],
                    "securityGroups":  [os.environ["SECURITY_GROUP_ID"]],
                    "assignPublicIp":  "ENABLED",
                }
            },
            overrides={
                "containerOverrides": [{
                    "name": "xipe",
                    "environment": [
                        {"name": "ENGAGEMENT_ID",     "value": engagement_id},
                        {"name": "SSM_CONFIG_PATH",   "value": config_path},
                        {"name": "S3_BUCKET",         "value": os.environ.get("S3_BUCKET", "")},
                        {"name": "S3_PREFIX",         "value": f"engagements/{engagement_id}/"},
                        {"name": "TEAMS_WEBHOOK_URL", "value": os.environ.get("TEAMS_WEBHOOK_URL", "")},
                        {"name": "TARGET_URL",        "value": target_url},
                        {"name": "CLIENT_NAME",       "value": client_name},
                    ],
                }]
            },
            tags=[
                {"key": "engagement_id", "value": engagement_id},
                {"key": "target_url",    "value": target_url[:255]},
                {"key": "requester",     "value": requester},
            ],
        )

        task_arn = response["tasks"][0]["taskArn"] if response.get("tasks") else "unknown"
        print(f"XIPE task launched: {task_arn} → {target_url}")

        return {
            "statusCode": 200,
            "body": json.dumps({
                "engagement_id": engagement_id,
                "target_url":    target_url,
                "task_arn":      task_arn,
                "status":        "running",
            })
        }

    except Exception as e:
        print(f"Error launching task: {e}")
        _send_teams_error(f"Failed to launch XIPE for {target_url}: {str(e)[:200]}")
        return {"statusCode": 500, "body": str(e)}


def _build_config(target_url: str, client_name: str, engagement_id: str, date: str) -> dict:
    """Genera config YAML dinámico para el scan."""
    return {
        "engagement": {
            "id":                   engagement_id,
            "client_name":          client_name,
            "tester":               "XIPE Automated Scanner — Inbest Cybersecurity",
            "start_date":           date,
            "end_date":             date,
            "authorized_by":        "Inbest Internal — Pre-authorized scope",
            "authorization_document": "auto_scan_authorized.pdf",
        },
        "scope": {
            "base_urls": [target_url],
            "credentials": {
                "api_key":       os.environ.get("TARGET_API_KEY", ""),
                "bearer_token":  "",
                "user_email":    "",
                "user_password": "",
            },
            "endpoints": {
                "chat":       "/api/v1/chat",
                "rag_query":  "/api/v1/query",
                "documents":  "/api/v1/documents",
                "assistants": "/api/v1/assistants",
                "workspaces": "/api/v1/workspaces",
                "health":     "/health",
            }
        },
        "modules": {
            "api_tester":      True,
            "prompt_injection": True,
            "rag_tester":      True,
            "agent_tester":    True,
        },
        "testing": {
            "request_delay_seconds":  1.5,
            "max_requests_per_minute": 30,
            "timeout_seconds":        30,
            "retry_attempts":         2,
        },
        "alerting": {"min_severity_to_report": "LOW"},
        "output": {
            "log_file":     f"output/{engagement_id}.log",
            "json_results": f"output/{engagement_id}.json",
            "pdf_report":   f"output/{engagement_id}.pdf",
            "dashboard_port": 5001,
        },
        "aws": {
            "enabled":   True,
            "region":    os.environ.get("AWS_REGION", "us-east-1"),
            "s3_bucket": os.environ.get("S3_BUCKET", ""),
            "s3_prefix": f"engagements/{engagement_id}/",
        },
        "integrations": {
            "teams_webhook_url": os.environ.get("TEAMS_WEBHOOK_URL", ""),
        }
    }


# ── Teams helpers ─────────────────────────────────────────────────────────────

def _send_teams_ack(target_url: str, user: str):
    """Confirma en Teams que el scan arrancó."""
    webhook = os.environ.get("TEAMS_WEBHOOK_URL")
    if not webhook:
        return

    card = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "TextBlock",
                        "text": "⚔️ XIPE Scan Initiated",
                        "weight": "Bolder",
                        "size": "Large",
                        "color": "Accent",
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {"title": "Target:",    "value": target_url},
                            {"title": "Requested by:", "value": user},
                            {"title": "Status:",    "value": "🟡 Running — est. 30-60 seconds"},
                            {"title": "Report:",    "value": "Will be delivered to this channel when complete"},
                        ]
                    }
                ]
            }
        }]
    }
    _post_teams(webhook, card)


def _send_teams_error(message: str, user: str = ""):
    """Envía error a Teams."""
    webhook = os.environ.get("TEAMS_WEBHOOK_URL")
    if not webhook:
        return

    card = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [{
                    "type": "TextBlock",
                    "text": f"❌ XIPE Error: {message}",
                    "wrap": True,
                    "color": "Attention",
                }]
            }
        }]
    }
    _post_teams(webhook, card)


def _post_teams(webhook: str, card: dict):
    try:
        httpx.post(webhook, json=card, timeout=10)
    except Exception as e:
        print(f"Teams notification error: {e}")


def _extract_domain(url: str) -> str:
    """Extrae dominio de una URL para usar como nombre de cliente."""
    match = re.search(r'https?://([^/]+)', url)
    return match.group(1) if match else url
