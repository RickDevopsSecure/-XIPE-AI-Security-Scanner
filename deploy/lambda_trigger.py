"""
XIPE — AWS Lambda Trigger
Disparado por EventBridge Scheduler → lanza tarea ECS Fargate con XIPE.
También puede ser invocado manualmente desde Teams o API Gateway.

Deploy:
  - Runtime: Python 3.11
  - Handler: lambda_trigger.handler
  - Env vars: ECS_CLUSTER, ECS_TASK_DEF, SUBNET_ID, SECURITY_GROUP_ID,
              TEAMS_WEBHOOK_URL, S3_BUCKET, S3_PREFIX
"""
import json
import os
import boto3
from datetime import datetime


ecs    = boto3.client("ecs",    region_name=os.environ.get("AWS_REGION", "us-east-1"))
s3     = boto3.client("s3",     region_name=os.environ.get("AWS_REGION", "us-east-1"))
ssm    = boto3.client("ssm",    region_name=os.environ.get("AWS_REGION", "us-east-1"))


def handler(event, context):
    """
    Entry point del Lambda.
    Puede recibir:
      - EventBridge schedule: { "source": "aws.scheduler" }
      - Invocación manual:    { "engagement_id": "ENG-2025-001", "config_ssm_path": "/xipe/..." }
    """
    print(f"XIPE Lambda triggered — {datetime.utcnow().isoformat()}")
    print(f"Event: {json.dumps(event)}")

    # Obtener configuración de SSM Parameter Store
    config_path  = event.get("config_ssm_path", os.environ.get("SSM_CONFIG_PATH", "/xipe/config/default"))
    engagement_id = event.get("engagement_id", f"ENG-AUTO-{datetime.utcnow().strftime('%Y%m%d-%H%M')}")

    try:
        # Lanzar tarea ECS Fargate con XIPE
        task_arn = _launch_xipe_task(engagement_id, config_path, event.get("target_url",""), event.get("client_name",""))

        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "XIPE task launched",
                "task_arn": task_arn,
                "engagement_id": engagement_id,
                "timestamp": datetime.utcnow().isoformat(),
            })
        }

    except Exception as e:
        print(f"Error launching XIPE task: {e}")
        _notify_error(str(e), engagement_id)
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }


def _launch_xipe_task(engagement_id: str, config_ssm_path: str, target_url: str = "", client_name: str = "") -> str:
    """Lanza una tarea ECS Fargate con XIPE."""

    cluster      = os.environ["ECS_CLUSTER"]
    task_def     = os.environ["ECS_TASK_DEF"]
    subnet_id    = os.environ["SUBNET_ID"]
    sg_id        = os.environ["SECURITY_GROUP_ID"]
    s3_bucket    = os.environ.get("S3_BUCKET", "inbest-xipe-results")
    teams_webhook = os.environ.get("TEAMS_WEBHOOK_URL", "")

    response = ecs.run_task(
        cluster=cluster,
        taskDefinition=task_def,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [subnet_id],
                "securityGroups": [sg_id],
                "assignPublicIp": "ENABLED",
            }
        },
        overrides={
            "containerOverrides": [{
                "name": "xipe",
                "command": [
                    "python", "main.py",
                    "--config", "/app/config.yaml",
                ],
                "environment": [
                    {"name": "ENGAGEMENT_ID",      "value": engagement_id},
                    {"name": "SSM_CONFIG_PATH",    "value": config_ssm_path},
                    {"name": "S3_BUCKET",          "value": s3_bucket},
                    {"name": "S3_PREFIX",          "value": f"engagements/{engagement_id}/"},
                    {"name": "TEAMS_WEBHOOK_URL",  "value": teams_webhook},
                    {"name": "TARGET_URL",        "value": target_url},
                    {"name": "CLIENT_NAME",       "value": client_name},
                ],
            }]
        },
        tags=[
            {"key": "engagement_id", "value": engagement_id},
            {"key": "tool",          "value": "xipe"},
            {"key": "managed_by",    "value": "inbest"},
        ],
    )

    tasks = response.get("tasks", [])
    if not tasks:
        failures = response.get("failures", [])
        raise Exception(f"ECS task failed to start: {failures}")

    task_arn = tasks[0]["taskArn"]
    print(f"XIPE ECS task launched: {task_arn}")
    return task_arn


def _notify_error(error: str, engagement_id: str):
    """Notifica error de arranque a Teams."""
    webhook_url = os.environ.get("TEAMS_WEBHOOK_URL")
    if not webhook_url:
        return

    import urllib.request
    payload = {
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
                        "text": "⚠️ Error al arrancar XIPE",
                        "weight": "Bolder",
                        "color": "Attention",
                        "size": "Large",
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {"title": "Engagement:", "value": engagement_id},
                            {"title": "Error:", "value": error[:200]},
                            {"title": "Timestamp:", "value": datetime.utcnow().isoformat()},
                        ]
                    }
                ]
            }
        }]
    }

    req = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=10)
