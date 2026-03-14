# XIPE Teams Bot — Setup Guide

## Arquitectura completa

```
Teams: "xipe scan https://target.com"
    ↓
Power Automate Flow
    ↓ HTTP POST
API Gateway (AWS)
    ↓
Lambda xipe-bot
    ↓ SSM config + ECS RunTask
ECS Fargate (XIPE)
    ↓
S3 (PDF + JSON)
    ↓
Teams card con link al reporte
```

---

## Paso 1 — API Gateway en AWS

Agrega esto a tu `main.tf` existente:

```hcl
# API Gateway para recibir llamadas de Power Automate
resource "aws_api_gateway_rest_api" "xipe_bot" {
  name = "xipe-bot-api"
}

resource "aws_api_gateway_resource" "scan" {
  rest_api_id = aws_api_gateway_rest_api.xipe_bot.id
  parent_id   = aws_api_gateway_rest_api.xipe_bot.root_resource_id
  path_part   = "scan"
}

resource "aws_api_gateway_method" "scan_post" {
  rest_api_id   = aws_api_gateway_rest_api.xipe_bot.id
  resource_id   = aws_api_gateway_resource.scan.id
  http_method   = "POST"
  authorization = "NONE"
  api_key_required = true   # Requiere API key para seguridad
}

resource "aws_api_gateway_integration" "scan_lambda" {
  rest_api_id             = aws_api_gateway_rest_api.xipe_bot.id
  resource_id             = aws_api_gateway_resource.scan.id
  http_method             = aws_api_gateway_method.scan_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.xipe_bot.invoke_arn
}

resource "aws_api_gateway_deployment" "xipe_bot" {
  rest_api_id = aws_api_gateway_rest_api.xipe_bot.id
  depends_on  = [aws_api_gateway_integration.scan_lambda]
  stage_name  = "prod"
}

resource "aws_api_gateway_api_key" "xipe_bot" {
  name = "xipe-bot-key"
}

resource "aws_lambda_function" "xipe_bot" {
  filename         = "lambda_bot.zip"
  function_name    = "xipe-bot"
  role             = aws_iam_role.xipe_lambda_role.arn
  handler          = "lambda_bot.handler"
  runtime          = "python3.11"
  timeout          = 30

  environment {
    variables = {
      ECS_CLUSTER        = aws_ecs_cluster.xipe.name
      ECS_TASK_DEF       = aws_ecs_task_definition.xipe.family
      SUBNET_ID          = var.subnet_id
      SECURITY_GROUP_ID  = aws_security_group.xipe_fargate.id
      S3_BUCKET          = aws_s3_bucket.xipe_results.bucket
      TEAMS_WEBHOOK_URL  = var.teams_webhook_url
    }
  }
}

resource "aws_lambda_permission" "api_gateway_xipe_bot" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.xipe_bot.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.xipe_bot.execution_arn}/*/*"
}

output "api_gateway_url" {
  value = "${aws_api_gateway_deployment.xipe_bot.invoke_url}/scan"
}

output "api_key_id" {
  value = aws_api_gateway_api_key.xipe_bot.id
}
```

Después de `terraform apply` obtienes:
```
api_gateway_url = "https://XXXXXXXX.execute-api.us-east-1.amazonaws.com/prod/scan"
api_key_id      = "xxxxxxxxxx"
```

Obtén el valor del API key:
```bash
aws apigateway get-api-key --api-key <api_key_id> --include-value --query 'value' --output text
```

---

## Paso 2 — Power Automate Flow

1. Ve a https://make.powerautomate.com
2. **Crear** → **Flujo automatizado**
3. Trigger: **"When a new message is added to a channel"**
   - Team: iNBest Cybersecurity
   - Canal: XIPE Scans

4. Agrega condición:
   - `contains(triggerBody()?['body/content'], 'xipe scan')`

5. Si es verdadero → **HTTP**:
   - Method: POST
   - URI: `https://XXXXXXXX.execute-api.us-east-1.amazonaws.com/prod/scan`
   - Headers:
     ```
     Content-Type: application/json
     x-api-key: TU_API_KEY_AQUI
     ```
   - Body:
     ```json
     {
       "message": "@{triggerBody()?['body/content']}",
       "user": "@{triggerBody()?['from/displayName']}",
       "channel": "XIPE Scans"
     }
     ```

6. **Guardar** el flujo

---

## Paso 3 — Probar

En Teams, canal XIPE Scans, escribe:
```
xipe scan https://ai-platform.cliente.com
```

Debes recibir en segundos:
1. ✅ Card de confirmación: "XIPE Scan Initiated"
2. ~30-60 segundos después: Card con resumen de hallazgos + link al PDF

---

## Uso desde Teams

```
xipe scan https://target.com              → scan completo
xipe scan https://api.target.com/v1       → scan de API específica
```

---

## Scheduled targets (scan automático diario)

```bash
# Agregar targets para scan diario
aws ssm put-parameter \
  --name "/xipe/scheduled_targets" \
  --type "SecureString" \
  --value '[
    {"url": "https://ai.cliente1.com", "client_name": "Cliente 1"},
    {"url": "https://api.cliente2.com", "client_name": "Cliente 2"}
  ]'
```

Cada día a las 8am UTC, XIPE escaneará todos los targets y enviará los reportes a Teams.

---

*XIPE by Inbest Cybersecurity*
