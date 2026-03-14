# XIPE v2 — Guía de Despliegue en AWS + Teams

## Lo que vas a tener al final

```
EventBridge (diario 8am)
    → Lambda xipe-trigger
        → ECS Fargate (XIPE corre en contenedor)
            → S3 (PDF + JSON guardados)
            → Teams (card con resumen + link al PDF)
```

---

## Paso 1 — Webhook de Teams

1. Abre Teams → tu canal de Inbest Security
2. `...` → **Conectores** → **Incoming Webhook** → Configurar
3. Nombre: `XIPE Scanner`, sube el logo
4. **Crear** → Copia la URL
5. Pégala en `config.yaml` bajo `integrations.teams_webhook_url`

---

## Paso 2 — ECR + Docker

```bash
# Build de la imagen
docker build -f deploy/Dockerfile -t xipe-ai-scanner .

# Crear repositorio ECR
aws ecr create-repository --repository-name xipe-ai-scanner --region us-east-1

# Login y push
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com

docker tag xipe-ai-scanner:latest \
  <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/xipe-ai-scanner:latest

docker push \
  <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/xipe-ai-scanner:latest
```

---

## Paso 3 — Terraform

```bash
cd deploy/

# Crear terraform.tfvars
cat > terraform.tfvars << EOF
aws_region          = "us-east-1"
teams_webhook_url   = "https://inbest.webhook.office.com/webhookb2/..."
vpc_id              = "vpc-XXXXXXXXX"
subnet_id           = "subnet-XXXXXXXXX"
ecr_image_uri       = "<ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/xipe-ai-scanner:latest"
schedule_expression = "cron(0 8 * * ? *)"   # 8am UTC diario
EOF

terraform init
terraform plan
terraform apply
```

Outputs que recibirás:
```
s3_bucket       = "inbest-xipe-results-123456789"
lambda_arn      = "arn:aws:lambda:us-east-1:..."
ecs_cluster     = "xipe-cluster"
task_definition = "xipe"
```

---

## Paso 4 — Config del engagement en SSM

```bash
# Subir config.yaml a SSM (para no hardcodear credenciales)
aws ssm put-parameter \
  --name "/xipe/config/default" \
  --value "$(cat config.yaml)" \
  --type "SecureString" \
  --region us-east-1
```

---

## Paso 5 — Probar manualmente

```bash
# Invocar Lambda manualmente para probar
aws lambda invoke \
  --function-name xipe-trigger \
  --payload '{"engagement_id": "ENG-TEST-001"}' \
  --region us-east-1 \
  output.json

cat output.json
```

Deberías ver en Teams la notificación en segundos.

---

## Paso 6 — Agregar config de cliente nuevo

```bash
# Para cada nuevo engagement
aws ssm put-parameter \
  --name "/xipe/config/cliente-abc" \
  --value "$(cat config_cliente_abc.yaml)" \
  --type "SecureString"

# Invocar para ese cliente específico
aws lambda invoke \
  --function-name xipe-trigger \
  --payload '{"engagement_id": "ENG-2025-002", "config_ssm_path": "/xipe/config/cliente-abc"}' \
  output.json
```

---

## Schedule personalizado

En `terraform.tfvars` cambia `schedule_expression`:

```
"rate(1 day)"           → cada 24 horas
"rate(12 hours)"        → cada 12 horas
"cron(0 8 * * ? *)"     → 8am UTC diario
"cron(0 8 ? * MON *)"   → lunes 8am
```

---

## Archivos generados por este setup

```
s3://inbest-xipe-results-ACCOUNT/
└── engagements/
    └── ENG-2025-001/
        ├── findings.json
        └── reporte_XIPE.pdf   ← URL pre-firmada en Teams
```

---

## Estructura de archivos nuevos en el repo

```
XIPE-AI-Security-Scanner/
├── reporting/
│   └── teams_notifier.py      ← NUEVO
├── agent/
│   └── orchestrator.py        ← ACTUALIZADO (Teams + S3 + bilingüe)
├── deploy/
│   ├── lambda_trigger.py      ← NUEVO
│   ├── main.tf                ← NUEVO
│   └── terraform.tfvars       ← NUEVO (no subir a git)
└── config.yaml.example        ← ACTUALIZADO
```

---

*XIPE by Inbest Cybersecurity — Guadalajara, México*
