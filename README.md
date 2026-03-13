# Inbest AI Pentesting Framework

> **Herramienta de uso exclusivo para engagements de seguridad autorizados.**
> Desarrollado por [Inbest Cybersecurity](https://inbest.cloud).

---

## Arquitectura

```
┌─────────────────────────────────────────────────────────┐
│                    INBEST AI PENTEST                     │
│                                                          │
│  main.py  ──►  orchestrator.py                          │
│                      │                                   │
│         ┌────────────┼────────────┐────────────┐         │
│         ▼            ▼            ▼            ▼         │
│    api_tester   prompt_inj    rag_tester  agent_tester   │
│         │            │            │            │         │
│         └────────────┴────────────┴────────────┘         │
│                      │                                   │
│               findings: List[Finding]                    │
│                      │                                   │
│         ┌────────────┴────────────┐                      │
│         ▼                         ▼                      │
│    pdf_report.py           dashboard.py                  │
│    (PDF profesional)       (Flask + HTML)                │
│         │                         │                      │
│    output/reporte.pdf      :5001/                        │
│    output/findings.json                                  │
│                                                          │
│  (Opcional) ──► AWS S3                                   │
└─────────────────────────────────────────────────────────┘
```

## Módulos de Testing (OWASP LLM Top 10)

| Módulo | OWASP | Qué prueba |
|---|---|---|
| `api_tester` | AUTH, IDOR, LLM10 | Auth bypass, IDOR, rate limiting, headers |
| `prompt_injection` | LLM01, LLM07, LLM06 | Direct injection, system prompt leak, agency |
| `rag_tester` | LLM08, LLM02, LLM04 | Doc enumeration, cross-tenant, sensitive data |
| `agent_tester` | LLM06, LLM05, LLM01 | Tool abuse, workflow bypass, output handling |

## Instalación

```bash
# 1. Clonar / copiar el proyecto
cd inbest-ai-pentest

# 2. Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Configurar el engagement
cp config.yaml.example config.yaml
# Editar config.yaml con los datos del cliente
```

## Uso

```bash
# Ejecución básica
python main.py --config config.yaml

# Con dashboard en tiempo real
python main.py --config config.yaml --dashboard

# Con puerto personalizado
python main.py --config config.yaml --dashboard --dashboard-port 8080
```

## Despliegue en AWS ECS

```bash
# 1. Build de la imagen Docker
cd deploy
docker build -f Dockerfile -t inbest-ai-pentest ..

# 2. Crear ECR repository
aws ecr create-repository --repository-name inbest-ai-pentest --region us-east-1

# 3. Push a ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com

docker tag inbest-ai-pentest:latest <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/inbest-ai-pentest:latest
docker push <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/inbest-ai-pentest:latest

# 4. Crear cluster ECS (Fargate)
aws ecs create-cluster --cluster-name inbest-pentest-cluster

# 5. Crear S3 bucket para resultados
aws s3 mb s3://inbest-pentest-results-<ACCOUNT_ID>

# 6. Desplegar task (usar consola AWS o CLI con task definition)
# Montar config.yaml como secret en AWS Secrets Manager
# Mapear puerto 5001 para el dashboard
```

## Output del Engagement

```
output/
├── pentest.log          # Log estructurado JSON
├── findings.json        # Hallazgos en JSON (para el dashboard)
└── reporte_final.pdf    # Reporte profesional para el cliente
```

## Estructura del Proyecto

```
inbest-ai-pentest/
├── main.py                    # Entry point
├── requirements.txt
├── config.yaml.example        # Plantilla de configuración
├── agent/
│   ├── orchestrator.py        # Orquestador principal
│   └── finding.py             # Modelo de datos Finding
├── modules/
│   ├── api_tester.py          # Auth, IDOR, headers, rate limiting
│   ├── prompt_injection.py    # LLM01, LLM07, LLM06
│   ├── rag_tester.py          # LLM08, LLM02, cross-tenant
│   └── agent_tester.py        # LLM06, LLM05, tool abuse
├── reporting/
│   ├── pdf_report.py          # Reporte PDF profesional
│   └── dashboard.py           # Dashboard Flask en tiempo real
├── utils/
│   └── logger.py              # Logger estructurado con Rich
└── deploy/
    └── Dockerfile             # Para ECS / Cloud Run
```

## Checklist Pre-Engagement

- [ ] Contrato firmado con el cliente
- [ ] Documento de autorización firmado
- [ ] Alcance técnico definido (URLs, fechas, módulos)
- [ ] Credenciales de prueba proporcionadas por el cliente
- [ ] config.yaml configurado y revisado
- [ ] Coordinación con el equipo técnico del cliente (notificar inicio/fin)
- [ ] Canal de comunicación de emergencia definido

---

*Inbest Cybersecurity — Guadalajara, México*
