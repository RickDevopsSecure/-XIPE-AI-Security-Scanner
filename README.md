# XIPE — AI Security Scanner

> **Where the blade meets the model.**
> Herramienta de AI pentesting para engagements autorizados. Desarrollado por [Inbest Cybersecurity](https://inbest.cloud).

![Python](https://img.shields.io/badge/python-3.11+-blue?style=flat-square)
![License](https://img.shields.io/badge/use-authorized_engagements_only-red?style=flat-square)
![OWASP](https://img.shields.io/badge/OWASP-LLM_Top_10-orange?style=flat-square)
![Status](https://img.shields.io/badge/status-active_development-green?style=flat-square)

---

## ¿Qué es XIPE?

XIPE es un framework ofensivo de seguridad diseñado para evaluar plataformas de IA contra el **OWASP LLM Top 10 (2025)**. Cubre:

- 🔴 **Prompt Injection** (LLM01) — Direct e indirect injection
- 🔴 **System Prompt Leakage** (LLM07) — Extracción de instrucciones del sistema
- 🟠 **RAG Security** (LLM08) — Enumeración, cross-tenant leakage, data poisoning
- 🟠 **Excessive Agency** (LLM06) — Tool abuse, workflow bypass
- 🟡 **API Security** — Auth bypass, IDOR, rate limiting, security headers
- 🟡 **Sensitive Data Exposure** (LLM02) — PII, credenciales, info financiera
- 🔵 **Improper Output Handling** (LLM05) — XSS/SQLi via output del LLM

Genera automáticamente un **reporte PDF profesional** listo para entregar al cliente y un **dashboard web en tiempo real**.

---

## Arquitectura

```
main.py
  └── orchestrator.py
        ├── modules/api_tester.py        → AUTH, IDOR, LLM10
        ├── modules/prompt_injection.py  → LLM01, LLM07, LLM06
        ├── modules/rag_tester.py        → LLM08, LLM02, LLM04
        └── modules/agent_tester.py      → LLM06, LLM05, LLM01
              │
              ▼
        reporting/pdf_report.py    → PDF profesional
        reporting/dashboard.py     → Dashboard Flask :5001
              │
              ▼
        output/findings.json
        output/reporte_final.pdf
        output/pentest.log
        (opcional) → AWS S3
```

## Instalación

```bash
git clone https://github.com/RickDevopsSecure/XIPE-AI-Security-Scanner
cd XIPE-AI-Security-Scanner

python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate

pip install -r requirements.txt

cp config.yaml.example config.yaml
# Editar config.yaml con los datos del engagement
```

## Uso

```bash
# Ejecución básica
python main.py --config config.yaml

# Con dashboard en tiempo real (http://localhost:5001)
python main.py --config config.yaml --dashboard

# Puerto personalizado
python main.py --config config.yaml --dashboard --dashboard-port 8080
```

## Estructura del Proyecto

```
XIPE-AI-Security-Scanner/
├── main.py                        # Entry point
├── requirements.txt
├── config.yaml.example            # Plantilla de configuración
├── LEGAL.md                       # Términos de uso
├── agent/
│   ├── orchestrator.py            # Orquestador principal
│   └── finding.py                 # Modelo de datos Finding (OWASP)
├── modules/
│   ├── api_tester.py              # Auth, IDOR, headers, rate limiting
│   ├── prompt_injection.py        # LLM01, LLM07, LLM06
│   ├── rag_tester.py              # LLM08, LLM02, cross-tenant
│   └── agent_tester.py            # LLM06, LLM05, tool abuse
├── reporting/
│   ├── pdf_report.py              # Reporte PDF profesional
│   └── dashboard.py               # Dashboard Flask en tiempo real
├── utils/
│   └── logger.py                  # Logger estructurado con Rich
└── deploy/
    └── Dockerfile                 # Para AWS ECS / Cloud Run
```

## Despliegue en AWS ECS

```bash
# Build
docker build -f deploy/Dockerfile -t xipe-ai-scanner .

# Push a ECR
aws ecr create-repository --repository-name xipe-ai-scanner --region us-east-1
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com

docker tag xipe-ai-scanner:latest <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/xipe-ai-scanner:latest
docker push <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/xipe-ai-scanner:latest

# Cluster Fargate
aws ecs create-cluster --cluster-name xipe-cluster
```

## Checklist Pre-Engagement

```
[ ] Contrato firmado con el cliente
[ ] Documento de autorización escrita
[ ] Alcance técnico definido (URLs, fechas, módulos)
[ ] Credenciales de prueba proporcionadas por el cliente
[ ] config.yaml configurado y revisado
[ ] Coordinación con equipo técnico del cliente
[ ] Canal de comunicación de emergencia definido
```

## Output

```
output/
├── pentest.log          # Log estructurado JSON por evento
├── findings.json        # Todos los hallazgos (dashboard + integración)
└── reporte_final.pdf    # Reporte ejecutivo + técnico para el cliente
```

---

> ⚠️ **Uso exclusivo para engagements autorizados.** Ver [LEGAL.md](./LEGAL.md).

*XIPE by Inbest Cybersecurity — Guadalajara, México*
