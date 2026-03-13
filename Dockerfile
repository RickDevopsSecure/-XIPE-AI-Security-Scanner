FROM python:3.11-slim

LABEL maintainer="Inbest Cybersecurity <security@inbest.cloud>"
LABEL description="Inbest AI Pentesting Framework"

WORKDIR /app

# Dependencias del sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Instalar dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código
COPY . .

# Crear directorios de output
RUN mkdir -p output

# Usuario no-root
RUN useradd -m -u 1000 pentest && chown -R pentest:pentest /app
USER pentest

# Dashboard expuesto en 5001
EXPOSE 5001

ENTRYPOINT ["python", "main.py"]
CMD ["--config", "config.yaml", "--dashboard"]
