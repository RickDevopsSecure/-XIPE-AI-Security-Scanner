FROM python:3.11-slim

LABEL maintainer="Inbest Cybersecurity <security@inbest.cloud>"
LABEL description="XIPE AI Security Scanner"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p output
RUN useradd -m -u 1000 pentest && chown -R pentest:pentest /app
USER pentest

EXPOSE 5001

CMD ["python", "main.py", "--config", "config.yaml"]
