FROM python:3.11-slim
LABEL maintainer="Inbest Cybersecurity <security@inbest.cloud>"
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0 \
    libgdk-pixbuf-xlib-2.0-0 libffi-dev libcairo2 fonts-liberation \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p output
RUN useradd -m -u 1000 pentest && chown -R pentest:pentest /app
USER pentest
CMD ["python", "main.py", "--config", "config.yaml"]
