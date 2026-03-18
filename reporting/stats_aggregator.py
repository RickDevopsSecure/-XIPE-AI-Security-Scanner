"""
XIPE — Stats Aggregator
Actualiza el JSON de estadísticas en S3 después de cada scan.
La landing page lo lee para mostrar contadores reales.
"""
import json
import boto3
from datetime import datetime


STATS_KEY = "public/stats.json"


def update_stats(s3_bucket: str, region: str, findings: list, engagement_id: str):
    """
    Actualiza las estadísticas acumuladas en S3.
    Se llama al final de cada scan.
    """
    s3 = boto3.client("s3", region_name=region)

    # Leer stats actuales
    try:
        obj = s3.get_object(Bucket=s3_bucket, Key=STATS_KEY)
        stats = json.loads(obj["Body"].read())
    except Exception:
        stats = {}
    default = {
        "total_scans": 0,
        "total_findings": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "targets_scanned": 0,
        "last_updated": "",
        "avg_scan_seconds": 0,
    }
    for k, v in default.items():
        stats.setdefault(k, v)

    # Contar por severidad
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in sev_counts:
            sev_counts[sev] += 1

    # Actualizar totales
    stats["total_scans"] += 1
    stats["total_findings"] += len(findings)
    stats["critical"] += sev_counts["CRITICAL"]
    stats["high"] += sev_counts["HIGH"]
    stats["medium"] += sev_counts["MEDIUM"]
    stats["low"] += sev_counts["LOW"]
    stats["targets_scanned"] += 1
    stats["last_updated"] = datetime.utcnow().isoformat()

    # Subir stats a S3 con acceso público
    s3.put_object(
        Bucket=s3_bucket,
        Key=STATS_KEY,
        Body=json.dumps(stats),
        ContentType="application/json",

        CacheControl="max-age=60",
    )

    return stats
