"""XIPE — Training Data Collector v1.0"""
import json, uuid
from datetime import datetime
from typing import List, Dict
import boto3

class TrainingDataCollector:
    def __init__(self, s3_bucket: str, region: str = "us-east-1"):
        self.bucket = s3_bucket
        self.region = region
        self.s3 = boto3.client("s3", region_name=region)
        self.records: List[Dict] = []

    def record_web_recon(self, target_url, target_profile, findings):
        for f in findings:
            self.records.append({"id": str(uuid.uuid4()), "type": "web_recon", "target": target_url,
                "platform_type": target_profile.get("system_type", "unknown"),
                "tech_stack": target_profile.get("tech_stack", []),
                "finding_title": f.get("title", ""), "finding_severity": f.get("severity", ""),
                "is_vulnerability": f.get("severity", "INFO") != "INFO",
                "timestamp": datetime.utcnow().isoformat()})

    def record_ai_interaction(self, target_url, platform_type, attack_prompt,
                               ai_response, is_vulnerability, severity,
                               vulnerability_type, evidence="", attack_category=""):
        self.records.append({"id": str(uuid.uuid4()), "type": "ai_interaction",
            "target": target_url, "platform_type": platform_type,
            "attack_category": attack_category, "attack_prompt": attack_prompt,
            "ai_response": (ai_response or "")[:500], "is_vulnerability": is_vulnerability,
            "severity": severity, "vulnerability_type": vulnerability_type,
            "timestamp": datetime.utcnow().isoformat()})

    def record_engagement_summary(self, engagement_id, target_url, platform_type,
                                   total_findings, critical, high, medium,
                                   duration_seconds, tech_stack):
        self.records.append({"id": str(uuid.uuid4()), "type": "engagement_summary",
            "engagement_id": engagement_id, "target": target_url,
            "platform_type": platform_type, "total_findings": total_findings,
            "critical": critical, "high": high, "medium": medium,
            "duration_seconds": duration_seconds, "tech_stack": tech_stack,
            "timestamp": datetime.utcnow().isoformat()})

    def save_to_s3(self, engagement_id: str) -> bool:
        if not self.records:
            return True
        try:
            key = f"training-data/engagements/{engagement_id}.jsonl"
            body = "\n".join(json.dumps(r, ensure_ascii=False) for r in self.records)
            self.s3.put_object(Bucket=self.bucket, Key=key, Body=body, ContentType="application/jsonl")
            self._update_index(engagement_id)
            return True
        except Exception as e:
            print(f"Training save error: {e}")
            return False

    def _update_index(self, engagement_id):
        try:
            try:
                obj = self.s3.get_object(Bucket=self.bucket, Key="training-data/index.json")
                index = json.loads(obj["Body"].read())
            except Exception:
                index = {"total_engagements": 0, "total_records": 0, "ai_interactions": 0, "engagements": []}
            index["total_engagements"] += 1
            index["total_records"] += len(self.records)
            index["ai_interactions"] += sum(1 for r in self.records if r.get("type") == "ai_interaction")
            index["engagements"].append(engagement_id)
            index["last_updated"] = datetime.utcnow().isoformat()
            self.s3.put_object(Bucket=self.bucket, Key="training-data/index.json",
                Body=json.dumps(index, indent=2), ContentType="application/json")
        except Exception:
            pass

    def get_training_stats(self) -> Dict:
        try:
            obj = self.s3.get_object(Bucket=self.bucket, Key="training-data/index.json")
            return json.loads(obj["Body"].read())
        except Exception:
            return {"total_records": 0, "ai_interactions": 0}
