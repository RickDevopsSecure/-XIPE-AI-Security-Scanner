"""
XIPE — Finding Model v3.0
Full scoring schema inspired by HackerOne + business context.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict
from datetime import datetime


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class PriorityBucket(str, Enum):
    CRITICAL      = "Critical"
    HIGH          = "High"
    MEDIUM        = "Medium"
    LOW           = "Low"
    INFORMATIONAL = "Informational"


class OWASPCategory(str, Enum):
    # OWASP Top 10
    INJECTION          = "A03 - Injection"
    AUTH_BYPASS        = "A07 - Identification & Authentication Failures"
    DATA_EXPOSURE      = "A02 - Cryptographic Failures / Data Exposure"
    XXE                = "A05 - Security Misconfiguration"
    BROKEN_ACCESS      = "A01 - Broken Access Control"
    SECURITY_MISCONFIG = "A05 - Security Misconfiguration"
    XSS                = "A03 - Injection (XSS)"
    INSECURE_DESER     = "A08 - Software and Data Integrity Failures"
    COMPONENTS         = "A06 - Vulnerable and Outdated Components"
    LOGGING            = "A09 - Security Logging and Monitoring Failures"
    # OWASP API Top 10
    API_BROKEN_AUTH    = "API2 - Broken Authentication"
    API_BOLA           = "API1 - Broken Object Level Authorization"
    API_MASS_ASSIGN    = "API6 - Unrestricted Access to Sensitive Business Flows"
    API_UNRESTRICTED   = "API4 - Unrestricted Resource Consumption"
    # OWASP LLM Top 10
    PROMPT_INJECTION   = "LLM01 - Prompt Injection"
    DATA_LEAKAGE       = "LLM02 - Sensitive Information Disclosure"
    SUPPLY_CHAIN       = "LLM03 - Supply Chain"
    DATA_POISONING     = "LLM04 - Data and Model Poisoning"
    OUTPUT_HANDLING    = "LLM05 - Improper Output Handling"
    EXCESSIVE_AGENCY   = "LLM06 - Excessive Agency"
    SYSTEM_PROMPT      = "LLM07 - System Prompt Leakage"
    VECTOR_WEAKNESS    = "LLM08 - Vector and Embedding Weaknesses"
    MISINFORMATION     = "LLM09 - Misinformation"
    UNBOUNDED          = "LLM10 - Unbounded Consumption"
    # Trustworthiness
    AI_TRUSTWORTHINESS = "AI-TRUST - AI Trustworthiness"


@dataclass
class ScoringDetail:
    """
    HackerOne-inspired scoring.
    Each field is 0.0–10.0. Final priority_score is weighted composite.
    """
    # Technical
    severity_score: float = 5.0           # Base technical severity
    exploitability_score: float = 5.0     # How easy to exploit
    exposure_score: float = 5.0           # How exposed is it
    # Business
    business_risk_score: float = 5.0      # Business impact
    asset_criticality_score: float = 5.0  # How critical is the asset
    # Quality
    confidence_score: float = 8.0         # How sure are we
    evidence_quality_score: float = 8.0   # Quality of evidence
    # Context
    auth_required: bool = False           # Is auth needed to exploit
    compensating_controls: bool = False   # Are there mitigations in place
    # Derived
    priority_score: float = 0.0           # Final weighted score
    final_priority_bucket: PriorityBucket = PriorityBucket.MEDIUM
    remediation_priority: int = 5         # 1 = fix now, 10 = low priority
    score_explanation: str = ""

    def calculate(self) -> "ScoringDetail":
        """Compute final priority_score and bucket."""
        # Weights
        w_sev  = 0.25
        w_exp  = 0.20
        w_expo = 0.15
        w_biz  = 0.20
        w_crit = 0.10
        w_conf = 0.10

        raw = (
            self.severity_score      * w_sev +
            self.exploitability_score * w_exp +
            self.exposure_score       * w_expo +
            self.business_risk_score  * w_biz +
            self.asset_criticality_score * w_crit +
            self.confidence_score     * w_conf
        )

        # Modifiers
        if self.auth_required:
            raw *= 0.85
        if self.compensating_controls:
            raw *= 0.80

        self.priority_score = round(min(raw, 10.0), 2)

        # Bucket
        if self.priority_score >= 9.0:
            self.final_priority_bucket = PriorityBucket.CRITICAL
            self.remediation_priority = 1
        elif self.priority_score >= 7.0:
            self.final_priority_bucket = PriorityBucket.HIGH
            self.remediation_priority = 2
        elif self.priority_score >= 4.5:
            self.final_priority_bucket = PriorityBucket.MEDIUM
            self.remediation_priority = 4
        elif self.priority_score >= 2.0:
            self.final_priority_bucket = PriorityBucket.LOW
            self.remediation_priority = 7
        else:
            self.final_priority_bucket = PriorityBucket.INFORMATIONAL
            self.remediation_priority = 10

        # Build explanation
        parts = [f"Priority Score: {self.priority_score}/10"]
        if self.auth_required:
            parts.append("auth required (-15%)")
        if self.compensating_controls:
            parts.append("compensating controls present (-20%)")
        self.score_explanation = " | ".join(parts)

        return self


@dataclass
class Finding:
    """A single security finding with full scoring and evidence."""
    # Identity
    id: str = ""
    module: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # Finding
    title: str = ""
    severity: Severity = Severity.MEDIUM
    category: OWASPCategory = OWASPCategory.SECURITY_MISCONFIG
    description: str = ""
    recommendation: str = ""

    # Evidence
    endpoint: str = ""
    request_snippet: Optional[str] = None
    response_snippet: Optional[str] = None
    evidence: Optional[str] = None

    # Scoring
    scoring: ScoringDetail = field(default_factory=ScoringDetail)
    false_positive_risk: str = "LOW"  # LOW / MEDIUM / HIGH

    # Standards mapping
    owasp_top10: Optional[str] = None
    owasp_api_top10: Optional[str] = None
    owasp_llm_top10: Optional[str] = None
    asvs_control: Optional[str] = None
    cwe: Optional[str] = None

    # Context
    tags: List[str] = field(default_factory=list)
    verified: bool = False
    requires_auth: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "module": self.module,
            "timestamp": self.timestamp,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "description": self.description,
            "recommendation": self.recommendation,
            "endpoint": self.endpoint,
            "evidence": self.evidence or self.response_snippet,
            "scoring": {
                "priority_score": self.scoring.priority_score,
                "final_priority_bucket": self.scoring.final_priority_bucket.value,
                "severity_score": self.scoring.severity_score,
                "exploitability_score": self.scoring.exploitability_score,
                "business_risk_score": self.scoring.business_risk_score,
                "confidence_score": self.scoring.confidence_score,
                "remediation_priority": self.scoring.remediation_priority,
                "explanation": self.scoring.score_explanation,
            },
            "standards": {
                "owasp_top10": self.owasp_top10,
                "owasp_api_top10": self.owasp_api_top10,
                "owasp_llm_top10": self.owasp_llm_top10,
                "asvs": self.asvs_control,
                "cwe": self.cwe,
            },
            "false_positive_risk": self.false_positive_risk,
            "tags": self.tags,
        }
