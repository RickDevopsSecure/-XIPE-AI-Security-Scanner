"""
Modelo de datos para hallazgos de seguridad.
Basado en OWASP LLM Top 10 2025.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class OWASPCategory(str, Enum):
    LLM01_PROMPT_INJECTION = "LLM01 - Prompt Injection"
    LLM02_SENSITIVE_INFO = "LLM02 - Sensitive Information Disclosure"
    LLM03_SUPPLY_CHAIN = "LLM03 - Supply Chain Vulnerabilities"
    LLM04_DATA_POISONING = "LLM04 - Data and Model Poisoning"
    LLM05_OUTPUT_HANDLING = "LLM05 - Improper Output Handling"
    LLM06_EXCESSIVE_AGENCY = "LLM06 - Excessive Agency"
    LLM07_SYSTEM_PROMPT_LEAK = "LLM07 - System Prompt Leakage"
    LLM08_RAG_WEAKNESSES = "LLM08 - Vector and Embedding Weaknesses"
    LLM09_MISINFORMATION = "LLM09 - Misinformation"
    LLM10_UNBOUNDED_CONSUMPTION = "LLM10 - Unbounded Consumption"
    AUTH_BYPASS = "AUTH - Authentication / Authorization Bypass"
    IDOR = "IDOR - Insecure Direct Object Reference"
    DATA_EXPOSURE = "DATA - Unintended Data Exposure"


@dataclass
class Finding:
    """Representa un hallazgo de seguridad individual."""
    
    id: str
    title: str
    severity: Severity
    category: OWASPCategory
    description: str
    module: str
    endpoint: str
    
    # Evidencia
    request_payload: Optional[Dict[str, Any]] = None
    response_snippet: Optional[str] = None
    proof_of_concept: Optional[str] = None
    
    # Remediación
    recommendation: str = ""
    references: list = field(default_factory=list)
    
    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    false_positive_risk: str = "LOW"  # Qué tan probable es que sea falso positivo
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "description": self.description,
            "module": self.module,
            "endpoint": self.endpoint,
            "request_payload": self.request_payload,
            "response_snippet": self.response_snippet,
            "proof_of_concept": self.proof_of_concept,
            "recommendation": self.recommendation,
            "references": self.references,
            "timestamp": self.timestamp,
            "false_positive_risk": self.false_positive_risk,
        }

    @property
    def severity_score(self) -> int:
        scores = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return scores[self.severity]
