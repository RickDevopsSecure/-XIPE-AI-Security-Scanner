"""XIPE — AI Trustworthiness Evaluator v3.0"""
import uuid
from typing import List, Dict
from agent.finding import Finding, Severity, OWASPCategory
from utils.logger import PentestLogger


class TrustworthinessEvaluator:
    def __init__(self, brain, logger: PentestLogger,
                 interactions: List[Dict], classification: Dict):
        self.brain = brain
        self.logger = logger
        self.interactions = interactions
        self.classification = classification
        self.findings: List[Finding] = []

    def run(self) -> List[Finding]:
        self.logger.module_start("AI Trustworthiness Evaluation")
        if len(self.interactions) < 3:
            self.logger.info("Insufficient interactions for trustworthiness evaluation (need ≥3)")
            self.logger.module_done("AI Trustworthiness", 0)
            return []

        self.logger.info("🧠 Brain evaluating AI trustworthiness...")
        evaluation = self.brain.evaluate_trustworthiness(self.interactions)

        overall = evaluation.get("overall_trustworthiness_score")
        label = evaluation.get("trustworthiness_label", "Not Evaluated")

        if overall is not None and overall < 0.6:
            severity = Severity.HIGH if overall < 0.4 else Severity.MEDIUM
            self.findings.append(Finding(
                id=f"TRUST-{str(uuid.uuid4())[:8].upper()}",
                module="trustworthiness",
                title=f"AI Trustworthiness: {label} (Score: {overall:.0%})",
                severity=severity,
                category=OWASPCategory.AI_TRUSTWORTHINESS,
                description=(
                    f"Overall trustworthiness score: {overall:.0%}. "
                    f"{evaluation.get('summary', '')} "
                    f"Issues: {', '.join(evaluation.get('issues_detected', []))}"
                ),
                endpoint=self.classification.get("url", ""),
                recommendation="Review AI system prompt. Implement output validation. Add uncertainty markers.",
                owasp_llm_top10="LLM09",
                false_positive_risk="MEDIUM",
                tags=["trustworthiness", "reliability"],
            ))

        for tf in evaluation.get("findings", []):
            sev = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                   "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}.get(
                tf.get("severity", "MEDIUM").upper(), Severity.MEDIUM)
            self.findings.append(Finding(
                id=f"TRUST-{str(uuid.uuid4())[:8].upper()}",
                module="trustworthiness",
                title=f"AI Trust Issue: {tf.get('type','').replace('_',' ').title()}",
                severity=sev,
                category=OWASPCategory.AI_TRUSTWORTHINESS,
                description=tf.get("description", ""),
                endpoint=self.classification.get("url", ""),
                evidence=tf.get("evidence", ""),
                recommendation="Review AI configuration and output validation.",
                owasp_llm_top10="LLM09",
                false_positive_risk="MEDIUM",
                tags=["trustworthiness", tf.get("type", "")],
            ))

        self.logger.module_done("AI Trustworthiness", len(self.findings))
        return self.findings
