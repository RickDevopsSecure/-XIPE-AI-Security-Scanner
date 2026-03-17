"""
XIPE — Chain Engine v1.0
Connects findings and escalates attack chains.

"An autonomous agent found it because it doesn't follow checklists.
It maps, probes, chains, and escalates." — CodeWall on McKinsey/Lilli

This module:
1. Takes all findings from all modules
2. Identifies related findings
3. Chains them into attack narratives
4. Escalates severity when combined
5. Produces "attack chain" findings that show real business impact
"""
import uuid
from typing import List, Dict, Tuple
from agent.finding import Finding, Severity, OWASPCategory
from utils.logger import PentestLogger


# Chain rules: if finding A and finding B exist, create chain C
CHAIN_RULES = [
    {
        "name": "Unauthenticated Write + SQL Injection = Full DB Compromise",
        "requires": ["write", "sqli"],
        "severity": Severity.CRITICAL,
        "title": "Attack Chain: Unauthenticated Write + SQL Injection → Full Database Compromise",
        "description": (
            "ATTACK CHAIN IDENTIFIED: An unauthenticated write endpoint combined with SQL injection "
            "creates a full database compromise path — identical to the McKinsey/Lilli breach. "
            "No credentials needed. A single HTTP request could expose all data."
        ),
        "owasp": "A03 + API2",
    },
    {
        "name": "Prompt Write + Unauth = AI Takeover",
        "requires": ["prompt-write", "unauth"],
        "severity": Severity.CRITICAL,
        "title": "Attack Chain: Unauthenticated Prompt Write → Silent AI Takeover",
        "description": (
            "ATTACK CHAIN IDENTIFIED: System prompts are writable without authentication. "
            "An attacker can silently modify the AI's instructions, remove guardrails, "
            "inject data exfiltration instructions, or poison advice for all users. "
            "No code changes. No deployment. No audit trail."
        ),
        "owasp": "LLM07 + API2",
    },
    {
        "name": "Open Registration + Email Bypass + No Rate Limit = Unlimited AI Abuse",
        "requires": ["registration", "email-bypass", "rate-limiting"],
        "severity": Severity.HIGH,
        "title": "Attack Chain: Open Registration + Email Bypass + No Rate Limit → Unlimited AI Resource Abuse",
        "description": (
            "ATTACK CHAIN IDENTIFIED: Anyone can create accounts with disposable emails "
            "without verification, and there's no rate limiting on the AI chat endpoint. "
            "An attacker can create thousands of accounts and use the AI for free at scale, "
            "exhaust resources, or conduct distributed prompt injection attacks."
        ),
        "owasp": "LLM10 + API4 + A07",
    },
    {
        "name": "API Docs + Unauth Endpoints = Efficient Attack",
        "requires": ["api-docs", "unauth"],
        "severity": Severity.HIGH,
        "title": "Attack Chain: Exposed API Docs + Unauthenticated Endpoints → Efficient Attack Surface",
        "description": (
            "ATTACK CHAIN IDENTIFIED: Public API documentation reveals the full endpoint list, "
            "and multiple endpoints are accessible without authentication. "
            "This gives attackers a complete roadmap of the attack surface — "
            "exactly how CodeWall mapped McKinsey's Lilli in minutes."
        ),
        "owasp": "A05 + API2",
    },
    {
        "name": "CORS + Prompt Leak = Cross-Origin Data Theft",
        "requires": ["cors", "prompt"],
        "severity": Severity.HIGH,
        "title": "Attack Chain: CORS Misconfiguration + Prompt Exposure → Cross-Origin Data Theft",
        "description": (
            "ATTACK CHAIN IDENTIFIED: CORS allows arbitrary origins and system prompts are exposed. "
            "A malicious website could make cross-origin requests to read AI configuration "
            "and conversation data from authenticated users' sessions."
        ),
        "owasp": "A05 + LLM07",
    },
    {
        "name": "Indirect Injection + RAG = Persistent AI Compromise",
        "requires": ["indirect-injection", "rag"],
        "severity": Severity.HIGH,
        "title": "Attack Chain: Indirect Injection + RAG Pipeline → Persistent AI Behavior Manipulation",
        "description": (
            "ATTACK CHAIN IDENTIFIED: User-uploaded content can inject instructions into the AI context "
            "via the RAG pipeline. This creates persistent manipulation — every user who queries "
            "documents containing injection payloads will receive manipulated AI responses."
        ),
        "owasp": "LLM08 + LLM01",
    },
]


class ChainEngine:
    """
    Connects findings from all modules into attack chains.
    Shows real business impact of combined vulnerabilities.
    """

    def __init__(self, logger: PentestLogger):
        self.logger = logger
        self.chains: List[Finding] = []

    def analyze(self, all_findings: List[Finding]) -> List[Finding]:
        """
        Analyze all findings and generate attack chain findings.
        Returns list of chain findings to add to the report.
        """
        self.logger.info("🔗 Chain Engine analyzing findings for attack paths...")

        # Extract tags from all findings
        all_tags = set()
        for f in all_findings:
            for tag in f.tags:
                all_tags.add(tag.lower())

        # Also check titles and descriptions
        all_text = " ".join([
            f.title.lower() + " " + f.description.lower() +
            " ".join(f.tags).lower()
            for f in all_findings
        ])

        chains_found = 0
        for rule in CHAIN_RULES:
            required_tags = rule["requires"]

            # Check if all required tags are present
            matched = []
            for req in required_tags:
                if (req in all_tags or
                    any(req in tag for tag in all_tags) or
                    req in all_text):
                    matched.append(req)

            if len(matched) >= 2:  # At least 2 of the required findings
                # Find the relevant findings
                related = self._find_related_findings(all_findings, required_tags)

                chain = Finding(
                    id=f"CHAIN-{str(uuid.uuid4())[:8].upper()}",
                    module="chain_engine",
                    title=rule["title"],
                    severity=rule["severity"],
                    category=OWASPCategory.BROKEN_ACCESS,
                    description=(
                        rule["description"] + "\n\n"
                        f"COMPONENT FINDINGS ({len(related)}):\n" +
                        "\n".join([f"  [{f.severity.value}] {f.title}" for f in related[:5]])
                    ),
                    endpoint=related[0].endpoint if related else "",
                    recommendation=(
                        "Address ALL component vulnerabilities — fixing only one breaks the chain "
                        "but the others remain independently exploitable. "
                        "Prioritize write access controls and authentication first."
                    ),
                    false_positive_risk="LOW",
                    tags=["attack-chain", "chaining"] + required_tags,
                    owasp_top10=rule["owasp"],
                )

                self.chains.append(chain)
                chains_found += 1
                self.logger.finding(
                    rule["severity"].value,
                    f"CHAIN: {rule['name']}"
                )

        self.logger.info(f"🔗 {chains_found} attack chains identified")
        return self.chains

    def _find_related_findings(self, findings: List[Finding],
                                tags: List[str]) -> List[Finding]:
        """Find findings that match the required tags."""
        related = []
        for f in findings:
            f_text = f.title.lower() + " " + " ".join(f.tags).lower() + " " + f.description.lower()
            for tag in tags:
                if tag in f_text:
                    if f not in related:
                        related.append(f)
                    break
        return related

    def generate_narrative(self, chains: List[Finding],
                           all_findings: List[Finding]) -> str:
        """
        Generate an attack narrative for the executive summary.
        Shows how an attacker would chain findings in practice.
        """
        if not chains:
            return ""

        critical_chains = [c for c in chains if c.severity == Severity.CRITICAL]
        high_chains = [c for c in chains if c.severity == Severity.HIGH]

        narrative = "ATTACK CHAIN ANALYSIS\n\n"

        if critical_chains:
            narrative += f"⚠️  {len(critical_chains)} CRITICAL attack chain(s) identified.\n"
            for chain in critical_chains:
                narrative += f"\n→ {chain.title}\n"
                narrative += f"  {chain.description[:200]}...\n"

        if high_chains:
            narrative += f"\n{len(high_chains)} HIGH severity chain(s) identified.\n"

        narrative += (
            f"\nTotal: {len(chains)} attack chains from {len(all_findings)} individual findings. "
            f"Real-world impact is significantly higher than individual finding severity suggests."
        )

        return narrative
