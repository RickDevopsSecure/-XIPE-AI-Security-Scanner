"""
XIPE — Orchestrator v4.0
Unified 4-phase intelligent assessment flow.

PHASE 1: Reconnaissance     → fingerprint target
PHASE 2: Assessment Plan    → Brain decides what to test
PHASE 3: Parallel Execution → run only relevant modules
PHASE 4: Report + Training  → score, report, persist

Multi-URL: iterates over all scope.base_urls, merges findings.
"""
import json
import os
import time
import concurrent.futures
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import httpx
import yaml

from agent.brain import XIPEBrain
from agent.finding import Finding, Severity, OWASPCategory
from modules.web_security import WebSecurityModule
from modules.api_mapper import APIMapper
from modules.prompt_hunter import PromptHunter
from modules.chain_engine import ChainEngine
from modules.ai_security import AISecurityModule
from modules.js_analyzer import JSAnalyzer
from modules.tls_checker import TLSChecker
from modules.session_checker import SessionChecker
from modules.prompt_injection import PromptInjectionTester
from modules.rag_tester import RAGTester
from modules.agent_tester import AgentTester
from modules.wordpress_scanner import WordPressScanner
from modules import (jwt_tester, ssrf_tester, auth_tester,
                     graphql_tester, business_logic_tester,
                     subdomain_takeover, xxe_tester)
from reporting.report_generator import ReportGenerator
from reporting.teams_notifier import TeamsNotifier
from reporting.training_data_collector import TrainingDataCollector
from reporting.stats_aggregator import update_stats
from utils.logger import PentestLogger
from utils.scope_validator import ScopeValidator


class PentestOrchestrator:

    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self._apply_env_overrides()
        self.engagement_id = self.config["engagement"]["id"]
        self.start_time = datetime.utcnow()

        self.logger = PentestLogger(
            log_file=self.config["output"]["log_file"],
            engagement_id=self.engagement_id,
        )

        self.http_client = httpx.Client(
            verify=True,
            follow_redirects=True,
            timeout=self.config["testing"].get("timeout_seconds", 20),
            headers={"User-Agent": "XIPE/4.0 (Authorized Security Assessment)"},
        )

        # Central Brain
        self.brain = XIPEBrain(logger=self.logger)

        # Output
        webhook = (
            self.config.get("integrations", {}).get("teams_webhook_url")
            or os.environ.get("TEAMS_WEBHOOK_URL", "")
        )
        self.teams = TeamsNotifier(webhook) if webhook else None

        # Training data collector
        aws = self.config.get("aws", {})
        self.training = None
        if aws.get("enabled") and aws.get("s3_bucket"):
            self.training = TrainingDataCollector(
                s3_bucket=aws["s3_bucket"],
                region=aws.get("region", "us-east-1"),
            )

        self.scope = ScopeValidator(self.config["scope"]["base_urls"])
        self.all_findings: List[Finding] = []
        self.exploit_results: List[Dict] = []
        self.classification: Dict = {}
        self.assessment_plan: Dict = {}
        self.ai_interactions: List[Dict] = []
        self._auth_session = None   # populated by auth_tester, shared with other modules
        self._auth_headers: Dict = {}

    # ── Main Flow ─────────────────────────────────────────────────────────────

    def run(self):
        self._print_banner()
        self._validate_authorization()

        base_urls = self.config["scope"]["base_urls"]
        primary_url = base_urls[0]
        self.logger.info(f"Scope: {', '.join(self.scope.allowed_hosts)}")
        if len(base_urls) > 1:
            self.logger.info(f"Multi-URL scan: {len(base_urls)} targets")

        # ── PHASE 1: RECONNAISSANCE ───────────────────────────────────────────
        self.logger.section("PHASE 1 — Reconnaissance")
        recon_data = self._run_reconnaissance(primary_url)
        self.logger.info(f"Surface detected: {recon_data.get('surface_summary', 'unknown')}")

        # Brain classifies the target
        self.logger.info("Brain classifying target...")
        self.classification = self.brain.classify_target(primary_url, recon_data)
        self._log_classification()

        # ── PHASE 2: ASSESSMENT PLAN ─────────────────────────────────────────
        self.logger.section("PHASE 2 — Assessment Plan")
        self.logger.info("Brain planning assessment...")
        self.assessment_plan = self.brain.plan_assessment(primary_url, self.classification)
        self._log_plan()

        # ── PHASE 3: EXECUTION ───────────────────────────────────────────────
        self.logger.section("PHASE 3 — Execution")

        # Run auth tester first so token is available to all modules
        self._run_auth_bootstrap(primary_url)

        # Run all modules against every target URL
        for url in base_urls:
            if url != primary_url:
                self.logger.info(f"Scanning additional target: {url}")
            self._current_target = url
            self._run_modules_parallel()

        # ── PHASE 3: WORDPRESS OFFENSIVE SCAN ──────────────────────────────────
        wp_findings = self._run_wordpress_scan()
        if wp_findings:
            self.logger.info(f"WordPress: {len(wp_findings)} findings adicionales")
            self.all_findings.extend(wp_findings)

        # ── PHASE 3.5: BRAIN-DRIVEN EXPLOITATION ────────────────────────────
        self.logger.section("PHASE 3.5 — Brain-Driven Exploitation")
        try:
            from modules.exploit_engine import ExploitEngine
            exploit_engine = ExploitEngine(
                target_url=primary_url,
                logger=self.logger,
                tech_stack=self.classification.get("tech_stack", [])
            )
            findings_dicts = [f.to_dict() for f in self.all_findings]
            self.exploit_results = exploit_engine.run_exploits(findings_dicts)
            confirmed = sum(1 for r in self.exploit_results if r.get("confirmed"))
            self.logger.info(f"Exploit phase complete: {len(self.exploit_results)} tested, {confirmed} confirmed")
        except Exception as e:
            self.logger.error(f"Exploit engine error: {e}")
            self.exploit_results = []

        # ── PHASE 4: SCORING + REPORT ────────────────────────────────────────
        self.logger.section("PHASE 4 — Scoring & Report")
        # Chain Engine — connect findings into attack paths
        chain_engine = ChainEngine(self.logger)
        chains = chain_engine.analyze(self.all_findings)
        self.all_findings.extend(chains)
        self._score_all_findings()
        self._generate_outputs()
        self._print_summary()

    # ── Phase 1: Reconnaissance ───────────────────────────────────────────────

    def _run_reconnaissance(self, url: str) -> Dict:
        """Passive/low-impact fingerprinting of the target."""
        data = {
            "url": url,
            "tech": [],
            "headers": {},
            "has_ai": False,
            "has_api": False,
            "is_spa": False,
            "is_authenticated": False,
            "status_code": None,
            "server": None,
            "title": None,
            "tls": url.startswith("https"),
            "surface_summary": "",
        }

        try:
            self._verify_connectivity(url)
            resp = self.http_client.get(url, timeout=15)
            data["status_code"] = resp.status_code
            headers = {k.lower(): v for k, v in resp.headers.items()}
            data["headers"] = headers
            data["server"] = headers.get("server", headers.get("x-powered-by", ""))

            body = resp.text.lower()

            # Title
            import re
            m = re.search(r"<title>([^<]{1,100})</title>", resp.text, re.I)
            if m:
                data["title"] = m.group(1).strip()

            # Tech fingerprinting
            fingerprints = {
                "WordPress": ["wp-content", "wp-includes"],
                "React": ["react", "_next/static", "__next"],
                "Vue.js": ["__vue__", "vue-router"],
                "Angular": ["ng-version", "_nghost"],
                "Next.js": ["__next", "_next/"],
                "Django": ["csrfmiddlewaretoken"],
                "Laravel": ["laravel_session"],
                "Cloudflare": ["cf-ray"],
                "AWS CloudFront": ["x-amz-cf-id"],
                "Nginx": ["server: nginx"],
                "Apache": ["server: apache"],
            }
            combined = body + str(headers)
            for tech, patterns in fingerprints.items():
                if any(p in combined for p in patterns):
                    data["tech"].append(tech)

            # AI detection
            ai_words = ["openai", "anthropic", "gpt", "llm", "chatbot",
                        "ai assistant", "claude", "llama", "flowise", "librechat"]
            if any(w in body for w in ai_words):
                data["has_ai"] = True

            # API detection
            for path in ["/api", "/api/v1", "/graphql", "/v1"]:
                try:
                    r = self.http_client.get(url.rstrip("/") + path, timeout=5)
                    if r.status_code in (200, 401, 403):
                        ct = r.headers.get("content-type", "")
                        if "html" not in ct:
                            data["has_api"] = True
                            break
                except Exception:
                    pass

            # SPA detection
            import uuid
            canary = f"/{uuid.uuid4().hex[:8]}"
            try:
                cr = self.http_client.get(url.rstrip("/") + canary, timeout=5)
                if cr.status_code == 200 and "html" in cr.headers.get("content-type", ""):
                    data["is_spa"] = True
            except Exception:
                pass

            # Auth indicators
            auth_words = ["login", "sign in", "dashboard", "portal", "account"]
            if any(w in body for w in auth_words):
                data["is_authenticated"] = True

            data["surface_summary"] = (
                f"{'HTTPS' if data['tls'] else 'HTTP'} | "
                f"Status {data['status_code']} | "
                f"Tech: {', '.join(data['tech'][:3]) or 'unknown'} | "
                f"{'AI ' if data['has_ai'] else ''}"
                f"{'API ' if data['has_api'] else ''}"
                f"{'SPA' if data['is_spa'] else ''}"
            )

        except Exception as e:
            self.logger.error(f"Recon error: {e}")
            data["surface_summary"] = f"Error during recon: {e}"

        return data

    # ── Phase 3: Auth Bootstrap ───────────────────────────────────────────────

    def _run_auth_bootstrap(self, url: str):
        """
        Run auth_tester first so its session token is available to every other module.
        Also captures auth-related findings.
        """
        mods = self.config.get("modules", {})
        if not mods.get("auth_tester", True):
            return
        try:
            self.logger.info("Auth bootstrap — establishing session and testing auth controls...")
            tester = auth_tester.AuthTester(url, self.config)
            findings = tester.run()
            self.all_findings.extend(findings)
            # Propagate session headers to http_client and all subsequent modules
            self._auth_headers = tester.get_session_headers()
            if self._auth_headers:
                for k, v in self._auth_headers.items():
                    self.http_client.headers[k] = v
                self.logger.info(f"Auth session established — propagating to all modules")
            self.logger.info(f"Auth tester: {len(findings)} findings")
        except Exception as e:
            self.logger.error(f"Auth bootstrap error: {e}")

    # ── Phase 3: Module Execution ─────────────────────────────────────────────

    def _run_wordpress_scan(self) -> list:
        """Escaneo ofensivo específico para WordPress."""
        try:
            tech = self.classification.get("tech_stack", [])
            if isinstance(tech, list):
                is_wp = any("wordpress" in t.lower() for t in tech)
            else:
                is_wp = "wordpress" in str(tech).lower()
            if not is_wp:
                return []
            self.logger.info("🔴 WordPress detectado — activando scanner ofensivo...")
            scanner = WordPressScanner(
                target_url=self.config["scope"]["base_urls"][0],
                logger=self.logger
            )
            findings = scanner.scan()
            self.logger.info(f"✓ WordPress Scanner: {len(findings)} findings")
            return findings
        except Exception as e:
            self.logger.error(f"WordPress scanner error: {e}")
            return []

    def _run_modules_parallel(self):
        """Run relevant modules in parallel with concurrency control."""
        plan = self.assessment_plan.get("modules_to_run", {})
        mods_cfg = self.config.get("modules", {})
        max_workers = self.config["testing"].get("max_concurrent_modules", 5)

        tasks = []

        # config modules section is authoritative:
        #   false  → never run (even if brain wants it)
        #   true   → always run (even if brain didn't plan it)
        #   absent → follow brain plan (with default fallback)
        def _enabled(key: str, default: bool = True) -> bool:
            cfg_val = mods_cfg.get(key)
            if cfg_val is False:
                return False
            if cfg_val is True:
                return True
            return plan.get(key, default)

        if _enabled("web_security"):
            tasks.append(("Web Security", self._run_web_security))
        if _enabled("tls_transport"):
            tasks.append(("TLS / Transport", self._run_tls))
        if _enabled("js_analysis") and (self.classification.get("is_spa") or mods_cfg.get("js_analysis") is True):
            tasks.append(("JavaScript Analysis", self._run_js_analysis))
        if _enabled("session_security", False) and self.classification.get("is_authenticated"):
            tasks.append(("Session Security", self._run_session))
        if _enabled("api_security", False) and self.classification.get("has_api"):
            tasks.append(("API Security", self._run_api_security))
        if _enabled("ai_security", False) and (self.classification.get("has_ai") or mods_cfg.get("ai_security") is True):
            tasks.append(("AI Security", self._run_ai_security))
        if _enabled("api_mapper"):
            tasks.append(("API Mapper", self._run_api_mapper))
        if _enabled("prompt_hunter") and (self.classification.get("has_ai") or self.classification.get("has_api") or mods_cfg.get("prompt_hunter") is True):
            tasks.append(("Prompt Hunter", self._run_prompt_hunter))
        if _enabled("prompt_injection", False) and (self.classification.get("has_ai") or mods_cfg.get("prompt_injection") is True):
            tasks.append(("Prompt Injection", self._run_prompt_injection))
        if _enabled("rag_tester", False) and (self.classification.get("has_ai") or mods_cfg.get("rag_tester") is True):
            tasks.append(("RAG Tester", self._run_rag_tester))
        if _enabled("agent_tester", False) and (self.classification.get("has_ai") or mods_cfg.get("agent_tester") is True):
            tasks.append(("Agent Tester", self._run_agent_tester))
        if mods_cfg.get("jwt_tester", True):
            tasks.append(("JWT/OAuth Tester", self._run_jwt_tester))
        if mods_cfg.get("ssrf_tester", True):
            tasks.append(("SSRF Tester", self._run_ssrf_tester))
        if mods_cfg.get("graphql_tester", True):
            tasks.append(("GraphQL Tester", self._run_graphql_tester))
        if mods_cfg.get("business_logic_tester", True):
            tasks.append(("Business Logic", self._run_business_logic))
        if mods_cfg.get("subdomain_takeover", True):
            tasks.append(("Subdomain Takeover", self._run_subdomain_takeover))
        if mods_cfg.get("xxe_tester", True):
            tasks.append(("XXE / XML Injection", self._run_xxe_tester))

        self.logger.info(f"Running {len(tasks)} modules (max {max_workers} parallel)")

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(fn): name
                for name, fn in tasks
            }
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    findings = future.result(timeout=120)
                    self.all_findings.extend(findings or [])
                    self.logger.info(f"✓ {name}: {len(findings or [])} findings")
                except Exception as e:
                    self.logger.error(f"Module '{name}' failed: {e}")

        # Trustworthiness runs after AI security (needs interactions)
        if plan.get("trustworthiness") and self.ai_interactions:
            self.logger.info("Running AI Trustworthiness evaluation...")
            tw_findings = self._run_trustworthiness()
            self.all_findings.extend(tw_findings or [])

    def _run_web_security(self) -> List[Finding]:
        mod = WebSecurityModule(
            config=self.config,
            logger=self.logger,
            http_client=self.http_client,
            brain=self.brain,
            classification=self.classification,
            assessment_plan=self.assessment_plan,
        )
        return mod.run()

    def _run_tls(self) -> List[Finding]:
        mod = TLSChecker(
            config=self.config,
            logger=self.logger,
            http_client=self.http_client,
        )
        return mod.run()

    def _run_js_analysis(self) -> List[Finding]:
        mod = JSAnalyzer(
            config=self.config,
            logger=self.logger,
            http_client=self.http_client,
        )
        return mod.run()

    def _run_session(self) -> List[Finding]:
        mod = SessionChecker(
            config=self.config,
            logger=self.logger,
            http_client=self.http_client,
        )
        return mod.run()

    def _run_api_security(self) -> List[Finding]:
        mod = WebSecurityModule(
            config=self.config,
            logger=self.logger,
            http_client=self.http_client,
            brain=self.brain,
            classification=self.classification,
            assessment_plan=self.assessment_plan,
        )
        return mod.run_api_checks()

    def _run_ai_security(self) -> List[Finding]:
        mod = AISecurityModule(
            config=self.config,
            logger=self.logger,
            http_client=self.http_client,
            brain=self.brain,
            classification=self.classification,
        )
        findings = mod.run()
        self.ai_interactions = mod.interactions
        return findings

    def _run_api_mapper(self) -> list:
        mod = APIMapper(self.config, self.logger, self.http_client,
                       self.brain, self.classification)
        findings = mod.run()
        self._api_mapper = mod
        return findings

    def _run_prompt_hunter(self) -> list:
        auth_token = self._auth_headers.get("Authorization", "").replace("Bearer ", "") or None
        mod = PromptHunter(self.config, self.logger, self.http_client,
                          self.brain, self.classification, auth_token)
        return mod.run()

    def _run_prompt_injection(self) -> list:
        mod = PromptInjectionTester(self.config, self.logger, self.http_client)
        return mod.run()

    def _run_rag_tester(self) -> list:
        mod = RAGTester(self.config, self.logger, self.http_client)
        return mod.run()

    def _run_agent_tester(self) -> list:
        mod = AgentTester(self.config, self.logger, self.http_client)
        return mod.run()

    def _run_jwt_tester(self) -> list:
        target = getattr(self, "_current_target", self.config["scope"]["base_urls"][0])
        return jwt_tester.run(target, self.config)

    def _run_ssrf_tester(self) -> list:
        target = getattr(self, "_current_target", self.config["scope"]["base_urls"][0])
        return ssrf_tester.run(target, self.config)

    def _run_graphql_tester(self) -> list:
        target = getattr(self, "_current_target", self.config["scope"]["base_urls"][0])
        return graphql_tester.run(target, self.config)

    def _run_business_logic(self) -> list:
        target = getattr(self, "_current_target", self.config["scope"]["base_urls"][0])
        return business_logic_tester.run(target, self.config)

    def _run_subdomain_takeover(self) -> list:
        target = getattr(self, "_current_target", self.config["scope"]["base_urls"][0])
        return subdomain_takeover.run(target, self.config)

    def _run_xxe_tester(self) -> list:
        target = getattr(self, "_current_target", self.config["scope"]["base_urls"][0])
        return xxe_tester.run(target, self.config)

    def _run_trustworthiness(self) -> List[Finding]:
        from modules.trustworthiness import TrustworthinessEvaluator
        mod = TrustworthinessEvaluator(
            brain=self.brain,
            logger=self.logger,
            interactions=self.ai_interactions,
            classification=self.classification,
        )
        return mod.run()

    # ── Phase 4: Scoring + Output ─────────────────────────────────────────────

    def _score_all_findings(self):
        """Apply HackerOne-inspired scoring to every finding."""
        for finding in self.all_findings:
            finding.scoring = self.brain.score_finding(finding, self.classification)

        # Sort by priority score descending
        self.all_findings.sort(key=lambda f: f.scoring.priority_score, reverse=True)

    def _generate_outputs(self):
        deduplicated = self._deduplicate()
        duration = int((datetime.utcnow() - self.start_time).total_seconds())

        # Trustworthiness section
        trustworthiness = None
        if self.ai_interactions:
            trustworthiness = self.brain.evaluate_trustworthiness(self.ai_interactions)

        # Executive summary
        exec_summary = self.brain.generate_executive_summary(
            findings=deduplicated,
            classification=self.classification,
            url=self.config["scope"]["base_urls"][0],
            duration_seconds=duration,
        )

        assessment_result = {
            "engagement": self.config["engagement"],
            "target": self.config["scope"]["base_urls"][0],
            "classification": self.classification,
            "assessment_plan": self.assessment_plan,
            "executive_summary": exec_summary,
            "execution": {
                "start_time": self.start_time.isoformat(),
                "end_time": datetime.utcnow().isoformat(),
                "duration_seconds": duration,
                "total_findings": len(deduplicated),
                "by_severity": self._count_by_severity(deduplicated),
                "by_module": self._count_by_module(deduplicated),
            },
            "findings": [f.to_dict() for f in deduplicated],
            "trustworthiness": trustworthiness,
            "exploit_results": self.exploit_results,
        }

        output_dir = Path(self.config["output"]["json_results"]).parent
        output_dir.mkdir(parents=True, exist_ok=True)

        # JSON report
        json_path = self.config["output"]["json_results"]
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(assessment_result, f, indent=2, ensure_ascii=False)
        self.logger.success(f"JSON exported: {json_path}")

        # HTML + PDF report
        generator = ReportGenerator(
            assessment=assessment_result,
            output_dir=str(output_dir),
        )
        html_path = generator.generate_html()
        self.logger.success(f"HTML report: {html_path}")

        pdf_path = generator.generate_pdf()
        if pdf_path:
            self.logger.success(f"PDF report: {pdf_path}")

        # S3 upload
        pdf_s3_url = None
        if self.config.get("aws", {}).get("enabled"):
            pdf_s3_url = self._upload_to_s3(json_path, pdf_path or html_path)

        # Teams notification
        if self.teams:
            self.logger.info("Sending Teams notification...")
            self.teams.notify_engagement_complete(
                engagement=self.config["engagement"],
                findings=deduplicated,
                pdf_s3_url=pdf_s3_url,
                duration_seconds=duration,
            )
            self.logger.success("Teams notification sent ✓")

        # Push results to XIPE platform dashboard
        platform_url = self.config.get("integrations", {}).get("platform_api_url", "")
        platform_token = self.config.get("integrations", {}).get("platform_api_token", "") or \
                         os.environ.get("XIPE_PLATFORM_TOKEN", "")
        if platform_url and platform_token:
            try:
                import base64
                import requests as _req
                ingest_payload = dict(assessment_result)
                if pdf_path:
                    try:
                        with open(pdf_path, "rb") as _pf:
                            ingest_payload["pdf_b64"] = base64.b64encode(_pf.read()).decode("ascii")
                    except Exception:
                        pass
                resp = _req.post(
                    platform_url.rstrip("/") + "/api/scans/ingest",
                    json=ingest_payload,
                    headers={"Authorization": f"Bearer {platform_token}"},
                    timeout=30,
                )
                if resp.status_code == 200:
                    self.logger.success(f"Results pushed to platform dashboard ✓")
                else:
                    self.logger.warning(f"Platform push returned {resp.status_code}: {resp.text[:200]}")
            except Exception as e:
                self.logger.warning(f"Could not push to platform: {e}")

        # Update public stats for landing page
        if self.config.get("aws", {}).get("enabled") and self.config.get("aws", {}).get("s3_bucket"):
            try:
                update_stats(
                    s3_bucket=self.config["aws"]["s3_bucket"],
                    region=self.config["aws"].get("region", "us-east-1"),
                    findings=[f.to_dict() for f in deduplicated],
                    engagement_id=self.engagement_id,
                )
                self.logger.success("Stats updated in S3")
            except Exception as e:
                self.logger.error(f"Stats update error: {e}")

        # Training data
        if self.training:
            self.training.record_web_recon(
                target_url=self.config["scope"]["base_urls"][0],
                target_profile=self.classification,
                findings=[f.to_dict() for f in deduplicated],
            )
            for interaction in self.ai_interactions:
                self.training.record_ai_interaction(
                    target_url=self.config["scope"]["base_urls"][0],
                    platform_type=self.classification.get("system_type", "unknown"),
                    **interaction,
                )
            self.training.record_engagement_summary(
                engagement_id=self.engagement_id,
                target_url=self.config["scope"]["base_urls"][0],
                platform_type=self.classification.get("system_type", "unknown"),
                total_findings=len(deduplicated),
                critical=self._count_by_severity(deduplicated).get("CRITICAL", 0),
                high=self._count_by_severity(deduplicated).get("HIGH", 0),
                medium=self._count_by_severity(deduplicated).get("MEDIUM", 0),
                duration_seconds=duration,
                tech_stack=self.classification.get("tech_stack", []),
            )
            if self.training.save_to_s3(self.engagement_id):
                stats = self.training.get_training_stats()
                self.logger.info(
                    f"🧠 Training data: {stats.get('total_records', 0)} records | "
                    f"{stats.get('ai_interactions', 0)} AI interactions stored"
                )

    def _upload_to_s3(self, json_path: str, report_path: str) -> Optional[str]:
        try:
            import boto3
            aws = self.config["aws"]
            s3 = boto3.client("s3", region_name=aws["region"])
            prefix = f"engagements/{self.engagement_id}/"
            bucket = aws["s3_bucket"]

            s3.upload_file(json_path, bucket, prefix + Path(json_path).name)
            report_key = prefix + Path(report_path).name
            s3.upload_file(report_path, bucket, report_key)

            url = s3.generate_presigned_url(
                "get_object",
                Params={"Bucket": bucket, "Key": report_key},
                ExpiresIn=604800,
            )
            self.logger.success(f"Uploaded to S3: s3://{bucket}/{report_key}")
            return url
        except Exception as e:
            self.logger.error(f"S3 upload error: {e}")
            return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _log_classification(self):
        c = self.classification
        self.logger.info(f"  System type : {c.get('system_type', 'unknown')} (confidence: {c.get('confidence', 0):.0%})")
        self.logger.info(f"  Tech stack  : {', '.join(c.get('tech_stack', []))}")
        self.logger.info(f"  Has AI      : {c.get('has_ai', False)}")
        self.logger.info(f"  Has API     : {c.get('has_api', False)}")
        self.logger.info(f"  Surface     : {c.get('surface_overview', '')}")

    def _log_plan(self):
        modules = self.assessment_plan.get("modules_to_run", {})
        active = [k for k, v in modules.items() if v]
        self.logger.info(f"  Active modules: {', '.join(active)}")
        self.logger.info(f"  Priority checks: {', '.join(self.assessment_plan.get('priority_checks', [])[:3])}")
        reasons = self.assessment_plan.get("module_reasons", {})
        for mod, reason in list(reasons.items())[:3]:
            self.logger.info(f"  [{mod}] {reason}")

    def _verify_connectivity(self, url: str):
        self.logger.info("Verifying connectivity...")
        try:
            resp = self.http_client.get(url, timeout=10)
            self.logger.success(f"Connectivity OK — {url} → HTTP {resp.status_code}")
        except Exception as e:
            self.logger.warning(f"Connectivity check failed: {e}. Continuing...")

    def _validate_authorization(self):
        required = ["id", "client_name", "authorized_by", "authorization_document"]
        eng = self.config["engagement"]
        missing = [f for f in required if not eng.get(f)]
        if missing:
            raise ValueError(f"Missing authorization fields: {missing}")
        today = datetime.utcnow().date()
        start = datetime.strptime(eng["start_date"], "%Y-%m-%d").date()
        end = datetime.strptime(eng["end_date"], "%Y-%m-%d").date()
        if not (start <= today <= end):
            raise ValueError(f"Engagement outside authorized date range: {start} — {end}")
        self.logger.success("Authorization validated.")

    def _deduplicate(self) -> List[Finding]:
        """
        Semantic deduplication: merge findings with the same title + endpoint
        regardless of which module found them. Keeps the one with highest priority_score.
        """
        import re as _re

        def _normalize(text: str) -> str:
            text = text.lower().strip()
            text = _re.sub(r'\s+', ' ', text)
            # Strip trailing path segments and IDs so variants collapse
            text = _re.sub(r'[\s\-_:]+[a-f0-9\-]{8,}', '', text)
            return text

        groups: Dict[str, Finding] = {}
        for f in self.all_findings:
            key = f"{_normalize(f.title)}|{_normalize(f.endpoint or '')}"
            existing = groups.get(key)
            if existing is None:
                groups[key] = f
            elif f.scoring.priority_score > existing.scoring.priority_score:
                groups[key] = f

        return list(groups.values())

    def _count_by_severity(self, findings: List[Finding]) -> Dict:
        counts = {s.value: 0 for s in Severity}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def _count_by_module(self, findings: List[Finding]) -> Dict:
        counts: Dict = {}
        for f in findings:
            counts[f.module] = counts.get(f.module, 0) + 1
        return counts

    def _print_banner(self):
        eng = self.config["engagement"]
        company = eng.get("company", eng.get("tester", "XIPE Security"))
        self.logger.section(f"XIPE — AI Security Scanner v4.0 | {company}")
        self.logger.info(f"Engagement ID : {eng['id']}")
        self.logger.info(f"Client        : {eng['client_name']}")
        self.logger.info(f"Tester        : {eng['tester']}")
        self.logger.info(f"Authorized by : {eng['authorized_by']}")
        urls = self.config["scope"]["base_urls"]
        self.logger.info(f"Targets       : {', '.join(urls)}")
        self.logger.section("")

    def _print_summary(self):
        self.logger.section("ENGAGEMENT SUMMARY")
        deduped = self._deduplicate()
        by_sev = self._count_by_severity(deduped)
        self.logger.info(f"Target       : {self.config['scope']['base_urls'][0]}")
        self.logger.info(f"System type  : {self.classification.get('system_type', 'unknown')}")
        self.logger.info(f"Total findings: {len(deduped)}")
        for sev, count in by_sev.items():
            if count > 0:
                self.logger.info(f"  {sev}: {count}")
        duration = int((datetime.utcnow() - self.start_time).total_seconds())
        self.logger.info(f"Duration      : {duration // 60}m {duration % 60}s")
        self.logger.success("Assessment complete. Report ready.")

    @staticmethod
    def _load_config(path: str) -> dict:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def _apply_env_overrides(self):
        if os.environ.get("ENGAGEMENT_ID"):
            self.config["engagement"]["id"] = os.environ["ENGAGEMENT_ID"]
        if os.environ.get("TARGET_URL"):
            self.config["scope"]["base_urls"] = [os.environ["TARGET_URL"]]
        if os.environ.get("CLIENT_NAME"):
            self.config["engagement"]["client_name"] = os.environ["CLIENT_NAME"]
        if os.environ.get("TESTER_COMPANY"):
            self.config["engagement"]["company"] = os.environ["TESTER_COMPANY"]
        if os.environ.get("S3_BUCKET"):
            self.config.setdefault("aws", {})["enabled"] = True
            self.config["aws"]["s3_bucket"] = os.environ["S3_BUCKET"]
        creds = self.config.setdefault("scope", {}).setdefault("credentials", {})
        if os.environ.get("SCAN_USERNAME"):
            creds["username"] = os.environ["SCAN_USERNAME"]
            creds["user_email"] = os.environ.get("SCAN_EMAIL", os.environ["SCAN_USERNAME"])
        if os.environ.get("SCAN_PASSWORD"):
            creds["password"] = os.environ["SCAN_PASSWORD"]
            creds["user_password"] = os.environ["SCAN_PASSWORD"]

    def __del__(self):
        if hasattr(self, "http_client"):
            self.http_client.close()
        if hasattr(self, "brain"):
            self.brain.close()
