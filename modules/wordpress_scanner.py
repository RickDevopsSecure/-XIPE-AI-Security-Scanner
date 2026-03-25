"""XIPE WordPress Offensive Scanner"""
import requests
import re
from typing import List, Dict
from agent.finding import Finding, Severity

WP_SENSITIVE_PATHS = [
    "/wp-config.php", "/wp-config.php.bak", "/.env",
    "/debug.log", "/wp-content/debug.log", "/xmlrpc.php",
    "/wp-json/wp/v2/users", "/.htaccess", "/backup.sql",
    "/readme.html", "/license.txt", "/wp-cron.php",
]

WP_REST_ENDPOINTS = [
    "/wp-json/wp/v2/posts",
    "/wp-json/wp/v2/pages",
    "/wp-json/wp/v2/comments",
    "/wp-json/wp/v2/media",
]

class WordPressScanner:
    def __init__(self, target_url: str, logger=None):
        self.target = target_url.rstrip("/")
        self.logger = logger
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (compatible; SecurityScanner/3.1)"
        self.findings: List[Finding] = []

    def scan(self) -> List[Finding]:
        self._check_sensitive_files()
        self._enumerate_users()
        self._check_rest_api()
        self._check_xmlrpc()
        self._check_wp_version()
        self._check_login_page()
        return self.findings

    def _extract_credentials(self, text: str) -> Dict:
        creds = {}
        for key in ["DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST"]:
            m = re.search(r"define\s*\(\s*['\"]" + key + r"['\"]\s*,\s*['\"]([^'\"]+)['\"]", text)
            if m:
                val = m.group(1)
                creds[key] = ("******" + val[-2:]) if "PASSWORD" in key else val
        return creds

    def _check_sensitive_files(self):
        for path in WP_SENSITIVE_PATHS:
            url = self.target + path
            try:
                resp = self.session.get(url, timeout=8, allow_redirects=False)
                if resp.status_code == 200 and len(resp.text) > 30:
                    preview = resp.text[:3000]
                    sev = Severity.MEDIUM
                    title = "Sensitive File Exposed: " + path
                    ev = "File accessible at " + url + "\n"
                    if "wp-config" in path or ".env" in path:
                        creds = self._extract_credentials(preview)
                        if creds:
                            sev = Severity.CRITICAL
                            title = "Database Credentials Exposed: " + path
                            ev += "\nCREDENTIALS FOUND:\n"
                            for k, v in creds.items():
                                ev += "  " + k + ": " + v + "\n"
                        else:
                            sev = Severity.HIGH
                        ev += "\nFile preview:\n" + preview[:400]
                    elif ".sql" in path:
                        sev = Severity.CRITICAL
                        ev += "\nDB backup exposed:\n" + preview[:300]
                    self.findings.append(Finding(
                        module="wordpress_scanner", title=title, severity=sev,
                        description="The file " + path + " is publicly accessible.",
                        endpoint=url,
                        recommendation="Block via .htaccess. Move outside web root.",
                        evidence=ev, tags=["sensitive-files","wordpress"], owasp_top10="A05",
                    ))
                    if self.logger:
                        self.logger.warning("  SENSITIVE FILE: " + url)
            except Exception:
                pass

    def _enumerate_users(self):
        url = self.target + "/wp-json/wp/v2/users"
        try:
            resp = self.session.get(url, timeout=8)
            if resp.status_code == 200:
                users = resp.json()
                if isinstance(users, list) and users:
                    ulist = [str(u.get("slug","?")) + " (ID:" + str(u.get("id","?")) + ")" for u in users[:10]]
                    self.findings.append(Finding(
                        module="wordpress_scanner",
                        title="WordPress User Enumeration via REST API",
                        severity=Severity.MEDIUM,
                        description="REST API exposes " + str(len(users)) + " users: " + ", ".join(ulist),
                        endpoint=url,
                        recommendation="Disable: add_filter('rest_endpoints', function($e){ unset($e['/wp/v2/users']); return $e; });",
                        evidence="Users:\n" + "\n".join(ulist),
                        tags=["wordpress","user-enumeration"], owasp_top10="A01",
                    ))
        except Exception:
            pass

    def _check_rest_api(self):
        """Audita endpoints REST API más allá de /users buscando info disclosure."""
        exposed = []
        for path in WP_REST_ENDPOINTS:
            url = self.target + path
            try:
                resp = self.session.get(url, timeout=8)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception:
                        continue
                    count = len(data) if isinstance(data, list) else 1
                    exposed.append(f"{path} → {count} items")
            except Exception:
                pass

        if exposed:
            self.findings.append(Finding(
                module="wordpress_scanner",
                title="WordPress REST API — Unauthenticated Data Exposure",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(exposed)} REST API endpoint(s) return data without authentication, "
                    "potentially exposing post content, media URLs, comment authors, and internal metadata."
                ),
                endpoint=self.target + "/wp-json/wp/v2/",
                recommendation=(
                    "Restrict REST API to authenticated users: "
                    "add_filter('rest_authentication_errors', function($r){ "
                    "return is_user_logged_in() ? $r : new WP_Error('rest_forbidden','',['status'=>401]); });"
                ),
                evidence="Exposed endpoints:\n" + "\n".join(exposed),
                tags=["wordpress", "rest-api", "information-disclosure"],
                owasp_top10="A01",
            ))
            if self.logger:
                self.logger.warning(f"  REST API exposed: {', '.join(exposed)}")

    def _check_login_page(self):
        """Detecta username enumeration vía diferencias en mensajes de error del login."""
        url = self.target + "/wp-login.php"
        try:
            resp = self.session.get(url, timeout=8)
            if resp.status_code != 200 or "user_login" not in resp.text:
                return

            # Probar con username inexistente para ver el mensaje base
            fake_resp = self.session.post(
                url,
                data={"log": "xipe_nonexistent_user_zz9", "pwd": "wrongpass", "wp-submit": "Log+In"},
                timeout=8,
                allow_redirects=True,
            )
            # WordPress dice "Invalid username" para user inexistente
            # y "The password you entered for the username X is incorrect" para user válido
            if "invalid username" in fake_resp.text.lower():
                self.findings.append(Finding(
                    module="wordpress_scanner",
                    title="WordPress Login — Username Enumeration via Error Messages",
                    severity=Severity.MEDIUM,
                    description=(
                        "The login page returns different error messages for valid vs invalid usernames, "
                        "allowing an attacker to enumerate valid accounts and then target them for brute force."
                    ),
                    endpoint=url,
                    recommendation=(
                        "add_filter('login_errors', function(){ "
                        "return 'Invalid username or password.'; });"
                    ),
                    evidence=(
                        f"POST {url} with fake username returned: "
                        f"'{'invalid username' if 'invalid username' in fake_resp.text.lower() else 'other error'}'"
                    ),
                    tags=["wordpress", "login", "user-enumeration"],
                    owasp_top10="A07",
                ))
                if self.logger:
                    self.logger.warning(f"  LOGIN: Username enumeration confirmed at {url}")

        except Exception:
            pass

    def _check_xmlrpc(self):
        url = self.target + "/xmlrpc.php"
        try:
            xml = "<?xml version='1.0'?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>password</value></param></params></methodCall>"
            resp = self.session.post(url, data=xml, headers={"Content-Type": "text/xml"}, timeout=8)
            if resp.status_code == 200 and "XML-RPC" in resp.text:
                self.findings.append(Finding(
                    module="wordpress_scanner",
                    title="XML-RPC Enabled — Brute Force Vector",
                    severity=Severity.HIGH,
                    description="XML-RPC allows thousands of brute force attempts per request via system.multicall.",
                    endpoint=url,
                    recommendation="add_filter('xmlrpc_enabled', '__return_false');",
                    evidence="XML-RPC active at " + url,
                    tags=["wordpress","xmlrpc"], owasp_top10="A07",
                ))
        except Exception:
            pass

    def _check_wp_version(self):
        try:
            resp = self.session.get(self.target, timeout=8)
            m = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', resp.text)
            if m:
                v = m.group(1)
                self.findings.append(Finding(
                    module="wordpress_scanner",
                    title="WordPress Version Disclosed: " + v,
                    severity=Severity.LOW,
                    description="WordPress " + v + " disclosed via meta generator.",
                    endpoint=self.target,
                    recommendation="remove_action('wp_head', 'wp_generator');",
                    evidence="Generator: WordPress " + v,
                    tags=["wordpress","version-disclosure"], owasp_top10="A06",
                ))
        except Exception:
            pass
