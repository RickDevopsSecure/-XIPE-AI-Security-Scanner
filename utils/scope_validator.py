"""
XIPE — Scope Validator v1.0
Ensures all probed URLs stay within the authorized engagement scope.
Called by modules before sending any request to a non-base URL.
"""
import re
from urllib.parse import urlparse
from typing import List


class ScopeValidator:
    """
    Validates URLs against the configured scope.

    Usage:
        validator = ScopeValidator(config["scope"]["base_urls"])
        if validator.is_in_scope(url):
            ...
    """

    def __init__(self, base_urls: List[str]):
        self._allowed_hosts: List[str] = []
        for url in base_urls:
            parsed = urlparse(url)
            host = parsed.netloc.lower().split(":")[0]  # strip port
            if host:
                self._allowed_hosts.append(host)

    # ── Public API ─────────────────────────────────────────────────────────────

    def is_in_scope(self, url: str) -> bool:
        """
        Returns True if url belongs to an allowed host.
        Allows exact match and sub-domains of allowed hosts.
        """
        if not url or not isinstance(url, str):
            return False
        try:
            parsed = urlparse(url)
            host = parsed.netloc.lower().split(":")[0]
            if not host:
                # Relative URL — always in scope
                return True
            return any(
                host == allowed or host.endswith("." + allowed)
                for allowed in self._allowed_hosts
            )
        except Exception:
            return False

    def filter_urls(self, urls: List[str]) -> List[str]:
        """Return only in-scope URLs from a list."""
        return [u for u in urls if self.is_in_scope(u)]

    def assert_in_scope(self, url: str):
        """Raise ValueError if url is out of scope."""
        if not self.is_in_scope(url):
            raise ValueError(
                f"Out-of-scope URL blocked: {url!r}. "
                f"Allowed hosts: {self._allowed_hosts}"
            )

    @property
    def allowed_hosts(self) -> List[str]:
        return list(self._allowed_hosts)
