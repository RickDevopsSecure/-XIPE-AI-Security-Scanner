"""
XIPE — Universal AI Chat Client v1.0
Detects and interacts with ANY AI chat platform automatically.

Supported platforms:
- LibreChat / OpenWild
- ChatGPT / OpenAI API
- Flowise
- Anthropic Claude API
- Ollama (local)
- Langchain endpoints
- Generic SSE streaming APIs
- WebSocket-based chats
- REST JSON APIs
- Any iframe-embedded chatbot
"""
import time
import uuid
import json
import re
from typing import Optional, Dict, Any
from urllib.parse import urljoin, urlparse
import httpx


class UniversalAIClient:
    """
    Detects the platform type automatically and uses the right
    communication method to send messages and receive responses.
    """

    PLATFORM_SIGNATURES = {
        "librechat": {
            "config_endpoint": "/api/config",
            "markers": ["registrationEnabled", "socialLogins", "serverDomain"],
            "chat_endpoints": ["/api/ask/custom", "/api/ask/openAI", "/api/messages"],
            "auth_endpoint": "/api/auth/login",
        },
        "flowise": {
            "config_endpoint": "/api/v1/chatflows",
            "markers": ["id", "name", "deployed"],
            "chat_endpoints": ["/api/v1/prediction/"],
            "auth_endpoint": None,
        },
        "openai_api": {
            "config_endpoint": "/v1/models",
            "markers": ["data", "object"],
            "chat_endpoints": ["/v1/chat/completions"],
            "auth_endpoint": None,
        },
        "anthropic_api": {
            "config_endpoint": None,
            "markers": [],
            "chat_endpoints": ["/v1/messages"],
            "auth_endpoint": None,
        },
        "ollama": {
            "config_endpoint": "/api/tags",
            "markers": ["models", "name", "size"],
            "chat_endpoints": ["/api/chat", "/api/generate"],
            "auth_endpoint": None,
        },
        "langchain": {
            "config_endpoint": "/playground",
            "markers": ["input_schema", "output_schema"],
            "chat_endpoints": ["/invoke", "/stream", "/chat"],
            "auth_endpoint": None,
        },
    }

    def __init__(self, base_url: str, token: Optional[str] = None,
                 api_key: Optional[str] = None, logger=None, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.api_key = api_key
        self.logger = logger
        self.timeout = timeout
        self.platform: Optional[str] = None
        self.chat_endpoint: Optional[str] = None
        self.chat_format: Optional[str] = None
        self.platform_config: Dict = {}
        self.conversation_id: Optional[str] = None
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; XIPE-Scanner/2.1)"}
        )

    # ── Platform Detection ────────────────────────────────────────────────────

    def detect_platform(self) -> str:
        """Auto-detect the AI platform type."""
        self._log(f"Detecting platform at {self.base_url}...")

        # Try known signatures
        for platform, sig in self.PLATFORM_SIGNATURES.items():
            if sig["config_endpoint"]:
                try:
                    resp = self.client.get(
                        self.base_url + sig["config_endpoint"],
                        timeout=8
                    )
                    if resp.status_code == 200:
                        content_type = resp.headers.get("content-type", "")
                        if "html" in content_type:
                            continue
                        try:
                            data = resp.json()
                            if any(marker in str(data) for marker in sig["markers"]):
                                self.platform = platform
                                self.platform_config = data if isinstance(data, dict) else {}
                                self._log(f"Platform detected: {platform}")
                                return platform
                        except Exception:
                            pass
                except Exception:
                    pass

        # Scan JS bundle for API patterns
        platform = self._detect_from_js()
        if platform:
            self.platform = platform
            return platform

        # Try generic probing
        platform = self._probe_generic_endpoints()
        if platform:
            self.platform = platform
            return platform

        self.platform = "unknown"
        self._log("Platform: unknown — will attempt generic methods")
        return "unknown"

    def _detect_from_js(self) -> Optional[str]:
        """Detect platform by analyzing JS bundles."""
        try:
            resp = self.client.get(self.base_url, timeout=10)
            html = resp.text

            # Extract JS files
            js_files = re.findall(r'src="([^"]*\.js[^"]*)"', html)
            for js_path in js_files[:5]:  # Check first 5 JS files only
                js_url = js_path if js_path.startswith("http") else self.base_url + "/" + js_path.lstrip("/")
                try:
                    js = self.client.get(js_url, timeout=8).text[:50000]
                    if "librechat" in js.lower() or "/api/ask/" in js:
                        return "librechat"
                    if "flowise" in js.lower() or "chatflow" in js.lower():
                        return "flowise"
                    if "openai" in js.lower() and "chat/completions" in js:
                        return "openai_api"
                    if "anthropic" in js.lower() and "messages" in js:
                        return "anthropic_api"
                    if "ollama" in js.lower():
                        return "ollama"
                except Exception:
                    pass
        except Exception:
            pass
        return None

    def _probe_generic_endpoints(self) -> Optional[str]:
        """Try common AI chat endpoints to find what works."""
        probes = [
            ("/v1/models", "openai_api"),
            ("/api/v1/chatflows", "flowise"),
            ("/api/tags", "ollama"),
            ("/api/config", "librechat"),
            ("/health", "generic"),
        ]
        for path, platform in probes:
            try:
                resp = self.client.get(self.base_url + path, timeout=5)
                if resp.status_code == 200:
                    ct = resp.headers.get("content-type", "")
                    if "json" in ct:
                        return platform
            except Exception:
                pass
        return None

    # ── Endpoint Discovery ────────────────────────────────────────────────────

    def discover_chat_endpoint(self) -> Optional[str]:
        """Find the working chat endpoint for this platform."""
        if not self.platform:
            self.detect_platform()

        headers = self._get_headers()

        if self.platform in self.PLATFORM_SIGNATURES:
            candidates = self.PLATFORM_SIGNATURES[self.platform]["chat_endpoints"]
        else:
            candidates = [
                "/v1/chat/completions",
                "/api/chat",
                "/api/v1/chat",
                "/chat",
                "/api/messages",
                "/api/ask/custom",
                "/invoke",
                "/stream",
            ]

        for path in candidates:
            url = self.base_url + path
            try:
                resp = self.client.post(
                    url,
                    headers={**headers, "Content-Type": "application/json"},
                    json={"messages": [{"role": "user", "content": "test"}]},
                    timeout=8,
                )
                ct = resp.headers.get("content-type", "")
                # Not HTML = real API endpoint
                if "html" not in ct and resp.status_code in (200, 201, 400, 401, 403, 422):
                    self.chat_endpoint = url
                    self._detect_chat_format(resp)
                    self._log(f"Chat endpoint: {url} ({self.chat_format})")
                    return url
                # LibreChat special: /api/ask/* returns HTML via CloudFront
                # but still works for SSE — force it if platform is librechat
                if self.platform == "librechat" and "/api/ask/" in path:
                    self._log(f"LibreChat: forcing {url} despite HTML response (CloudFront SPA)")
                    self.chat_endpoint = url
                    self.chat_format = "librechat"
                    return url
            except Exception:
                pass

        # Flowise special case — needs chatflow ID
        if self.platform == "flowise" and isinstance(self.platform_config, list):
            flows = self.platform_config
            if flows:
                flow_id = flows[0].get("id", "")
                self.chat_endpoint = f"{self.base_url}/api/v1/prediction/{flow_id}"
                self.chat_format = "flowise"
                return self.chat_endpoint

        return None

    def _detect_chat_format(self, resp: httpx.Response):
        """Determine how to parse responses from this endpoint."""
        ct = resp.headers.get("content-type", "")
        if "event-stream" in ct or "text/plain" in ct:
            self.chat_format = "sse"
        elif "json" in ct:
            try:
                data = resp.json()
                if "choices" in data:
                    self.chat_format = "openai"
                elif "content" in data:
                    self.chat_format = "anthropic"
                elif "text" in data:
                    self.chat_format = "flowise"
                else:
                    self.chat_format = "generic_json"
            except Exception:
                self.chat_format = "generic_json"
        else:
            self.chat_format = "sse"

    # ── Message Sending ───────────────────────────────────────────────────────

    def send_message(self, text: str) -> Optional[str]:
        """
        Send a message to the AI and return the response.
        Automatically uses the right format for this platform.
        """
        if not self.chat_endpoint:
            self.discover_chat_endpoint()
        if not self.chat_endpoint:
            return None

        headers = {**self._get_headers(), "Content-Type": "application/json"}

        # Try platform-specific methods first
        response = self._send_platform_specific(text, headers)
        if response:
            return response

        # Fallback: try all known formats
        return self._send_generic(text, headers)

    def _send_platform_specific(self, text: str, headers: dict) -> Optional[str]:
        """Use platform-specific sending logic."""
        if self.platform == "librechat":
            return self._send_librechat(text, headers)
        elif self.platform == "openai_api":
            return self._send_openai(text, headers)
        elif self.platform == "anthropic_api":
            return self._send_anthropic(text, headers)
        elif self.platform == "flowise":
            return self._send_flowise(text, headers)
        elif self.platform == "ollama":
            return self._send_ollama(text, headers)
        return None

    def _send_generic(self, text: str, headers: dict) -> Optional[str]:
        """Try multiple formats until one works."""
        payloads = [
            # OpenAI format
            {"messages": [{"role": "user", "content": text}], "stream": False},
            # Flowise format
            {"question": text},
            # Simple text
            {"text": text},
            # LangChain format
            {"input": {"question": text}},
            # Anthropic-like
            {"messages": [{"role": "user", "content": text}], "max_tokens": 1000},
        ]

        for payload in payloads:
            try:
                resp = self.client.post(
                    self.chat_endpoint,
                    headers=headers,
                    json=payload,
                    timeout=self.timeout,
                )
                ct = resp.headers.get("content-type", "")
                if "html" in ct:
                    continue
                if resp.status_code == 200:
                    result = self._extract_text_from_response(resp)
                    if result:
                        self.chat_format = "generic_json"
                        return result
                    # Try SSE
                    if "stream" in ct or "event-stream" in ct:
                        return self._read_sse_stream(resp)
            except Exception:
                continue
        return None

    # ── Platform-Specific Senders ─────────────────────────────────────────────

    def _send_librechat(self, text: str, headers: dict) -> Optional[str]:
        """LibreChat: use /api/messages polling instead of broken SSE."""
        # Create conversation if needed
        if not self.conversation_id:
            self.conversation_id = self._librechat_create_conversation()

        if not self.conversation_id:
            return None

        # Get last message ID
        parent_id = self._librechat_get_last_message_id() or \
                    "00000000-0000-0000-0000-000000000000"

        # Send message — try multiple payloads and endpoints
        attempts = [
            # LibreChat ask endpoint (SSE) — may be blocked by CloudFront
            (f"{self.base_url}/api/ask/custom", {
                "conversationId": self.conversation_id,
                "parentMessageId": parent_id,
                "text": text,
                "endpoint": "OpenWild",
                "endpointType": "custom",
                "model": "OpenWild",
            }),
            # LibreChat ask with gptPlugins
            (f"{self.base_url}/api/ask/gptPlugins", {
                "conversationId": self.conversation_id,
                "parentMessageId": parent_id,
                "text": text,
                "endpoint": "gptPlugins",
                "model": "gpt-3.5-turbo",
            }),
            # Generic messages POST
            (f"{self.base_url}/api/messages", {
                "conversationId": self.conversation_id,
                "parentMessageId": parent_id,
                "text": text,
                "sender": "User",
                "isCreatedByUser": True,
            }),
        ]

        sent = False
        for endpoint, payload in attempts:
            try:
                resp = self.client.post(
                    endpoint, headers=headers, json=payload, timeout=self.timeout
                )
                ct = resp.headers.get("content-type", "")
                self._log(f"  Send attempt {endpoint}: HTTP {resp.status_code} [{ct[:30]}]")
                if "html" in ct:
                    self._log(f"  CloudFront/SPA blocking {endpoint} — trying next")
                    continue
                if resp.status_code in (200, 201, 202):
                    sent = True
                    if "event-stream" in ct or "text/plain" in ct:
                        result = self._read_sse_stream(resp)
                        if result:
                            return result
                    break
                elif resp.status_code in (400, 422):
                    # Endpoint exists but wrong payload — still mark as sent
                    # The message may have been queued
                    sent = True
                    break
            except Exception as e:
                self._log(f"  Send error {endpoint}: {e}")
                continue

        self._log(f"  sent={sent}")
        if not sent:
            return None  # Don't poll if nothing was sent

        # Poll for response
        return self._librechat_poll_response()

    def _librechat_create_conversation(self) -> Optional[str]:
        """Create a LibreChat conversation."""
        headers = self._get_headers()
        try:
            resp = self.client.post(
                f"{self.base_url}/api/convos",
                headers={**headers, "Content-Type": "application/json"},
                json={"title": f"XIPE {uuid.uuid4().hex[:6]}", "endpoint": "OpenWild"},
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                return data.get("conversationId") or data.get("_id") or data.get("id")
            # Get existing
            resp2 = self.client.get(f"{self.base_url}/api/convos", headers=headers)
            if resp2.status_code == 200:
                convos = resp2.json().get("conversations", [])
                if convos:
                    return convos[0].get("conversationId") or convos[0].get("_id")
        except Exception:
            pass
        return str(uuid.uuid4())

    def _librechat_get_last_message_id(self) -> Optional[str]:
        """Get last message ID from conversation."""
        if not self.conversation_id:
            return None
        try:
            resp = self.client.get(
                f"{self.base_url}/api/messages/{self.conversation_id}",
                headers=self._get_headers(),
            )
            if resp.status_code == 200:
                messages = resp.json()
                if isinstance(messages, list) and messages:
                    return messages[-1].get("messageId") or messages[-1].get("_id")
        except Exception:
            pass
        return None

    def _librechat_poll_response(self, max_wait: int = 25) -> Optional[str]:
        """Poll /api/messages for AI response."""
        if not self.conversation_id:
            return None

        start = time.time()
        last_count = 0

        while time.time() - start < max_wait:
            try:
                resp = self.client.get(
                    f"{self.base_url}/api/messages/{self.conversation_id}",
                    headers=self._get_headers(),
                )
                if resp.status_code == 200:
                    messages = resp.json()
                    if isinstance(messages, list):
                        ai_msgs = [
                            m for m in messages
                            if not m.get("isCreatedByUser", True)
                        ]
                        if ai_msgs and len(ai_msgs) > last_count:
                            last_msg = ai_msgs[-1]
                            text = last_msg.get("text") or last_msg.get("content", "")
                            if text and len(text) > 5 and not last_msg.get("unfinished"):
                                return text
                            last_count = len(ai_msgs)
            except Exception:
                pass
            time.sleep(2)
        return None

    def _send_openai(self, text: str, headers: dict) -> Optional[str]:
        """OpenAI-compatible API."""
        payload = {
            "model": self.platform_config.get("model", "gpt-3.5-turbo"),
            "messages": [{"role": "user", "content": text}],
            "stream": False,
            "max_tokens": 1000,
        }
        try:
            resp = self.client.post(self.chat_endpoint, headers=headers, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("choices", [{}])[0].get("message", {}).get("content")
        except Exception:
            pass
        return None

    def _send_anthropic(self, text: str, headers: dict) -> Optional[str]:
        """Anthropic Claude API."""
        payload = {
            "model": "claude-3-haiku-20240307",
            "max_tokens": 1000,
            "messages": [{"role": "user", "content": text}],
        }
        try:
            resp = self.client.post(self.chat_endpoint, headers=headers, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("content", [{}])[0].get("text")
        except Exception:
            pass
        return None

    def _send_flowise(self, text: str, headers: dict) -> Optional[str]:
        """Flowise chatflow API."""
        payload = {
            "question": text,
            "sessionId": self.conversation_id or str(uuid.uuid4()),
        }
        try:
            resp = self.client.post(self.chat_endpoint, headers=headers, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("text") or data.get("answer") or str(data)
        except Exception:
            pass
        return None

    def _send_ollama(self, text: str, headers: dict) -> Optional[str]:
        """Ollama local API."""
        payload = {
            "model": self.platform_config.get("model", "llama3"),
            "messages": [{"role": "user", "content": text}],
            "stream": False,
        }
        try:
            resp = self.client.post(
                f"{self.base_url}/api/chat", headers=headers, json=payload
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("message", {}).get("content")
        except Exception:
            pass
        return None

    # ── SSE Stream Reader ─────────────────────────────────────────────────────

    def _read_sse_stream(self, resp: httpx.Response) -> Optional[str]:
        """Read Server-Sent Events stream."""
        full_text = ""
        try:
            for line in resp.iter_lines():
                if not line:
                    continue
                if line.startswith("data:"):
                    data_str = line[5:].strip()
                    if data_str == "[DONE]":
                        break
                    try:
                        data = json.loads(data_str)
                        # OpenAI delta format
                        if "choices" in data:
                            delta = data["choices"][0].get("delta", {})
                            full_text += delta.get("content", "")
                        # LibreChat text format
                        elif "text" in data:
                            full_text += data["text"]
                        # Final message
                        elif "message" in data:
                            full_text = data["message"].get("content", full_text)
                    except json.JSONDecodeError:
                        if data_str and not data_str.startswith("{"):
                            full_text += data_str
                elif line.startswith("event:") or line.startswith(":"):
                    continue
        except Exception:
            pass
        return full_text.strip() or None

    # ── Response Extraction ───────────────────────────────────────────────────

    def _extract_text_from_response(self, resp: httpx.Response) -> Optional[str]:
        """Extract text from any JSON response format."""
        try:
            data = resp.json()
        except Exception:
            return resp.text[:500] if resp.text else None

        # Try all known response formats
        extractors = [
            lambda d: d.get("choices", [{}])[0].get("message", {}).get("content"),
            lambda d: d.get("choices", [{}])[0].get("text"),
            lambda d: d.get("content", [{}])[0].get("text") if isinstance(d.get("content"), list) else None,
            lambda d: d.get("text"),
            lambda d: d.get("answer"),
            lambda d: d.get("response"),
            lambda d: d.get("output"),
            lambda d: d.get("result"),
            lambda d: d.get("message", {}).get("content") if isinstance(d.get("message"), dict) else None,
            lambda d: d.get("content") if isinstance(d.get("content"), str) else None,
            lambda d: d.get("generated_text"),
            lambda d: str(d) if d else None,
        ]

        for extractor in extractors:
            try:
                result = extractor(data)
                if result and isinstance(result, str) and len(result) > 3:
                    return result
            except Exception:
                continue
        return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_headers(self) -> dict:
        """Build auth headers based on available credentials."""
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        elif self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
            headers["x-api-key"] = self.api_key
        return headers

    def _log(self, msg: str):
        if self.logger:
            self.logger.info(msg)

    def close(self):
        self.client.close()
