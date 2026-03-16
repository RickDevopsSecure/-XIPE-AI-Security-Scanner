"""
XIPE — LibreChat SSE Fix
Usa el flujo real de LibreChat en lugar de /api/ask/ que CloudFront bloquea:
1. POST /api/convos → crear conversación
2. POST /api/messages → enviar mensaje (dispara el stream internamente)
3. GET  /api/messages/:convId → leer respuesta cuando esté lista
"""
import time
import uuid
from typing import Optional
import httpx


class LibreChatClient:
    """
    Cliente que habla con LibreChat usando la API REST correcta.
    Evita /api/ask/* que CloudFront redirige a la SPA.
    """

    def __init__(self, base_url: str, token: str, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        self.timeout = timeout
        self.client = httpx.Client(timeout=timeout, follow_redirects=True)

    def send_message(self, text: str, conversation_id: Optional[str] = None) -> Optional[str]:
        """
        Envía un mensaje y espera la respuesta.
        Returns: texto de la respuesta del AI, o None si falla.
        """
        # Paso 1: Crear o reusar conversación
        conv_id = conversation_id or self._create_conversation()
        if not conv_id:
            return None

        # Paso 2: Enviar mensaje
        parent_id = self._get_last_message_id(conv_id) or "00000000-0000-0000-0000-000000000000"
        msg_sent = self._send_message(conv_id, parent_id, text)
        if not msg_sent:
            return None

        # Paso 3: Esperar y leer respuesta
        response = self._poll_response(conv_id, max_wait=25)
        return response

    def _create_conversation(self) -> Optional[str]:
        """Crea una nueva conversación y retorna el ID."""
        try:
            resp = self.client.post(
                f"{self.base_url}/api/convos",
                headers=self.headers,
                json={
                    "title": f"XIPE Scan {uuid.uuid4().hex[:6]}",
                    "endpoint": "OpenWild",
                    "model": "OpenWild",
                },
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                conv_id = data.get("conversationId") or data.get("_id") or data.get("id")
                return conv_id
            # Si POST no funciona, intentar GET para ver convos existentes
            resp2 = self.client.get(f"{self.base_url}/api/convos", headers=self.headers)
            if resp2.status_code == 200:
                convos = resp2.json().get("conversations", [])
                if convos:
                    return convos[0].get("conversationId") or convos[0].get("_id")
        except Exception:
            pass
        return None

    def _get_last_message_id(self, conv_id: str) -> Optional[str]:
        """Obtiene el ID del último mensaje en la conversación."""
        try:
            resp = self.client.get(
                f"{self.base_url}/api/messages/{conv_id}",
                headers=self.headers,
            )
            if resp.status_code == 200:
                messages = resp.json()
                if isinstance(messages, list) and messages:
                    return messages[-1].get("messageId") or messages[-1].get("_id")
        except Exception:
            pass
        return None

    def _send_message(self, conv_id: str, parent_id: str, text: str) -> bool:
        """Envía el mensaje al endpoint correcto de LibreChat."""
        endpoints_to_try = [
            # Endpoint principal de mensajes
            (f"{self.base_url}/api/messages", {
                "conversationId": conv_id,
                "parentMessageId": parent_id,
                "text": text,
                "endpoint": "OpenWild",
                "model": "OpenWild",
                "sender": "User",
            }),
            # Endpoint alternativo ask con conversación existente
            (f"{self.base_url}/api/ask/custom", {
                "conversationId": conv_id,
                "parentMessageId": parent_id,
                "text": text,
                "endpoint": "OpenWild",
                "endpointType": "custom",
                "model": "OpenWild",
            }),
            # Endpoint de ask con nueva conversación
            (f"{self.base_url}/api/ask/custom", {
                "conversationId": "new",
                "parentMessageId": "00000000-0000-0000-0000-000000000000",
                "text": text,
                "endpoint": "OpenWild",
                "endpointType": "custom",
                "model": "OpenWild",
            }),
        ]

        for url, payload in endpoints_to_try:
            try:
                resp = self.client.post(url, headers=self.headers, json=payload)
                content_type = resp.headers.get("content-type", "")

                # Si devuelve HTML es CloudFront bloqueando
                if "html" in content_type:
                    continue

                if resp.status_code in (200, 201, 202):
                    return True

            except Exception:
                continue

        return False

    def _poll_response(self, conv_id: str, max_wait: int = 25) -> Optional[str]:
        """
        Espera y lee la respuesta del AI.
        LibreChat procesa el mensaje async — el AI responde en segundos.
        """
        start = time.time()
        last_msg_count = 0

        while time.time() - start < max_wait:
            try:
                resp = self.client.get(
                    f"{self.base_url}/api/messages/{conv_id}",
                    headers=self.headers,
                )
                if resp.status_code == 200:
                    messages = resp.json()
                    if isinstance(messages, list):
                        # Buscar el último mensaje del AI (no del usuario)
                        ai_messages = [
                            m for m in messages
                            if m.get("sender", "").lower() in ("assistant", "ai", "openwild", "gpt")
                            or not m.get("isCreatedByUser", True)
                        ]

                        if ai_messages and len(ai_messages) > last_msg_count:
                            last_msg = ai_messages[-1]
                            text = last_msg.get("text") or last_msg.get("content", "")

                            # Verificar que la respuesta no está vacía y parece completa
                            if text and len(text) > 10:
                                # LibreChat marca mensajes en proceso con unfinished=True
                                if not last_msg.get("unfinished", False):
                                    return text
                                # Si está unfinished, seguir esperando
                            last_msg_count = len(ai_messages)

            except Exception:
                pass

            time.sleep(2)

        return None

    def close(self):
        self.client.close()
