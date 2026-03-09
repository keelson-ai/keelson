"""SiteGPT adapter — public widget via WebSocket (PartyKit) or REST API."""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid

import httpx
import websockets

from keelson.adapters.base import BaseAdapter

logger = logging.getLogger(__name__)

_WIDGET_BASE = "https://widget.sitegpt.ai"
_PK_HOST = "pk.sitegpt.ai"


class SiteGPTAdapter(BaseAdapter):
    """Adapter for SiteGPT chatbots.

    Two modes:
    - **Widget mode** (default, no api_key): Uses the public widget WebSocket
      protocol to talk to any SiteGPT chatbot by its chatbot ID.
    - **API mode** (with api_key): Uses the REST API at
      ``POST /api/v0/chatbots/{chatbotId}/message``.
    """

    def __init__(
        self,
        chatbot_id: str,
        api_key: str = "",
        timeout: float = 60.0,
    ) -> None:
        self._chatbot_id = chatbot_id
        self._api_key = api_key
        self._timeout = timeout
        self._session_id: str = str(uuid.uuid4())
        self._thread_id: str | None = None
        self._client = httpx.AsyncClient(timeout=timeout)

    # ------------------------------------------------------------------
    # Widget mode helpers
    # ------------------------------------------------------------------

    async def _create_thread(self) -> str:
        """Create a new conversation thread via the widget Remix action."""
        resp = await self._client.post(
            f"{_WIDGET_BASE}/c/{self._chatbot_id}",
            params={"_data": "routes/_c4-layout.c.$chatbotId._index"},
            data={
                "_action": "START_CONVERSATION",
                "sessionId": self._session_id,
            },
            headers={"Origin": _WIDGET_BASE},
            follow_redirects=False,
        )
        # Thread ID is in the x-remix-redirect header
        redirect = resp.headers.get("x-remix-redirect", "")
        # Extract thread ID from URL: .../threads/{uuid}?...
        parts = redirect.split("/")
        for i, part in enumerate(parts):
            if part == "threads" and i + 1 < len(parts):
                tid = parts[i + 1].split("?")[0]
                return tid
        msg = f"Failed to create thread: {resp.status_code} {redirect}"
        raise RuntimeError(msg)

    async def _send_widget(self, message: str) -> tuple[str, int]:
        """Send a message via WebSocket and wait for the full response."""
        if not self._thread_id:
            self._thread_id = await self._create_thread()
            logger.info("Created thread %s", self._thread_id)

        ws_url = f"wss://{_PK_HOST}/parties/thread/{self._thread_id}?_pk={self._session_id}"

        payload = json.dumps(
            {
                "event": "NEW_MESSAGE",
                "data": {
                    "from": "USER",
                    "message": message,
                    "sessionId": self._session_id,
                    "triggerFunctionId": None,
                    "gptModelToUse": "gpt-3.5-turbo",
                    "overrides": {"prompt": {"prefix": "", "suffix": ""}},
                },
            }
        )

        answer_parts: list[str] = []
        start = time.monotonic()

        async with websockets.connect(ws_url) as ws:
            await ws.send(payload)

            # Collect streamed response tokens until done
            while True:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=self._timeout)
                except TimeoutError:
                    break

                try:
                    msg = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    continue

                event = msg.get("event", "")

                if event == "AI_STREAM_UPDATED":
                    # Streaming token: answer text accumulates in data.message.answer
                    token = msg.get("data", {}).get("message", {}).get("answer", "")
                    if token:
                        answer_parts = [token]  # replace — value is cumulative

                elif event == "AI_STREAM_ENDED":
                    # Final answer in data.message.answer.text
                    full = msg.get("data", {}).get("message", {}).get("answer", {}).get("text", "")
                    if full:
                        answer_parts = [full]
                    break

                elif event == "ERROR":
                    error_msg = msg.get("data", {}).get("message", "Unknown")
                    raise RuntimeError(f"SiteGPT error: {error_msg}")

        elapsed_ms = int((time.monotonic() - start) * 1000)
        answer = "".join(answer_parts)
        return answer, elapsed_ms

    # ------------------------------------------------------------------
    # API mode helpers
    # ------------------------------------------------------------------

    async def _send_api(self, message: str) -> tuple[str, int]:
        """Send a message via the authenticated REST API."""
        payload: dict[str, str] = {"message": message, "from": "USER"}
        if self._thread_id:
            payload["threadId"] = self._thread_id

        start = time.monotonic()
        resp = await self._client.post(
            f"https://sitegpt.ai/api/v0/chatbots/{self._chatbot_id}/message",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
        )
        elapsed_ms = int((time.monotonic() - start) * 1000)
        resp.raise_for_status()

        data = resp.json()
        msg = data.get("data", {}).get("message", {})

        thread_id = msg.get("threadId")
        if thread_id:
            self._thread_id = thread_id

        answer_text: str = msg.get("answer", {}).get("text", "")
        return answer_text, elapsed_ms

    # ------------------------------------------------------------------
    # BaseAdapter interface
    # ------------------------------------------------------------------

    async def _send_messages_impl(
        self,
        messages: list[dict[str, str]],
        model: str = "default",
        max_response_tokens: int | None = None,  # noqa: ARG002
    ) -> tuple[str, int]:
        """Send the last user message and return (response_text, ms)."""
        user_message = self._last_user_message(messages)
        if self._api_key:
            return await self._send_api(user_message)
        return await self._send_widget(user_message)

    async def health_check(self) -> bool:
        """Verify the chatbot is reachable."""
        try:
            _, _ = await self.send_messages([{"role": "user", "content": "hello"}])
            return True
        except Exception:
            return False

    async def close(self) -> None:
        await self._client.aclose()

    def reset_session(self) -> None:
        """Clear thread and session to start a fresh conversation."""
        self._thread_id = None
        self._session_id = str(uuid.uuid4())
