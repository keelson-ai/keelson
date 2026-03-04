"""LangGraph Platform API adapter."""

from __future__ import annotations

import time

import httpx

from pentis.adapters.base import BaseAdapter


class LangGraphAdapter(BaseAdapter):
    """Adapter for the LangGraph Platform /runs/wait endpoint.

    Uses the blocking run endpoint — no SSE parsing required.
    """

    def __init__(
        self,
        url: str,
        api_key: str = "",
        assistant_id: str = "agent",
        thread_id: str | None = None,
        timeout: float = 120.0,
    ):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.assistant_id = assistant_id
        self.thread_id = thread_id
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.AsyncClient(headers=headers, timeout=timeout)

    async def send_messages(
        self, messages: list[dict[str, str]], model: str = "default"
    ) -> tuple[str, int]:
        """Send messages via /runs/wait and return (response_text, response_time_ms)."""
        payload: dict = {
            "input": {"messages": messages},
            "assistant_id": self.assistant_id,
        }
        if self.thread_id:
            payload["thread_id"] = self.thread_id
        if model != "default":
            payload["config"] = {"configurable": {"model": model}}

        start = time.monotonic()
        resp = await self._client.post(f"{self.url}/runs/wait", json=payload)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        resp.raise_for_status()
        data = resp.json()
        content = self._extract_ai_response(data)
        return content, elapsed_ms

    @staticmethod
    def _extract_ai_response(data: dict) -> str:
        """Find the last AI message from the run response.

        Handles messages at top level or nested under 'output', and content
        as a plain string or a list of content blocks.
        """
        messages = data.get("messages") or []
        if not messages:
            output = data.get("output", {})
            if isinstance(output, dict):
                messages = output.get("messages") or []

        # Walk backwards to find the last AI/assistant message
        for msg in reversed(messages):
            if msg.get("type") == "ai" or msg.get("role") == "assistant":
                content = msg.get("content", "")
                if isinstance(content, list):
                    # Content blocks: [{"type": "text", "text": "..."}, ...]
                    parts = []
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            parts.append(block.get("text", ""))
                        elif isinstance(block, str):
                            parts.append(block)
                    return "".join(parts)
                return content
        return ""

    async def health_check(self) -> bool:
        """Send a minimal run to verify the endpoint is reachable."""
        try:
            resp = await self._client.post(
                f"{self.url}/runs/wait",
                json={
                    "input": {"messages": [{"role": "user", "content": "ping"}]},
                    "assistant_id": self.assistant_id,
                },
            )
            return resp.status_code < 500
        except httpx.HTTPError:
            return False

    async def close(self) -> None:
        await self._client.aclose()
