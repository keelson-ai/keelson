"""LangGraph Platform API adapter."""

from __future__ import annotations

import time
from typing import Any, cast

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
        self._url = url.rstrip("/")
        self._api_key = api_key
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
        payload: dict[str, Any] = {
            "input": {"messages": messages},
            "assistant_id": self.assistant_id,
        }
        if self.thread_id:
            payload["thread_id"] = self.thread_id
        if model != "default":
            payload["config"] = {"configurable": {"model": model}}

        start = time.monotonic()
        resp = await self._client.post(f"{self._url}/runs/wait", json=payload)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()
        content = self._extract_ai_response(data)
        return content, elapsed_ms

    @staticmethod
    def _extract_ai_response(data: dict[str, Any]) -> str:
        """Find the last AI message from the run response.

        Handles messages at top level or nested under 'output', and content
        as a plain string or a list of content blocks.
        """
        raw_messages: Any = data.get("messages")
        messages: list[dict[str, Any]] = (
            cast(list[dict[str, Any]], raw_messages) if isinstance(raw_messages, list) else []
        )
        if not messages:
            output: Any = data.get("output", {})
            if isinstance(output, dict):
                output_dict = cast(dict[str, Any], output)
                raw_out: Any = output_dict.get("messages")
                messages = cast(list[dict[str, Any]], raw_out) if isinstance(raw_out, list) else []

        # Walk backwards to find the last AI/assistant message
        for msg in messages[::-1]:
            if msg.get("type") == "ai" or msg.get("role") == "assistant":
                content: Any = msg.get("content", "")
                if isinstance(content, list):
                    # Content blocks: [{"type": "text", "text": "..."}, ...]
                    parts: list[str] = []
                    for block_raw in cast(list[Any], content):
                        block = cast(dict[str, Any], block_raw)
                        if isinstance(block_raw, dict) and block.get("type") == "text":
                            parts.append(str(block.get("text", "")))
                        elif isinstance(block_raw, str):
                            parts.append(block_raw)
                    return "".join(parts)
                return str(content)
        return ""

    async def health_check(self) -> bool:
        """Send a minimal run to verify the endpoint is reachable."""
        try:
            resp = await self._client.post(
                f"{self._url}/runs/wait",
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
