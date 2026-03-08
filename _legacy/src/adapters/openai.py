"""OpenAI-compatible chat completions adapter."""

from __future__ import annotations

import time

import httpx

from keelson.adapters.base import BaseAdapter


class OpenAIAdapter(BaseAdapter):
    """Adapter for OpenAI-compatible chat completions API."""

    def __init__(self, url: str, api_key: str = "", timeout: float = 60.0):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.AsyncClient(headers=headers, timeout=timeout)

    async def _send_messages_impl(
        self,
        messages: list[dict[str, str]],
        model: str = "default",
        max_response_tokens: int | None = None,
    ) -> tuple[str, int]:
        """Send messages and return (response_text, response_time_ms)."""
        payload: dict[str, object] = {"model": model, "messages": messages}
        if max_response_tokens is not None:
            payload["max_tokens"] = max_response_tokens
        start = time.monotonic()
        resp = await self._client.post(self.url, json=payload)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        resp.raise_for_status()
        data = resp.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        return content, elapsed_ms

    async def health_check(self) -> bool:
        """Send a simple request to verify the target is reachable."""
        try:
            await self._send_messages_impl([{"role": "user", "content": "ping"}], "default")
            return True
        except (httpx.HTTPError, KeyError, IndexError):
            return False

    async def close(self) -> None:
        await self._client.aclose()
