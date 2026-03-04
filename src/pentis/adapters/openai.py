"""OpenAI-compatible chat completions adapter."""

from __future__ import annotations

import time

import httpx

from pentis.adapters.base import BaseAdapter


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

    async def send_messages(
        self, messages: list[dict[str, str]], model: str = "default"
    ) -> tuple[str, int]:
        """Send messages and return (response_text, response_time_ms)."""
        payload = {"model": model, "messages": messages}
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
            resp = await self._client.post(
                self.url,
                json={"model": "default", "messages": [{"role": "user", "content": "ping"}]},
            )
            return resp.status_code < 500
        except httpx.HTTPError:
            return False

    async def close(self) -> None:
        await self._client.aclose()
