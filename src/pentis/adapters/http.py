"""Generic HTTP adapter for any OpenAI-compatible chat completions endpoint."""

from __future__ import annotations

import time

import httpx

from pentis.adapters.base import BaseAdapter


class GenericHTTPAdapter(BaseAdapter):
    """Adapter for any OpenAI-compatible chat completions endpoint."""

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._client = httpx.AsyncClient(timeout=timeout)

    async def send_messages(
        self, messages: list[dict[str, str]], model: str = "default"
    ) -> tuple[str, int]:
        """Send messages to the endpoint and return (response_text, response_time_ms)."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        payload = {"model": model, "messages": messages}
        start = time.monotonic()
        resp = await self._client.post(
            f"{self._base_url}/v1/chat/completions",
            json=payload,
            headers=headers,
        )
        elapsed_ms = int((time.monotonic() - start) * 1000)
        resp.raise_for_status()
        content: str = resp.json()["choices"][0]["message"]["content"]
        return content, elapsed_ms

    async def health_check(self) -> bool:
        """Return True if the endpoint responds without a server error."""
        try:
            _, _ = await self.send_messages(
                [{"role": "user", "content": "ping"}], "default"
            )
            return True
        except (httpx.HTTPError, KeyError, IndexError):
            return False

    async def close(self) -> None:
        await self._client.aclose()
