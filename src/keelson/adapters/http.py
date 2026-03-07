"""Generic HTTP adapter for any OpenAI-compatible chat completions endpoint."""

from __future__ import annotations

import time

import httpx

from keelson.adapters.base import BaseAdapter


class GenericHTTPAdapter(BaseAdapter):
    """Adapter for any OpenAI-compatible chat completions endpoint."""

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        timeout: float = 60.0,
        default_model: str = "gpt-4o",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._default_model = default_model
        self._client = httpx.AsyncClient(timeout=timeout)

    async def _send_messages_impl(
        self,
        messages: list[dict[str, str]],
        model: str = "default",
        max_response_tokens: int | None = None,
    ) -> tuple[str, int]:
        """Send messages to the endpoint and return (response_text, response_time_ms)."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        resolved_model = model if model != "default" else self._default_model
        payload: dict[str, object] = {"model": resolved_model, "messages": messages}
        if max_response_tokens is not None:
            payload["max_tokens"] = max_response_tokens
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
            await self._send_messages_impl([{"role": "user", "content": "ping"}], "default")
            return True
        except (httpx.HTTPError, KeyError, IndexError):
            return False

    async def close(self) -> None:
        await self._client.aclose()
