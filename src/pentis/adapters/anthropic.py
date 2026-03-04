"""Anthropic Messages API adapter."""

from __future__ import annotations

import time

import httpx

from pentis.adapters.base import BaseAdapter

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"


class AnthropicAdapter(BaseAdapter):
    """Adapter for Anthropic Messages API.

    Converts OpenAI-style messages (with system role) into Anthropic format
    where system is a top-level parameter.
    """

    def __init__(
        self,
        api_key: str,
        url: str = ANTHROPIC_API_URL,
        timeout: float = 60.0,
        max_tokens: int = 4096,
    ):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.max_tokens = max_tokens
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
        }
        self._client = httpx.AsyncClient(headers=headers, timeout=timeout)

    async def send_messages(
        self, messages: list[dict[str, str]], model: str = "default"
    ) -> tuple[str, int]:
        """Send messages and return (response_text, response_time_ms).

        Extracts system role messages into the top-level system parameter.
        """
        system_parts: list[str] = []
        api_messages: list[dict[str, str]] = []

        for msg in messages:
            if msg["role"] == "system":
                system_parts.append(msg["content"])
            else:
                api_messages.append({"role": msg["role"], "content": msg["content"]})

        if model == "default":
            model = "claude-sonnet-4-6"

        payload: dict[str, object] = {
            "model": model,
            "max_tokens": self.max_tokens,
            "messages": api_messages,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)

        start = time.monotonic()
        resp = await self._client.post(self.url, json=payload)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        resp.raise_for_status()
        data = resp.json()
        content = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                content += block.get("text", "")
        return content, elapsed_ms

    async def health_check(self) -> bool:
        """Send a minimal request to verify the API is reachable."""
        try:
            resp = await self._client.post(
                self.url,
                json={
                    "model": "claude-sonnet-4-6",
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "ping"}],
                },
            )
            return resp.status_code < 500
        except httpx.HTTPError:
            return False

    async def close(self) -> None:
        await self._client.aclose()
