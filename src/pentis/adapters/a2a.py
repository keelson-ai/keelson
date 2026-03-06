"""Google Agent-to-Agent (A2A) protocol adapter via JSON-RPC 2.0."""

from __future__ import annotations

import time
import uuid
from typing import Any

import httpx

from pentis.adapters.base import BaseAdapter


class A2AAdapter(BaseAdapter):
    """Adapter for Google's Agent-to-Agent protocol.

    Communicates with A2A-compatible agents via JSON-RPC 2.0 over HTTP.
    Discovers agent capabilities via /.well-known/agent.json.

    Reference: https://google.github.io/A2A/
    """

    def __init__(
        self,
        url: str,
        api_key: str = "",
        timeout: float = 60.0,
    ):
        # url should be the base URL of the A2A agent (e.g., http://localhost:8000)
        self._base_url = url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)
        self._agent_card: dict[str, Any] | None = None

    async def _discover_agent(self) -> dict[str, Any]:
        """Discover agent capabilities via /.well-known/agent.json."""
        if self._agent_card is not None:
            return self._agent_card

        headers: dict[str, str] = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        resp = await self._client.get(
            f"{self._base_url}/.well-known/agent.json",
            headers=headers,
        )
        resp.raise_for_status()
        card: dict[str, Any] = resp.json()
        self._agent_card = card
        return card

    async def _send_messages_impl(
        self,
        messages: list[dict[str, str]],
        model: str = "default",  # noqa: ARG002
    ) -> tuple[str, int]:
        """Send messages via A2A tasks/send JSON-RPC method."""
        user_message = self._last_user_message(messages)

        task_id = uuid.uuid4().hex[:16]
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        # A2A JSON-RPC 2.0 request — tasks/send
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": uuid.uuid4().hex[:8],
            "method": "tasks/send",
            "params": {
                "id": task_id,
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": user_message}],
                },
            },
        }

        start = time.monotonic()
        resp = await self._client.post(
            self._base_url,
            json=payload,
            headers=headers,
        )
        elapsed_ms = int((time.monotonic() - start) * 1000)
        resp.raise_for_status()

        data: dict[str, Any] = resp.json()

        # Parse JSON-RPC response
        if "error" in data:
            error: dict[str, Any] = data["error"]
            return (
                f"A2A Error {error.get('code', -1)}: {error.get('message', 'Unknown')}",
                elapsed_ms,
            )

        result: dict[str, Any] = data.get("result", {})

        # Extract text from task result artifacts or status message
        response_text = self._extract_response(result)
        return response_text, elapsed_ms

    def _extract_response(self, result: dict[str, Any]) -> str:
        """Extract text response from A2A task result."""
        # Check for artifacts first (completed tasks)
        artifacts: list[dict[str, Any]] = result.get("artifacts", [])
        if artifacts:
            parts_text: list[str] = []
            for artifact in artifacts:
                parts: list[dict[str, Any]] = artifact.get("parts", [])
                for part in parts:
                    if part.get("type") == "text":
                        parts_text.append(str(part["text"]))
            if parts_text:
                return "\n".join(parts_text)

        # Fall back to status message
        status: dict[str, Any] = result.get("status", {})
        message: dict[str, Any] = status.get("message", {})
        if message:
            msg_parts: list[dict[str, Any]] = message.get("parts", [])
            texts: list[str] = [str(p["text"]) for p in msg_parts if p.get("type") == "text"]
            if texts:
                return "\n".join(texts)

        return str(result)

    async def health_check(self) -> bool:
        """Check if the A2A agent is reachable via agent card discovery."""
        try:
            card = await self._discover_agent()
            return "name" in card
        except (httpx.HTTPError, KeyError):
            return False

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
