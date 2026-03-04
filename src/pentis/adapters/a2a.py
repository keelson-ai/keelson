"""Google Agent-to-Agent (A2A) protocol adapter via JSON-RPC 2.0."""

from __future__ import annotations

import time
import uuid

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
        self._agent_card: dict | None = None

    async def _discover_agent(self) -> dict:
        """Discover agent capabilities via /.well-known/agent.json."""
        if self._agent_card:
            return self._agent_card

        headers = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        resp = await self._client.get(
            f"{self._base_url}/.well-known/agent.json",
            headers=headers,
        )
        resp.raise_for_status()
        self._agent_card = resp.json()
        return self._agent_card

    async def send_messages(
        self, messages: list[dict[str, str]], model: str = "default"
    ) -> tuple[str, int]:
        """Send messages via A2A tasks/send JSON-RPC method."""
        # Extract the latest user message
        user_message = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                user_message = msg["content"]
                break

        task_id = uuid.uuid4().hex[:16]
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        # A2A JSON-RPC 2.0 request — tasks/send
        payload = {
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

        data = resp.json()

        # Parse JSON-RPC response
        if "error" in data:
            error = data["error"]
            return f"A2A Error {error.get('code', -1)}: {error.get('message', 'Unknown')}", elapsed_ms

        result = data.get("result", {})

        # Extract text from task result artifacts or status message
        response_text = self._extract_response(result)
        return response_text, elapsed_ms

    def _extract_response(self, result: dict) -> str:
        """Extract text response from A2A task result."""
        # Check for artifacts first (completed tasks)
        artifacts = result.get("artifacts", [])
        if artifacts:
            parts_text: list[str] = []
            for artifact in artifacts:
                for part in artifact.get("parts", []):
                    if part.get("type") == "text":
                        parts_text.append(part["text"])
            if parts_text:
                return "\n".join(parts_text)

        # Fall back to status message
        status = result.get("status", {})
        message = status.get("message", {})
        if message:
            parts = message.get("parts", [])
            texts = [p["text"] for p in parts if p.get("type") == "text"]
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
