"""MCP (Model Context Protocol) adapter — JSON-RPC 2.0 over HTTP."""

from __future__ import annotations

import time
from typing import Any

import httpx

from pentis.adapters.base import BaseAdapter

MCP_JSONRPC_VERSION = "2.0"
MCP_PROTOCOL_VERSION = "2025-03-26"


class MCPAdapter(BaseAdapter):
    """Adapter for MCP servers using the Streamable HTTP transport.

    Speaks JSON-RPC 2.0: sends initialize handshake on first use,
    then calls tools/call for each message exchange.
    """

    def __init__(
        self,
        url: str,
        api_key: str = "",
        tool_name: str = "chat",
        timeout: float = 60.0,
    ):
        self._url = url.rstrip("/")
        self._api_key = api_key
        self.tool_name = tool_name
        self._initialized = False
        self._request_id = 0
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.AsyncClient(headers=headers, timeout=timeout)

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    async def _ensure_initialized(self) -> None:
        """Perform the MCP initialize handshake if not already done."""
        if self._initialized:
            return

        # Step 1: initialize request
        init_payload: dict[str, Any] = {
            "jsonrpc": MCP_JSONRPC_VERSION,
            "id": self._next_id(),
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "pentis", "version": "1.0.0"},
            },
        }
        resp = await self._client.post(self._url, json=init_payload)
        resp.raise_for_status()

        # Step 2: send initialized notification (no id — it's a notification)
        notification: dict[str, str] = {
            "jsonrpc": MCP_JSONRPC_VERSION,
            "method": "notifications/initialized",
        }
        await self._client.post(self._url, json=notification)

        self._initialized = True

    async def _send_messages_impl(
        self,
        messages: list[dict[str, str]],
        model: str = "default",
        max_response_tokens: int | None = None,  # noqa: ARG002
    ) -> tuple[str, int]:
        """Call tools/call on the MCP server and return (response_text, response_time_ms)."""
        await self._ensure_initialized()

        arguments: dict[str, Any] = {"messages": messages}
        if model != "default":
            arguments["model"] = model

        payload: dict[str, Any] = {
            "jsonrpc": MCP_JSONRPC_VERSION,
            "id": self._next_id(),
            "method": "tools/call",
            "params": {
                "name": self.tool_name,
                "arguments": arguments,
            },
        }

        start = time.monotonic()
        resp = await self._client.post(self._url, json=payload)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()

        # Check for JSON-RPC error
        if "error" in data:
            error: dict[str, Any] = data["error"]
            raise RuntimeError(
                f"MCP error {error.get('code', '?')}: {error.get('message', 'unknown')}"
            )

        result: dict[str, Any] = data.get("result", {})
        content_blocks: list[dict[str, Any]] = result.get("content", [])
        return self._extract_content(content_blocks), elapsed_ms

    @staticmethod
    def _extract_content(content_blocks: list[dict[str, Any]]) -> str:
        """Parse MCP content blocks into a plain text string."""
        parts: list[str] = []
        for block in content_blocks:
            if block.get("type") == "text":
                parts.append(str(block.get("text", "")))
        return "".join(parts)

    async def health_check(self) -> bool:
        """Attempt the MCP initialize handshake to verify reachability."""
        # Reset state so we actually send the handshake
        old_initialized = self._initialized
        old_id = self._request_id
        self._initialized = False
        try:
            await self._ensure_initialized()
            return True
        except Exception:
            return False
        finally:
            # Restore state so next real call re-initializes if needed
            self._initialized = old_initialized
            self._request_id = old_id

    async def close(self) -> None:
        await self._client.aclose()
