"""Tests for the MCP (Model Context Protocol) adapter."""

from __future__ import annotations

import json
from typing import Any

import pytest
import respx

from keelson.adapters.mcp import MCPAdapter

BASE_URL = "https://example.mcp.dev"


def _mcp_response(text: str, req_id: int = 1) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 success response with MCP content blocks."""
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "content": [{"type": "text", "text": text}],
        },
    }


def _mcp_init_response(req_id: int = 1) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "serverInfo": {"name": "test-server", "version": "1.0.0"},
        },
    }


def _mcp_error_response(code: int, message: str, req_id: int = 1) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": code, "message": message},
    }


@pytest.mark.asyncio
class TestMCPAdapter:
    @respx.mock
    async def test_send_messages_basic(self) -> None:
        """First call triggers init handshake, then tools/call."""
        # init request (id=1) -> init response
        # initialized notification (no response needed)
        # tools/call (id=2) -> tool response
        route = respx.post(BASE_URL).mock(
            side_effect=[
                respx.MockResponse(json=_mcp_init_response(req_id=1)),
                respx.MockResponse(json={}),  # notification ack
                respx.MockResponse(json=_mcp_response("Hello!", req_id=2)),
            ]
        )
        adapter = MCPAdapter(url=BASE_URL, api_key="test-key")
        text, ms = await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        assert text == "Hello!"
        assert ms >= 0
        # 3 requests: initialize, notification, tools/call
        assert len(route.calls) == 3

    @respx.mock
    async def test_init_called_once(self) -> None:
        """Second send_messages should not re-initialize."""
        route = respx.post(BASE_URL).mock(
            side_effect=[
                respx.MockResponse(json=_mcp_init_response(req_id=1)),
                respx.MockResponse(json={}),
                respx.MockResponse(json=_mcp_response("First", req_id=2)),
                respx.MockResponse(json=_mcp_response("Second", req_id=3)),
            ]
        )
        adapter = MCPAdapter(url=BASE_URL)
        await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.send_messages([{"role": "user", "content": "Again"}])
        await adapter.close()
        # 4 total: init + notification + 2 tools/call
        assert len(route.calls) == 4

    @respx.mock
    async def test_tool_call_payload_format(self) -> None:
        route = respx.post(BASE_URL).mock(
            side_effect=[
                respx.MockResponse(json=_mcp_init_response(req_id=1)),
                respx.MockResponse(json={}),
                respx.MockResponse(json=_mcp_response("ok", req_id=2)),
            ]
        )
        adapter = MCPAdapter(url=BASE_URL, tool_name="ask")
        await adapter.send_messages([{"role": "user", "content": "Hi"}], model="gpt-4")
        await adapter.close()
        # Third call is tools/call
        body: dict[str, Any] = json.loads(route.calls[2].request.content)  # type: ignore[reportUnknownMemberType]
        assert body["method"] == "tools/call"
        assert body["params"]["name"] == "ask"
        assert body["params"]["arguments"]["messages"] == [{"role": "user", "content": "Hi"}]
        assert body["params"]["arguments"]["model"] == "gpt-4"

    @respx.mock
    async def test_default_model_omitted(self) -> None:
        route = respx.post(BASE_URL).mock(
            side_effect=[
                respx.MockResponse(json=_mcp_init_response(req_id=1)),
                respx.MockResponse(json={}),
                respx.MockResponse(json=_mcp_response("ok", req_id=2)),
            ]
        )
        adapter = MCPAdapter(url=BASE_URL)
        await adapter.send_messages([{"role": "user", "content": "Hi"}], model="default")
        await adapter.close()
        body: dict[str, Any] = json.loads(route.calls[2].request.content)  # type: ignore[reportUnknownMemberType]
        assert "model" not in body["params"]["arguments"]

    @respx.mock
    async def test_initialize_payload(self) -> None:
        route = respx.post(BASE_URL).mock(
            side_effect=[
                respx.MockResponse(json=_mcp_init_response(req_id=1)),
                respx.MockResponse(json={}),
                respx.MockResponse(json=_mcp_response("ok", req_id=2)),
            ]
        )
        adapter = MCPAdapter(url=BASE_URL)
        await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        init_body: dict[str, Any] = json.loads(route.calls[0].request.content)  # type: ignore[reportUnknownMemberType]
        assert init_body["method"] == "initialize"
        assert init_body["jsonrpc"] == "2.0"
        assert init_body["params"]["clientInfo"]["name"] == "keelson"

    @respx.mock
    async def test_jsonrpc_error_raises(self) -> None:
        respx.post(BASE_URL).mock(
            side_effect=[
                respx.MockResponse(json=_mcp_init_response(req_id=1)),
                respx.MockResponse(json={}),
                respx.MockResponse(json=_mcp_error_response(-32600, "Invalid request", req_id=2)),
            ]
        )
        adapter = MCPAdapter(url=BASE_URL)
        with pytest.raises(RuntimeError, match="MCP error -32600"):
            await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()

    @respx.mock
    async def test_multi_content_blocks(self) -> None:
        response: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "content": [
                    {"type": "text", "text": "Part A "},
                    {"type": "text", "text": "Part B"},
                ],
            },
        }
        respx.post(BASE_URL).mock(
            side_effect=[
                respx.MockResponse(json=_mcp_init_response(req_id=1)),
                respx.MockResponse(json={}),
                respx.MockResponse(json=response),
            ]
        )
        adapter = MCPAdapter(url=BASE_URL)
        text, _ = await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        assert text == "Part A Part B"

    @respx.mock
    async def test_auth_header(self) -> None:
        route = respx.post(BASE_URL).mock(
            side_effect=[
                respx.MockResponse(json=_mcp_init_response(req_id=1)),
                respx.MockResponse(json={}),
                respx.MockResponse(json=_mcp_response("ok", req_id=2)),
            ]
        )
        adapter = MCPAdapter(url=BASE_URL, api_key="sk-mcp-123")
        await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        headers: Any = route.calls[0].request.headers  # type: ignore[reportUnknownMemberType]
        assert headers["authorization"] == "Bearer sk-mcp-123"

    @respx.mock
    async def test_health_check_success(self) -> None:
        respx.post(BASE_URL).mock(
            side_effect=[
                respx.MockResponse(json=_mcp_init_response(req_id=1)),
                respx.MockResponse(json={}),
            ]
        )
        adapter = MCPAdapter(url=BASE_URL)
        assert await adapter.health_check() is True
        await adapter.close()

    @respx.mock
    async def test_health_check_failure(self) -> None:
        respx.post(BASE_URL).respond(status_code=500)  # type: ignore[reportUnknownMemberType]
        adapter = MCPAdapter(url=BASE_URL)
        assert await adapter.health_check() is False
        await adapter.close()

    @respx.mock
    async def test_http_error_raises(self) -> None:
        respx.post(BASE_URL).mock(
            side_effect=[
                respx.MockResponse(json=_mcp_init_response(req_id=1)),
                respx.MockResponse(json={}),
                respx.MockResponse(status_code=503),
            ]
        )
        adapter = MCPAdapter(url=BASE_URL)
        with pytest.raises(Exception):
            await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()

    @respx.mock
    async def test_request_id_incrementing(self) -> None:
        route = respx.post(BASE_URL).mock(
            side_effect=[
                respx.MockResponse(json=_mcp_init_response(req_id=1)),
                respx.MockResponse(json={}),
                respx.MockResponse(json=_mcp_response("a", req_id=2)),
                respx.MockResponse(json=_mcp_response("b", req_id=3)),
            ]
        )
        adapter = MCPAdapter(url=BASE_URL)
        await adapter.send_messages([{"role": "user", "content": "First"}])
        await adapter.send_messages([{"role": "user", "content": "Second"}])
        await adapter.close()
        # init id=1, tools/call id=2, tools/call id=3
        init_body: dict[str, Any] = json.loads(route.calls[0].request.content)  # type: ignore[reportUnknownMemberType]
        call1_body: dict[str, Any] = json.loads(route.calls[2].request.content)  # type: ignore[reportUnknownMemberType]
        call2_body: dict[str, Any] = json.loads(route.calls[3].request.content)  # type: ignore[reportUnknownMemberType]
        assert init_body["id"] == 1
        assert call1_body["id"] == 2
        assert call2_body["id"] == 3
