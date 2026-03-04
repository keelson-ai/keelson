"""Tests for A2A (Agent-to-Agent) protocol adapter."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from pentis.adapters.a2a import A2AAdapter


class TestA2AAdapter:
    def test_init(self):
        adapter = A2AAdapter(url="http://localhost:8000", api_key="test-key")
        assert adapter._base_url == "http://localhost:8000"
        assert adapter._api_key == "test-key"

    def test_strips_trailing_slash(self):
        adapter = A2AAdapter(url="http://localhost:8000/")
        assert adapter._base_url == "http://localhost:8000"

    @respx.mock
    async def test_health_check_success(self):
        respx.get("http://localhost:8000/.well-known/agent.json").mock(
            return_value=Response(
                200,
                json={
                    "name": "Test Agent",
                    "description": "A test agent",
                    "url": "http://localhost:8000",
                    "capabilities": {"streaming": False, "pushNotifications": False},
                },
            )
        )

        adapter = A2AAdapter(url="http://localhost:8000")
        assert await adapter.health_check() is True
        await adapter.close()

    @respx.mock
    async def test_health_check_failure(self):
        respx.get("http://localhost:8000/.well-known/agent.json").mock(
            return_value=Response(500)
        )

        adapter = A2AAdapter(url="http://localhost:8000")
        assert await adapter.health_check() is False
        await adapter.close()

    @respx.mock
    async def test_send_messages_success(self):
        respx.post("http://localhost:8000").mock(
            return_value=Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": "test123",
                    "result": {
                        "id": "task-1",
                        "status": {"state": "completed"},
                        "artifacts": [
                            {
                                "parts": [
                                    {"type": "text", "text": "I cannot assist with that request."}
                                ]
                            }
                        ],
                    },
                },
            )
        )

        adapter = A2AAdapter(url="http://localhost:8000")
        response, ms = await adapter.send_messages(
            [{"role": "user", "content": "test attack prompt"}]
        )

        assert response == "I cannot assist with that request."
        assert ms >= 0
        await adapter.close()

    @respx.mock
    async def test_send_messages_with_status_message(self):
        """Verify fallback to status message when no artifacts."""
        respx.post("http://localhost:8000").mock(
            return_value=Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": "test456",
                    "result": {
                        "id": "task-2",
                        "status": {
                            "state": "completed",
                            "message": {
                                "role": "agent",
                                "parts": [{"type": "text", "text": "Status response"}],
                            },
                        },
                    },
                },
            )
        )

        adapter = A2AAdapter(url="http://localhost:8000")
        response, _ = await adapter.send_messages(
            [{"role": "user", "content": "test"}]
        )
        assert response == "Status response"
        await adapter.close()

    @respx.mock
    async def test_send_messages_error_response(self):
        """Verify error handling for JSON-RPC errors."""
        respx.post("http://localhost:8000").mock(
            return_value=Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": "test789",
                    "error": {"code": -32600, "message": "Invalid request"},
                },
            )
        )

        adapter = A2AAdapter(url="http://localhost:8000")
        response, _ = await adapter.send_messages(
            [{"role": "user", "content": "test"}]
        )
        assert "A2A Error" in response
        assert "Invalid request" in response
        await adapter.close()

    @respx.mock
    async def test_send_messages_with_auth_header(self):
        """Verify API key is sent as Bearer token."""
        route = respx.post("http://localhost:8000").mock(
            return_value=Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": "test",
                    "result": {
                        "id": "task-3",
                        "artifacts": [{"parts": [{"type": "text", "text": "ok"}]}],
                    },
                },
            )
        )

        adapter = A2AAdapter(url="http://localhost:8000", api_key="my-key")
        await adapter.send_messages([{"role": "user", "content": "test"}])

        assert route.called
        request = route.calls[0].request
        assert request.headers["Authorization"] == "Bearer my-key"
        await adapter.close()

    async def test_close(self):
        adapter = A2AAdapter(url="http://localhost:8000")
        await adapter.close()  # Should not raise
