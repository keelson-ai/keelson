"""Tests for the Anthropic Messages API adapter."""

import json
from typing import Any

import pytest
import respx

from pentis.adapters.anthropic import ANTHROPIC_API_URL, AnthropicAdapter


def _anthropic_response(text: str) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": text}],
        "model": "claude-sonnet-4-6",
        "role": "assistant",
    }


@pytest.mark.asyncio
class TestAnthropicAdapter:
    @respx.mock
    async def test_send_messages_basic(self) -> None:
        respx.post(ANTHROPIC_API_URL).respond(json=_anthropic_response("Hello!"))  # type: ignore[reportUnknownMemberType]
        adapter = AnthropicAdapter(api_key="test-key")
        text, ms = await adapter.send_messages(
            [{"role": "user", "content": "Hi"}], model="claude-sonnet-4-6"
        )
        await adapter.close()
        assert text == "Hello!"
        assert ms >= 0

    @respx.mock
    async def test_system_message_extraction(self) -> None:
        route = respx.post(ANTHROPIC_API_URL).respond(json=_anthropic_response("ok"))  # type: ignore[reportUnknownMemberType]
        adapter = AnthropicAdapter(api_key="test-key")
        await adapter.send_messages(
            [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Hi"},
            ],
            model="claude-sonnet-4-6",
        )
        await adapter.close()
        # Verify system was extracted to top-level param
        request_body = route.calls[0].request  # type: ignore[reportUnknownMemberType]
        body = json.loads(request_body.content)  # type: ignore[reportUnknownMemberType]
        assert body["system"] == "You are helpful."
        assert all(m["role"] != "system" for m in body["messages"])

    @respx.mock
    async def test_multiple_system_messages(self) -> None:
        route = respx.post(ANTHROPIC_API_URL).respond(json=_anthropic_response("ok"))  # type: ignore[reportUnknownMemberType]
        adapter = AnthropicAdapter(api_key="test-key")
        await adapter.send_messages(
            [
                {"role": "system", "content": "First instruction."},
                {"role": "system", "content": "Second instruction."},
                {"role": "user", "content": "Hi"},
            ],
            model="claude-sonnet-4-6",
        )
        await adapter.close()
        body = json.loads(route.calls[0].request.content)  # type: ignore[reportUnknownMemberType]
        assert "First instruction." in body["system"]
        assert "Second instruction." in body["system"]

    @respx.mock
    async def test_default_model(self) -> None:
        route = respx.post(ANTHROPIC_API_URL).respond(json=_anthropic_response("ok"))  # type: ignore[reportUnknownMemberType]
        adapter = AnthropicAdapter(api_key="test-key")
        await adapter.send_messages([{"role": "user", "content": "Hi"}], model="default")
        await adapter.close()
        body = json.loads(route.calls[0].request.content)  # type: ignore[reportUnknownMemberType]
        assert body["model"] == "claude-sonnet-4-6"

    @respx.mock
    async def test_headers(self) -> None:
        route = respx.post(ANTHROPIC_API_URL).respond(json=_anthropic_response("ok"))  # type: ignore[reportUnknownMemberType]
        adapter = AnthropicAdapter(api_key="sk-test-123")
        await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        headers = route.calls[0].request.headers  # type: ignore[reportUnknownMemberType]
        assert headers["x-api-key"] == "sk-test-123"
        assert headers["anthropic-version"] == "2023-06-01"

    @respx.mock
    async def test_health_check_success(self) -> None:
        respx.post(ANTHROPIC_API_URL).respond(json=_anthropic_response("pong"))  # type: ignore[reportUnknownMemberType]
        adapter = AnthropicAdapter(api_key="test-key")
        assert await adapter.health_check() is True
        await adapter.close()

    @respx.mock
    async def test_health_check_failure(self) -> None:
        respx.post(ANTHROPIC_API_URL).respond(status_code=500)  # type: ignore[reportUnknownMemberType]
        adapter = AnthropicAdapter(api_key="test-key")
        assert await adapter.health_check() is False
        await adapter.close()

    @respx.mock
    async def test_multi_content_blocks(self) -> None:
        response: dict[str, Any] = {
            "content": [
                {"type": "text", "text": "Part 1 "},
                {"type": "text", "text": "Part 2"},
            ],
            "model": "claude-sonnet-4-6",
            "role": "assistant",
        }
        respx.post(ANTHROPIC_API_URL).respond(json=response)  # type: ignore[reportUnknownMemberType]
        adapter = AnthropicAdapter(api_key="test-key")
        text, _ = await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        assert text == "Part 1 Part 2"
