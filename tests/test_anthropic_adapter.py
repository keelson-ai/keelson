"""Tests for the Anthropic Messages API adapter."""

import pytest
import respx

from pentis.adapters.anthropic import AnthropicAdapter, ANTHROPIC_API_URL


def _anthropic_response(text: str) -> dict:
    return {
        "content": [{"type": "text", "text": text}],
        "model": "claude-sonnet-4-20250514",
        "role": "assistant",
    }


@pytest.mark.asyncio
class TestAnthropicAdapter:
    @respx.mock
    async def test_send_messages_basic(self):
        respx.post(ANTHROPIC_API_URL).respond(json=_anthropic_response("Hello!"))
        adapter = AnthropicAdapter(api_key="test-key")
        text, ms = await adapter.send_messages(
            [{"role": "user", "content": "Hi"}], model="claude-sonnet-4-20250514"
        )
        await adapter.close()
        assert text == "Hello!"
        assert ms >= 0

    @respx.mock
    async def test_system_message_extraction(self):
        route = respx.post(ANTHROPIC_API_URL).respond(json=_anthropic_response("ok"))
        adapter = AnthropicAdapter(api_key="test-key")
        await adapter.send_messages(
            [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Hi"},
            ],
            model="claude-sonnet-4-20250514",
        )
        await adapter.close()
        # Verify system was extracted to top-level param
        request_body = route.calls[0].request
        import json

        body = json.loads(request_body.content)
        assert body["system"] == "You are helpful."
        assert all(m["role"] != "system" for m in body["messages"])

    @respx.mock
    async def test_multiple_system_messages(self):
        route = respx.post(ANTHROPIC_API_URL).respond(json=_anthropic_response("ok"))
        adapter = AnthropicAdapter(api_key="test-key")
        await adapter.send_messages(
            [
                {"role": "system", "content": "First instruction."},
                {"role": "system", "content": "Second instruction."},
                {"role": "user", "content": "Hi"},
            ],
            model="claude-sonnet-4-20250514",
        )
        await adapter.close()
        import json

        body = json.loads(route.calls[0].request.content)
        assert "First instruction." in body["system"]
        assert "Second instruction." in body["system"]

    @respx.mock
    async def test_default_model(self):
        route = respx.post(ANTHROPIC_API_URL).respond(json=_anthropic_response("ok"))
        adapter = AnthropicAdapter(api_key="test-key")
        await adapter.send_messages([{"role": "user", "content": "Hi"}], model="default")
        await adapter.close()
        import json

        body = json.loads(route.calls[0].request.content)
        assert body["model"] == "claude-sonnet-4-20250514"

    @respx.mock
    async def test_headers(self):
        route = respx.post(ANTHROPIC_API_URL).respond(json=_anthropic_response("ok"))
        adapter = AnthropicAdapter(api_key="sk-test-123")
        await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        headers = route.calls[0].request.headers
        assert headers["x-api-key"] == "sk-test-123"
        assert headers["anthropic-version"] == "2023-06-01"

    @respx.mock
    async def test_health_check_success(self):
        respx.post(ANTHROPIC_API_URL).respond(json=_anthropic_response("pong"))
        adapter = AnthropicAdapter(api_key="test-key")
        assert await adapter.health_check() is True
        await adapter.close()

    @respx.mock
    async def test_health_check_failure(self):
        respx.post(ANTHROPIC_API_URL).respond(status_code=500)
        adapter = AnthropicAdapter(api_key="test-key")
        assert await adapter.health_check() is False
        await adapter.close()

    @respx.mock
    async def test_multi_content_blocks(self):
        response = {
            "content": [
                {"type": "text", "text": "Part 1 "},
                {"type": "text", "text": "Part 2"},
            ],
            "model": "claude-sonnet-4-20250514",
            "role": "assistant",
        }
        respx.post(ANTHROPIC_API_URL).respond(json=response)
        adapter = AnthropicAdapter(api_key="test-key")
        text, _ = await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        assert text == "Part 1 Part 2"
