"""Tests for the HTTP adapter."""

import pytest
import httpx
import respx

from pentis.adapters.http import HTTPAdapter
from pentis.core.models import AgentResponse
from tests.mock_server import create_mock_response, SAFE_AGENT


@pytest.fixture
def mock_url():
    return "http://test-agent.local/v1/chat/completions"


@pytest.fixture
def adapter(mock_url):
    return HTTPAdapter(url=mock_url, model="test-model", timeout=5.0)


class TestHTTPAdapter:
    @respx.mock
    @pytest.mark.asyncio
    async def test_send_basic_message(self, adapter, mock_url):
        mock_data = create_mock_response("Hello! How can I help?")
        respx.post(mock_url).mock(return_value=httpx.Response(200, json=mock_data))

        response = await adapter.send("Hello")
        assert isinstance(response, AgentResponse)
        assert response.content == "Hello! How can I help?"
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_response_model_parsed(self, adapter, mock_url):
        mock_data = create_mock_response("Hi", model="gpt-4")
        respx.post(mock_url).mock(return_value=httpx.Response(200, json=mock_data))

        response = await adapter.send("Hello")
        assert response.model == "gpt-4"
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_conversation_history_maintained(self, adapter, mock_url):
        mock_data = create_mock_response("Response 1")
        route = respx.post(mock_url).mock(return_value=httpx.Response(200, json=mock_data))

        await adapter.send("Message 1")
        await adapter.send("Message 2")

        # Check that history was sent in second request
        last_request = route.calls[-1].request
        body = last_request.content.decode()
        import json
        payload = json.loads(body)
        messages = payload["messages"]
        # Should include: history (user1, assistant1) + new user message
        assert len(messages) == 3
        assert messages[0]["content"] == "Message 1"
        assert messages[1]["content"] == "Response 1"
        assert messages[2]["content"] == "Message 2"
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_reset_history(self, adapter, mock_url):
        mock_data = create_mock_response("Response")
        respx.post(mock_url).mock(return_value=httpx.Response(200, json=mock_data))

        await adapter.send("Message 1")
        adapter.reset_history()
        await adapter.send("Message 2")

        assert len(adapter.history) == 2  # Only msg2 + response
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_tool_calls_parsed(self, adapter, mock_url):
        mock_data = create_mock_response(
            "Let me search for that.",
            tool_calls=[{
                "id": "call_1",
                "type": "function",
                "function": {"name": "search", "arguments": '{"query": "test"}'},
            }],
        )
        # Need to add tool_calls to message
        mock_data["choices"][0]["message"]["tool_calls"] = [{
            "id": "call_1",
            "type": "function",
            "function": {"name": "search", "arguments": '{"query": "test"}'},
        }]
        respx.post(mock_url).mock(return_value=httpx.Response(200, json=mock_data))

        response = await adapter.send("Search for test")
        assert response.has_tool_calls
        assert len(response.tool_calls) == 1
        assert response.tool_calls[0]["function"]["name"] == "search"
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_api_key_sent_in_header(self, mock_url):
        adapter = HTTPAdapter(url=mock_url, api_key="sk-test-123")
        mock_data = create_mock_response("Hi")
        route = respx.post(mock_url).mock(return_value=httpx.Response(200, json=mock_data))

        await adapter.send("Hello")
        assert route.calls[0].request.headers["Authorization"] == "Bearer sk-test-123"
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_http_error_raises(self, adapter, mock_url):
        respx.post(mock_url).mock(return_value=httpx.Response(500, text="Internal Server Error"))

        with pytest.raises(httpx.HTTPStatusError):
            await adapter.send("Hello")
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_latency_tracked(self, adapter, mock_url):
        mock_data = create_mock_response("Hi")
        respx.post(mock_url).mock(return_value=httpx.Response(200, json=mock_data))

        response = await adapter.send("Hello")
        assert response.latency_ms > 0
        await adapter.close()
