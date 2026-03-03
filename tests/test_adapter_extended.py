"""Extended tests for the HTTP adapter — discovery, edge cases, parsing."""

import json

import httpx
import pytest
import respx

from pentis.adapters.http import HTTPAdapter
from pentis.core.models import AgentResponse
from tests.mock_server import create_mock_response

MOCK_URL = "http://test-agent.local/v1/chat/completions"


class TestHTTPAdapterParsing:
    @respx.mock
    @pytest.mark.asyncio
    async def test_parse_empty_choices(self):
        """Empty choices array should return empty content."""
        respx.post(MOCK_URL).mock(return_value=httpx.Response(200, json={
            "id": "test", "object": "chat.completion", "model": "test",
            "choices": [], "usage": {},
        }))
        adapter = HTTPAdapter(url=MOCK_URL)
        resp = await adapter.send("hello", keep_history=False)
        assert resp.content == ""
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_parse_null_content(self):
        """Null content in message should be treated as empty string."""
        respx.post(MOCK_URL).mock(return_value=httpx.Response(200, json={
            "id": "test", "object": "chat.completion", "model": "test",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": None}, "finish_reason": "stop"}],
            "usage": {},
        }))
        adapter = HTTPAdapter(url=MOCK_URL)
        resp = await adapter.send("hello", keep_history=False)
        assert resp.content == ""
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_parse_missing_usage(self):
        """Missing usage field should default to empty dict."""
        respx.post(MOCK_URL).mock(return_value=httpx.Response(200, json={
            "id": "test", "object": "chat.completion", "model": "test",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
        }))
        adapter = HTTPAdapter(url=MOCK_URL)
        resp = await adapter.send("hello", keep_history=False)
        assert resp.usage == {}
        await adapter.close()


class TestHTTPAdapterHistory:
    @respx.mock
    @pytest.mark.asyncio
    async def test_keep_history_false_does_not_accumulate(self):
        respx.post(MOCK_URL).mock(return_value=httpx.Response(200, json=create_mock_response("OK")))
        adapter = HTTPAdapter(url=MOCK_URL)

        await adapter.send("msg1", keep_history=False)
        await adapter.send("msg2", keep_history=False)
        assert len(adapter.history) == 0
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_history_grows_with_keep_history(self):
        respx.post(MOCK_URL).mock(return_value=httpx.Response(200, json=create_mock_response("OK")))
        adapter = HTTPAdapter(url=MOCK_URL)

        await adapter.send("msg1", keep_history=True)
        assert len(adapter.history) == 2  # user + assistant
        await adapter.send("msg2", keep_history=True)
        assert len(adapter.history) == 4
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_reset_clears_history(self):
        respx.post(MOCK_URL).mock(return_value=httpx.Response(200, json=create_mock_response("OK")))
        adapter = HTTPAdapter(url=MOCK_URL)

        await adapter.send("msg1", keep_history=True)
        assert len(adapter.history) == 2
        adapter.reset_history()
        assert len(adapter.history) == 0
        await adapter.close()


class TestHTTPAdapterPayload:
    @respx.mock
    @pytest.mark.asyncio
    async def test_system_message_sent(self):
        route = respx.post(MOCK_URL).mock(return_value=httpx.Response(200, json=create_mock_response("OK")))
        adapter = HTTPAdapter(url=MOCK_URL)

        await adapter.send("hello", system="Be helpful.", keep_history=False)
        body = json.loads(route.calls[0].request.content)
        assert body["messages"][0] == {"role": "system", "content": "Be helpful."}
        assert body["messages"][1] == {"role": "user", "content": "hello"}
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_model_in_payload_when_none(self):
        route = respx.post(MOCK_URL).mock(return_value=httpx.Response(200, json=create_mock_response("OK")))
        adapter = HTTPAdapter(url=MOCK_URL, model=None)

        await adapter.send("hello", keep_history=False)
        body = json.loads(route.calls[0].request.content)
        assert "model" not in body
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_model_in_payload_when_set(self):
        route = respx.post(MOCK_URL).mock(return_value=httpx.Response(200, json=create_mock_response("OK")))
        adapter = HTTPAdapter(url=MOCK_URL, model="llama3")

        await adapter.send("hello", keep_history=False)
        body = json.loads(route.calls[0].request.content)
        assert body["model"] == "llama3"
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_temperature_sent(self):
        route = respx.post(MOCK_URL).mock(return_value=httpx.Response(200, json=create_mock_response("OK")))
        adapter = HTTPAdapter(url=MOCK_URL)

        await adapter.send("hello", keep_history=False, temperature=0.0)
        body = json.loads(route.calls[0].request.content)
        assert body["temperature"] == 0.0
        await adapter.close()


class TestHTTPAdapterURL:
    def test_trailing_slash_stripped(self):
        adapter = HTTPAdapter(url="http://test.com/v1/chat/completions/")
        assert adapter.url == "http://test.com/v1/chat/completions"

    def test_no_trailing_slash_unchanged(self):
        adapter = HTTPAdapter(url="http://test.com/v1/chat/completions")
        assert adapter.url == "http://test.com/v1/chat/completions"


class TestHTTPAdapterClose:
    @respx.mock
    @pytest.mark.asyncio
    async def test_close_idempotent(self):
        """Calling close multiple times should not raise."""
        adapter = HTTPAdapter(url=MOCK_URL)
        await adapter.close()
        await adapter.close()  # should not raise

    @respx.mock
    @pytest.mark.asyncio
    async def test_close_after_use(self):
        respx.post(MOCK_URL).mock(return_value=httpx.Response(200, json=create_mock_response("OK")))
        adapter = HTTPAdapter(url=MOCK_URL)
        await adapter.send("hi", keep_history=False)
        await adapter.close()
        assert adapter._client is None


class TestHTTPAdapterDiscover:
    @respx.mock
    @pytest.mark.asyncio
    async def test_discover_model_from_response(self):
        respx.post(MOCK_URL).mock(
            return_value=httpx.Response(200, json=create_mock_response("Hello!", model="llama3"))
        )
        adapter = HTTPAdapter(url=MOCK_URL)
        info = await adapter.discover()
        assert info.model == "llama3"
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_discover_model_fallback_to_configured(self):
        """When response has no model field, fall back to configured model."""
        respx.post(MOCK_URL).mock(
            return_value=httpx.Response(200, json=create_mock_response("Hello!", model=""))
        )
        adapter = HTTPAdapter(url=MOCK_URL, model="my-model")
        info = await adapter.discover()
        assert info.model == "my-model"
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_discover_on_first_probe_failure(self):
        """If first probe fails, return minimal info."""
        respx.post(MOCK_URL).mock(return_value=httpx.Response(500, text="Error"))
        adapter = HTTPAdapter(url=MOCK_URL)
        info = await adapter.discover()
        assert info.url == MOCK_URL
        assert info.model == ""
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_discover_system_prompt_short_response_not_leak(self):
        """Short responses to prompt leak should not be flagged."""
        call_count = 0

        def respond(request):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                return httpx.Response(200, json=create_mock_response("No."))
            return httpx.Response(200, json=create_mock_response("Hi!", model="test"))

        respx.post(MOCK_URL).mock(side_effect=respond)
        adapter = HTTPAdapter(url=MOCK_URL)
        info = await adapter.discover()
        assert info.system_prompt_leaked == ""
        await adapter.close()
