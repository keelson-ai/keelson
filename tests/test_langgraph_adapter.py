"""Tests for the LangGraph Platform API adapter."""

import json

import pytest
import respx

from pentis.adapters.langgraph import LangGraphAdapter

BASE_URL = "https://example.langgraph.app"
RUNS_URL = f"{BASE_URL}/runs/wait"


def _langgraph_response(text: str, nested: bool = False) -> dict:
    """Build a LangGraph /runs/wait response."""
    messages = [
        {"type": "human", "content": "Hi"},
        {"type": "ai", "content": text},
    ]
    if nested:
        return {"output": {"messages": messages}}
    return {"messages": messages}


@pytest.mark.asyncio
class TestLangGraphAdapter:
    @respx.mock
    async def test_send_messages_basic(self):
        respx.post(RUNS_URL).respond(json=_langgraph_response("Hello!"))
        adapter = LangGraphAdapter(url=BASE_URL, api_key="test-key")
        text, ms = await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        assert text == "Hello!"
        assert ms >= 0

    @respx.mock
    async def test_payload_format(self):
        route = respx.post(RUNS_URL).respond(json=_langgraph_response("ok"))
        adapter = LangGraphAdapter(url=BASE_URL, assistant_id="docs_agent")
        await adapter.send_messages([{"role": "user", "content": "Hi"}], model="gpt-4")
        await adapter.close()
        body = json.loads(route.calls[0].request.content)
        assert body["assistant_id"] == "docs_agent"
        assert body["input"]["messages"] == [{"role": "user", "content": "Hi"}]
        assert body["config"]["configurable"]["model"] == "gpt-4"

    @respx.mock
    async def test_default_model_omits_config(self):
        route = respx.post(RUNS_URL).respond(json=_langgraph_response("ok"))
        adapter = LangGraphAdapter(url=BASE_URL)
        await adapter.send_messages([{"role": "user", "content": "Hi"}], model="default")
        await adapter.close()
        body = json.loads(route.calls[0].request.content)
        assert "config" not in body

    @respx.mock
    async def test_thread_id_included(self):
        route = respx.post(RUNS_URL).respond(json=_langgraph_response("ok"))
        adapter = LangGraphAdapter(url=BASE_URL, thread_id="thread-123")
        await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        body = json.loads(route.calls[0].request.content)
        assert body["thread_id"] == "thread-123"

    @respx.mock
    async def test_multi_turn(self):
        route = respx.post(RUNS_URL).respond(json=_langgraph_response("ok"))
        adapter = LangGraphAdapter(url=BASE_URL)
        messages = [
            {"role": "user", "content": "First"},
            {"role": "assistant", "content": "Response"},
            {"role": "user", "content": "Second"},
        ]
        await adapter.send_messages(messages)
        await adapter.close()
        body = json.loads(route.calls[0].request.content)
        assert len(body["input"]["messages"]) == 3

    @respx.mock
    async def test_nested_output_format(self):
        respx.post(RUNS_URL).respond(json=_langgraph_response("Nested!", nested=True))
        adapter = LangGraphAdapter(url=BASE_URL)
        text, _ = await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        assert text == "Nested!"

    @respx.mock
    async def test_content_as_list_of_blocks(self):
        response = {
            "messages": [
                {
                    "type": "ai",
                    "content": [
                        {"type": "text", "text": "Part 1 "},
                        {"type": "text", "text": "Part 2"},
                    ],
                },
            ]
        }
        respx.post(RUNS_URL).respond(json=response)
        adapter = LangGraphAdapter(url=BASE_URL)
        text, _ = await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        assert text == "Part 1 Part 2"

    @respx.mock
    async def test_empty_response(self):
        respx.post(RUNS_URL).respond(json={"messages": []})
        adapter = LangGraphAdapter(url=BASE_URL)
        text, _ = await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        assert text == ""

    @respx.mock
    async def test_auth_header(self):
        route = respx.post(RUNS_URL).respond(json=_langgraph_response("ok"))
        adapter = LangGraphAdapter(url=BASE_URL, api_key="sk-test-123")
        await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        headers = route.calls[0].request.headers
        assert headers["authorization"] == "Bearer sk-test-123"

    @respx.mock
    async def test_health_check_success(self):
        respx.post(RUNS_URL).respond(json=_langgraph_response("pong"))
        adapter = LangGraphAdapter(url=BASE_URL)
        assert await adapter.health_check() is True
        await adapter.close()

    @respx.mock
    async def test_health_check_failure(self):
        respx.post(RUNS_URL).respond(status_code=500)
        adapter = LangGraphAdapter(url=BASE_URL)
        assert await adapter.health_check() is False
        await adapter.close()

    @respx.mock
    async def test_http_error_raises(self):
        respx.post(RUNS_URL).respond(status_code=422)
        adapter = LangGraphAdapter(url=BASE_URL)
        with pytest.raises(Exception):
            await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()

    @respx.mock
    async def test_trailing_slash_stripped(self):
        route = respx.post(RUNS_URL).respond(json=_langgraph_response("ok"))
        adapter = LangGraphAdapter(url=f"{BASE_URL}/")
        await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        assert route.calls[0].request.url == RUNS_URL
