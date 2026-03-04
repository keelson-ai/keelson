"""Tests for the LangGraph Platform API adapter."""

from __future__ import annotations

import json
from typing import Any

import pytest
import respx

from pentis.adapters.langgraph import LangGraphAdapter

BASE_URL = "https://example.langgraph.app"
RUNS_URL = f"{BASE_URL}/runs/wait"


def _langgraph_response(text: str, nested: bool = False) -> dict[str, Any]:
    """Build a LangGraph /runs/wait response."""
    messages: list[dict[str, str]] = [
        {"type": "human", "content": "Hi"},
        {"type": "ai", "content": text},
    ]
    if nested:
        return {"output": {"messages": messages}}
    return {"messages": messages}


@pytest.mark.asyncio
class TestLangGraphAdapter:
    @respx.mock
    async def test_send_messages_basic(self) -> None:
        respx.post(RUNS_URL).respond(json=_langgraph_response("Hello!"))  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=BASE_URL, api_key="test-key")
        text, ms = await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        assert text == "Hello!"
        assert ms >= 0

    @respx.mock
    async def test_payload_format(self) -> None:
        route = respx.post(RUNS_URL).respond(json=_langgraph_response("ok"))  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=BASE_URL, assistant_id="docs_agent")
        await adapter.send_messages([{"role": "user", "content": "Hi"}], model="gpt-4")
        await adapter.close()
        body: dict[str, Any] = json.loads(route.calls[0].request.content)  # type: ignore[reportUnknownMemberType]
        assert body["assistant_id"] == "docs_agent"
        assert body["input"]["messages"] == [{"role": "user", "content": "Hi"}]
        assert body["config"]["configurable"]["model"] == "gpt-4"

    @respx.mock
    async def test_default_model_omits_config(self) -> None:
        route = respx.post(RUNS_URL).respond(json=_langgraph_response("ok"))  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=BASE_URL)
        await adapter.send_messages([{"role": "user", "content": "Hi"}], model="default")
        await adapter.close()
        body: dict[str, Any] = json.loads(route.calls[0].request.content)  # type: ignore[reportUnknownMemberType]
        assert "config" not in body

    @respx.mock
    async def test_thread_id_included(self) -> None:
        route = respx.post(RUNS_URL).respond(json=_langgraph_response("ok"))  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=BASE_URL, thread_id="thread-123")
        await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        body: dict[str, Any] = json.loads(route.calls[0].request.content)  # type: ignore[reportUnknownMemberType]
        assert body["thread_id"] == "thread-123"

    @respx.mock
    async def test_multi_turn(self) -> None:
        route = respx.post(RUNS_URL).respond(json=_langgraph_response("ok"))  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=BASE_URL)
        messages: list[dict[str, str]] = [
            {"role": "user", "content": "First"},
            {"role": "assistant", "content": "Response"},
            {"role": "user", "content": "Second"},
        ]
        await adapter.send_messages(messages)
        await adapter.close()
        body: dict[str, Any] = json.loads(route.calls[0].request.content)  # type: ignore[reportUnknownMemberType]
        assert len(body["input"]["messages"]) == 3

    @respx.mock
    async def test_nested_output_format(self) -> None:
        respx.post(RUNS_URL).respond(json=_langgraph_response("Nested!", nested=True))  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=BASE_URL)
        text, _ = await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        assert text == "Nested!"

    @respx.mock
    async def test_content_as_list_of_blocks(self) -> None:
        response: dict[str, Any] = {
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
        respx.post(RUNS_URL).respond(json=response)  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=BASE_URL)
        text, _ = await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        assert text == "Part 1 Part 2"

    @respx.mock
    async def test_empty_response(self) -> None:
        respx.post(RUNS_URL).respond(json={"messages": []})  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=BASE_URL)
        text, _ = await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        assert text == ""

    @respx.mock
    async def test_auth_header(self) -> None:
        route = respx.post(RUNS_URL).respond(json=_langgraph_response("ok"))  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=BASE_URL, api_key="sk-test-123")
        await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        headers: Any = route.calls[0].request.headers  # type: ignore[reportUnknownMemberType]
        assert headers["authorization"] == "Bearer sk-test-123"

    @respx.mock
    async def test_health_check_success(self) -> None:
        respx.post(RUNS_URL).respond(json=_langgraph_response("pong"))  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=BASE_URL)
        assert await adapter.health_check() is True
        await adapter.close()

    @respx.mock
    async def test_health_check_failure(self) -> None:
        respx.post(RUNS_URL).respond(status_code=500)  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=BASE_URL)
        assert await adapter.health_check() is False
        await adapter.close()

    @respx.mock
    async def test_http_error_raises(self) -> None:
        respx.post(RUNS_URL).respond(status_code=422)  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=BASE_URL)
        with pytest.raises(Exception):
            await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()

    @respx.mock
    async def test_trailing_slash_stripped(self) -> None:
        route = respx.post(RUNS_URL).respond(json=_langgraph_response("ok"))  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=f"{BASE_URL}/")
        await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        assert route.calls[0].request.url == RUNS_URL  # type: ignore[reportUnknownMemberType]
