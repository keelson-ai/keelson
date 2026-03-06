"""Tests for the LangGraph Platform API adapter."""

from __future__ import annotations

import json
from typing import Any

import pytest
import respx

from pentis.adapters.langgraph import LangGraphAdapter

BASE_URL = "https://example.langgraph.app"
THREADS_URL = f"{BASE_URL}/threads"
THREAD_ID = "test-thread-001"


def _thread_response() -> dict[str, Any]:
    return {"thread_id": THREAD_ID}


def _runs_url(thread_id: str = THREAD_ID) -> str:
    return f"{BASE_URL}/threads/{thread_id}/runs/wait"


def _langgraph_response(text: str, nested: bool = False) -> dict[str, Any]:
    """Build a LangGraph /runs/wait response."""
    messages: list[dict[str, str]] = [
        {"type": "human", "content": "Hi"},
        {"type": "ai", "content": text},
    ]
    if nested:
        return {"output": {"messages": messages}}
    return {"messages": messages}


def _mock_thread_and_run(response: dict[str, Any] | None = None) -> respx.Route:
    """Mock the thread creation and run endpoints."""
    respx.post(THREADS_URL).respond(json=_thread_response())  # type: ignore[reportUnknownMemberType]
    route = respx.post(_runs_url()).respond(  # type: ignore[reportUnknownMemberType]
        json=response or _langgraph_response("ok")
    )
    return route


@pytest.mark.asyncio
class TestLangGraphAdapter:
    @respx.mock
    async def test_send_messages_basic(self) -> None:
        respx.post(THREADS_URL).respond(json=_thread_response())  # type: ignore[reportUnknownMemberType]
        respx.post(_runs_url()).respond(json=_langgraph_response("Hello!"))  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=BASE_URL, api_key="test-key")
        text, ms = await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        assert text == "Hello!"
        assert ms >= 0

    @respx.mock
    async def test_payload_format(self) -> None:
        _mock_thread_and_run()
        adapter = LangGraphAdapter(url=BASE_URL, assistant_id="docs_agent")
        await adapter.send_messages([{"role": "user", "content": "Hi"}], model="gpt-4")
        await adapter.close()
        # The run request is the second call (first is thread creation)
        run_route = respx.calls[-1]  # type: ignore[reportUnknownMemberType]
        body: dict[str, Any] = json.loads(run_route.request.content)  # type: ignore[reportUnknownMemberType]
        assert body["assistant_id"] == "docs_agent"
        assert body["input"]["messages"] == [{"role": "user", "content": "Hi"}]
        assert body["config"]["configurable"]["model"] == "gpt-4"

    @respx.mock
    async def test_default_model_omits_config(self) -> None:
        _mock_thread_and_run()
        adapter = LangGraphAdapter(url=BASE_URL)
        await adapter.send_messages([{"role": "user", "content": "Hi"}], model="default")
        await adapter.close()
        run_route = respx.calls[-1]  # type: ignore[reportUnknownMemberType]
        body: dict[str, Any] = json.loads(run_route.request.content)  # type: ignore[reportUnknownMemberType]
        assert "config" not in body

    @respx.mock
    async def test_thread_id_included_in_url(self) -> None:
        """When thread_id is pre-set, no thread creation call is needed."""
        respx.post(_runs_url("thread-123")).respond(  # type: ignore[reportUnknownMemberType]
            json=_langgraph_response("ok")
        )
        adapter = LangGraphAdapter(url=BASE_URL, thread_id="thread-123")
        await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        assert str(respx.calls[0].request.url) == _runs_url("thread-123")  # type: ignore[reportUnknownMemberType]

    @respx.mock
    async def test_multi_turn(self) -> None:
        _mock_thread_and_run()
        adapter = LangGraphAdapter(url=BASE_URL)
        messages: list[dict[str, str]] = [
            {"role": "user", "content": "First"},
            {"role": "assistant", "content": "Response"},
            {"role": "user", "content": "Second"},
        ]
        await adapter.send_messages(messages)
        await adapter.close()
        run_route = respx.calls[-1]  # type: ignore[reportUnknownMemberType]
        body: dict[str, Any] = json.loads(run_route.request.content)  # type: ignore[reportUnknownMemberType]
        assert len(body["input"]["messages"]) == 3

    @respx.mock
    async def test_nested_output_format(self) -> None:
        respx.post(THREADS_URL).respond(json=_thread_response())  # type: ignore[reportUnknownMemberType]
        respx.post(_runs_url()).respond(  # type: ignore[reportUnknownMemberType]
            json=_langgraph_response("Nested!", nested=True)
        )
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
        respx.post(THREADS_URL).respond(json=_thread_response())  # type: ignore[reportUnknownMemberType]
        respx.post(_runs_url()).respond(json=response)  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=BASE_URL)
        text, _ = await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        assert text == "Part 1 Part 2"

    @respx.mock
    async def test_empty_response(self) -> None:
        respx.post(THREADS_URL).respond(json=_thread_response())  # type: ignore[reportUnknownMemberType]
        respx.post(_runs_url()).respond(json={"messages": []})  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=BASE_URL)
        text, _ = await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        assert text == ""

    @respx.mock
    async def test_auth_header(self) -> None:
        _mock_thread_and_run()
        adapter = LangGraphAdapter(url=BASE_URL, api_key="sk-test-123")
        await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        headers: Any = respx.calls[-1].request.headers  # type: ignore[reportUnknownMemberType]
        assert headers["authorization"] == "Bearer sk-test-123"

    @respx.mock
    async def test_health_check_success(self) -> None:
        respx.post(THREADS_URL).respond(json=_thread_response())  # type: ignore[reportUnknownMemberType]
        respx.post(_runs_url()).respond(json=_langgraph_response("pong"))  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=BASE_URL)
        assert await adapter.health_check() is True
        await adapter.close()

    @respx.mock
    async def test_health_check_failure(self) -> None:
        respx.post(THREADS_URL).respond(json=_thread_response())  # type: ignore[reportUnknownMemberType]
        respx.post(_runs_url()).respond(status_code=500)  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=BASE_URL)
        assert await adapter.health_check() is False
        await adapter.close()

    @respx.mock
    async def test_http_error_raises(self) -> None:
        respx.post(THREADS_URL).respond(json=_thread_response())  # type: ignore[reportUnknownMemberType]
        respx.post(_runs_url()).respond(status_code=422)  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=BASE_URL)
        with pytest.raises(Exception):
            await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()

    @respx.mock
    async def test_trailing_slash_stripped(self) -> None:
        respx.post(THREADS_URL).respond(json=_thread_response())  # type: ignore[reportUnknownMemberType]
        respx.post(_runs_url()).respond(json=_langgraph_response("ok"))  # type: ignore[reportUnknownMemberType]
        adapter = LangGraphAdapter(url=f"{BASE_URL}/")
        await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.close()
        assert str(respx.calls[-1].request.url) == _runs_url()  # type: ignore[reportUnknownMemberType]

    def test_reset_thread(self) -> None:
        adapter = LangGraphAdapter(url=BASE_URL, thread_id="old-thread")
        assert adapter.thread_id == "old-thread"
        adapter.reset_thread()
        assert adapter.thread_id is None
