"""Tests for GenericHTTPAdapter."""

from __future__ import annotations

import httpx
import pytest
import respx

from pentis.adapters.http import GenericHTTPAdapter


@pytest.mark.asyncio
async def test_sends_to_custom_url() -> None:
    custom_url = "http://localhost:8080/v1/chat/completions"
    with respx.mock:
        route = respx.post(custom_url).mock(
            return_value=httpx.Response(
                200, json={"choices": [{"message": {"content": "hello"}}]}
            )
        )
        adapter = GenericHTTPAdapter(base_url="http://localhost:8080")
        text, ms = await adapter.send_messages(
            [{"role": "user", "content": "hi"}], "gpt-4"
        )
        assert route.called
        assert text == "hello"
        assert ms >= 0
        await adapter.close()


@pytest.mark.asyncio
async def test_sends_auth_header_when_key_provided() -> None:
    with respx.mock:
        route = respx.post("http://test-agent.local/v1/chat/completions").mock(
            return_value=httpx.Response(
                200, json={"choices": [{"message": {"content": "ok"}}]}
            )
        )
        adapter = GenericHTTPAdapter(
            base_url="http://test-agent.local", api_key="sk-test"
        )
        await adapter.send_messages([{"role": "user", "content": "test"}], "model")
        assert route.called
        assert route.calls[0].request.headers["Authorization"] == "Bearer sk-test"  # type: ignore[reportUnknownMemberType]
        await adapter.close()


@pytest.mark.asyncio
async def test_no_auth_header_when_no_key() -> None:
    with respx.mock:
        route = respx.post("http://no-auth.local/v1/chat/completions").mock(
            return_value=httpx.Response(
                200, json={"choices": [{"message": {"content": "ok"}}]}
            )
        )
        adapter = GenericHTTPAdapter(base_url="http://no-auth.local")
        await adapter.send_messages([{"role": "user", "content": "test"}], "model")
        assert route.called
        assert "Authorization" not in route.calls[0].request.headers  # type: ignore[reportUnknownMemberType]
        await adapter.close()


@pytest.mark.asyncio
async def test_raises_on_http_error() -> None:
    with respx.mock:
        respx.post("http://broken.local/v1/chat/completions").mock(
            return_value=httpx.Response(500)
        )
        adapter = GenericHTTPAdapter(base_url="http://broken.local")
        with pytest.raises(httpx.HTTPStatusError):
            await adapter.send_messages([{"role": "user", "content": "test"}], "model")
        await adapter.close()


@pytest.mark.asyncio
async def test_health_check_returns_true_on_success() -> None:
    with respx.mock:
        respx.post("http://healthy.local/v1/chat/completions").mock(
            return_value=httpx.Response(
                200, json={"choices": [{"message": {"content": "pong"}}]}
            )
        )
        adapter = GenericHTTPAdapter(base_url="http://healthy.local")
        assert await adapter.health_check() is True
        await adapter.close()


@pytest.mark.asyncio
async def test_health_check_returns_false_on_error() -> None:
    with respx.mock:
        respx.post("http://dead.local/v1/chat/completions").mock(
            side_effect=httpx.ConnectError("refused")
        )
        adapter = GenericHTTPAdapter(base_url="http://dead.local")
        assert await adapter.health_check() is False
        await adapter.close()
