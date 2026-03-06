# pyright: reportUnknownMemberType=false
"""Tests for adapter retry logic with exponential backoff."""

from __future__ import annotations

import httpx
import pytest
import respx

from pentis.adapters.openai import OpenAIAdapter


@pytest.mark.asyncio
class TestAdapterRetry:
    async def test_retry_on_429(self, respx_mock: respx.MockRouter) -> None:
        """Should retry on HTTP 429 and succeed on next attempt."""
        url = "https://api.example.com/v1/chat/completions"
        route = respx_mock.post(url)
        route.side_effect = [
            httpx.Response(429, json={"error": "rate limited"}),
            httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]}),
        ]
        adapter = OpenAIAdapter(url=url, api_key="test")
        try:
            text, _ = await adapter.send_messages(
                [{"role": "user", "content": "hi"}], max_retries=2
            )
            assert text == "ok"
            assert route.call_count == 2
        finally:
            await adapter.close()

    async def test_retry_on_503(self, respx_mock: respx.MockRouter) -> None:
        """Should retry on HTTP 503."""
        url = "https://api.example.com/v1/chat/completions"
        route = respx_mock.post(url)
        route.side_effect = [
            httpx.Response(503, json={"error": "unavailable"}),
            httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]}),
        ]
        adapter = OpenAIAdapter(url=url, api_key="test")
        try:
            text, _ = await adapter.send_messages(
                [{"role": "user", "content": "hi"}], max_retries=2
            )
            assert text == "ok"
        finally:
            await adapter.close()

    async def test_no_retry_on_400(self, respx_mock: respx.MockRouter) -> None:
        """Should NOT retry on HTTP 400 (client error)."""
        url = "https://api.example.com/v1/chat/completions"
        respx_mock.post(url).respond(400, json={"error": "bad request"})
        adapter = OpenAIAdapter(url=url, api_key="test")
        try:
            with pytest.raises(httpx.HTTPStatusError):
                await adapter.send_messages([{"role": "user", "content": "hi"}], max_retries=2)
        finally:
            await adapter.close()

    async def test_max_retries_exhausted(self, respx_mock: respx.MockRouter) -> None:
        """Should raise after exhausting all retries."""
        url = "https://api.example.com/v1/chat/completions"
        route = respx_mock.post(url)
        route.side_effect = [
            httpx.Response(429, json={"error": "rate limited"}),
            httpx.Response(429, json={"error": "rate limited"}),
            httpx.Response(429, json={"error": "rate limited"}),
        ]
        adapter = OpenAIAdapter(url=url, api_key="test")
        try:
            with pytest.raises(httpx.HTTPStatusError):
                await adapter.send_messages([{"role": "user", "content": "hi"}], max_retries=1)
        finally:
            await adapter.close()

    async def test_zero_retries(self, respx_mock: respx.MockRouter) -> None:
        """With max_retries=0, should not retry at all."""
        url = "https://api.example.com/v1/chat/completions"
        route = respx_mock.post(url)
        route.side_effect = [
            httpx.Response(429, json={"error": "rate limited"}),
        ]
        adapter = OpenAIAdapter(url=url, api_key="test")
        try:
            with pytest.raises(httpx.HTTPStatusError):
                await adapter.send_messages([{"role": "user", "content": "hi"}], max_retries=0)
            assert route.call_count == 1
        finally:
            await adapter.close()

    async def test_success_no_retry(self, respx_mock: respx.MockRouter) -> None:
        """Successful requests should not trigger any retry logic."""
        url = "https://api.example.com/v1/chat/completions"
        route = respx_mock.post(url).respond(
            200, json={"choices": [{"message": {"content": "hello"}}]}
        )
        adapter = OpenAIAdapter(url=url, api_key="test")
        try:
            text, _ = await adapter.send_messages([{"role": "user", "content": "hi"}])
            assert text == "hello"
            assert route.call_count == 1
        finally:
            await adapter.close()
