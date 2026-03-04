"""Tests for the caching adapter."""

import pytest
import respx

from pentis.adapters.cache import CachingAdapter
from pentis.adapters.openai import OpenAIAdapter


def _chat_response(content: str) -> dict:
    return {"choices": [{"message": {"content": content}}]}


@pytest.mark.asyncio
class TestCachingAdapter:
    @respx.mock
    async def test_cache_miss_forwards_to_adapter(self):
        respx.post("https://target.example.com/v1/chat").respond(json=_chat_response("Hello!"))
        inner = OpenAIAdapter("https://target.example.com/v1/chat")
        adapter = CachingAdapter(inner)
        text, ms = await adapter.send_messages([{"role": "user", "content": "Hi"}], model="default")
        await adapter.close()
        assert text == "Hello!"
        assert adapter.stats.misses == 1
        assert adapter.stats.hits == 0

    @respx.mock
    async def test_cache_hit_returns_cached(self):
        route = respx.post("https://target.example.com/v1/chat").respond(
            json=_chat_response("Hello!")
        )
        inner = OpenAIAdapter("https://target.example.com/v1/chat")
        adapter = CachingAdapter(inner)
        messages = [{"role": "user", "content": "Hi"}]

        # First call — miss
        text1, _ = await adapter.send_messages(messages, model="default")
        # Second call — hit
        text2, _ = await adapter.send_messages(messages, model="default")

        await adapter.close()
        assert text1 == text2 == "Hello!"
        assert adapter.stats.misses == 1
        assert adapter.stats.hits == 1
        assert len(route.calls) == 1  # Only one real request

    @respx.mock
    async def test_different_messages_are_different_keys(self):
        respx.post("https://target.example.com/v1/chat").respond(json=_chat_response("resp"))
        inner = OpenAIAdapter("https://target.example.com/v1/chat")
        adapter = CachingAdapter(inner)

        await adapter.send_messages([{"role": "user", "content": "Hi"}])
        await adapter.send_messages([{"role": "user", "content": "Bye"}])

        await adapter.close()
        assert adapter.stats.misses == 2
        assert adapter.stats.hits == 0

    @respx.mock
    async def test_different_model_is_different_key(self):
        respx.post("https://target.example.com/v1/chat").respond(json=_chat_response("resp"))
        inner = OpenAIAdapter("https://target.example.com/v1/chat")
        adapter = CachingAdapter(inner)
        messages = [{"role": "user", "content": "Hi"}]

        await adapter.send_messages(messages, model="gpt-4")
        await adapter.send_messages(messages, model="gpt-3.5")

        await adapter.close()
        assert adapter.stats.misses == 2

    @respx.mock
    async def test_ttl_expiry(self):

        respx.post("https://target.example.com/v1/chat").respond(json=_chat_response("resp"))
        inner = OpenAIAdapter("https://target.example.com/v1/chat")
        adapter = CachingAdapter(inner, ttl_seconds=0.1)
        messages = [{"role": "user", "content": "Hi"}]

        await adapter.send_messages(messages)
        # Force TTL expiry by patching time
        original_entry = list(adapter._cache.values())[0]
        original_entry.created_at -= 1.0  # Make it old

        await adapter.send_messages(messages)
        await adapter.close()
        assert adapter.stats.misses == 2
        assert adapter.stats.evictions >= 1

    @respx.mock
    async def test_lru_eviction(self):
        respx.post("https://target.example.com/v1/chat").respond(json=_chat_response("resp"))
        inner = OpenAIAdapter("https://target.example.com/v1/chat")
        adapter = CachingAdapter(inner, max_entries=2)

        await adapter.send_messages([{"role": "user", "content": "msg1"}])
        await adapter.send_messages([{"role": "user", "content": "msg2"}])
        await adapter.send_messages([{"role": "user", "content": "msg3"}])

        await adapter.close()
        assert adapter.stats.size == 2
        assert adapter.stats.evictions >= 1

    @respx.mock
    async def test_clear(self):
        respx.post("https://target.example.com/v1/chat").respond(json=_chat_response("resp"))
        inner = OpenAIAdapter("https://target.example.com/v1/chat")
        adapter = CachingAdapter(inner)

        await adapter.send_messages([{"role": "user", "content": "Hi"}])
        assert adapter.stats.size == 1
        adapter.clear()
        assert adapter.stats.size == 0
        await adapter.close()

    @respx.mock
    async def test_health_check_delegates(self):
        respx.post("https://target.example.com/v1/chat").respond(json=_chat_response("pong"))
        inner = OpenAIAdapter("https://target.example.com/v1/chat")
        adapter = CachingAdapter(inner)
        assert await adapter.health_check() is True
        await adapter.close()

    def test_cache_key_deterministic(self):
        messages = [{"role": "user", "content": "test"}]
        key1 = CachingAdapter._cache_key(messages, "gpt-4")
        key2 = CachingAdapter._cache_key(messages, "gpt-4")
        assert key1 == key2

    def test_cache_key_different_for_different_input(self):
        key1 = CachingAdapter._cache_key([{"role": "user", "content": "a"}], "gpt-4")
        key2 = CachingAdapter._cache_key([{"role": "user", "content": "b"}], "gpt-4")
        assert key1 != key2
