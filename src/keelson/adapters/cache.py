"""Caching adapter — wraps any BaseAdapter with response caching."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass

from keelson.adapters.base import BaseAdapter


@dataclass
class CacheEntry:
    """A single cached response."""

    response_text: str
    response_time_ms: int
    created_at: float
    hit_count: int = 0


@dataclass
class CacheStats:
    """Cache performance statistics."""

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size: int = 0


class CachingAdapter(BaseAdapter):
    """Wraps a BaseAdapter to cache responses by message+model hash.

    Composable: CachingAdapter(AttackerAdapter(AnthropicAdapter(...)))
    """

    def __init__(
        self,
        adapter: BaseAdapter,
        max_entries: int = 10_000,
        ttl_seconds: float = 3600.0,
    ):
        self._adapter = adapter
        self._max_entries = max_entries
        self._ttl_seconds = ttl_seconds
        self._cache: dict[str, CacheEntry] = {}
        self._stats = CacheStats()

    @property
    def stats(self) -> CacheStats:
        self._stats.size = len(self._cache)
        return self._stats

    @staticmethod
    def _cache_key(
        messages: list[dict[str, str]], model: str, max_response_tokens: int | None = None
    ) -> str:
        """Generate a deterministic cache key from messages, model, and max_response_tokens."""
        payload = json.dumps(
            {"messages": messages, "model": model, "max_tokens": max_response_tokens},
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def _evict_expired(self) -> None:
        """Remove entries past their TTL."""
        now = time.monotonic()
        expired = [k for k, v in self._cache.items() if now - v.created_at > self._ttl_seconds]
        for k in expired:
            del self._cache[k]
            self._stats.evictions += 1

    def _evict_lru(self) -> None:
        """Remove least recently used entries to stay under max_entries."""
        while len(self._cache) >= self._max_entries:
            # LRU: evict entry with oldest created_at (simple approximation)
            oldest_key = min(self._cache, key=lambda k: self._cache[k].created_at)
            del self._cache[oldest_key]
            self._stats.evictions += 1

    async def _send_messages_impl(
        self,
        messages: list[dict[str, str]],
        model: str = "default",
        max_response_tokens: int | None = None,
    ) -> tuple[str, int]:
        """Send messages, returning cached response if available."""
        key = self._cache_key(messages, model, max_response_tokens)

        # Check cache
        entry = self._cache.get(key)
        if entry is not None:
            now = time.monotonic()
            if now - entry.created_at <= self._ttl_seconds:
                entry.hit_count += 1
                self._stats.hits += 1
                return entry.response_text, entry.response_time_ms
            else:
                del self._cache[key]
                self._stats.evictions += 1

        # Cache miss — forward to underlying adapter
        self._stats.misses += 1
        self._evict_expired()
        self._evict_lru()

        response_text, response_time_ms = await self._adapter._send_messages_impl(
            messages, model=model, max_response_tokens=max_response_tokens
        )

        self._cache[key] = CacheEntry(
            response_text=response_text,
            response_time_ms=response_time_ms,
            created_at=time.monotonic(),
        )
        return response_text, response_time_ms

    async def health_check(self) -> bool:
        return await self._adapter.health_check()

    async def close(self) -> None:
        await self._adapter.close()

    def reset_session(self) -> None:
        self._adapter.reset_session()

    def clear(self) -> None:
        """Clear the entire cache."""
        self._cache.clear()
