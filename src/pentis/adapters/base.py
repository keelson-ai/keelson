"""Abstract base adapter for target communication."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod

import httpx

logger = logging.getLogger(__name__)

# Retryable HTTP status codes
_RETRYABLE_STATUS_CODES = {429, 502, 503, 504}

# Default retry configuration
_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 1.0  # seconds
_RETRY_MAX_DELAY = 30.0  # seconds


class BaseAdapter(ABC):
    """Abstract interface for sending messages to an AI agent target."""

    @abstractmethod
    async def _send_messages_impl(
        self, messages: list[dict[str, str]], model: str = "default"
    ) -> tuple[str, int]:
        """Send messages to the target and return (response_text, response_time_ms).

        Subclasses implement this. Retry logic is handled by send_messages().
        """

    async def send_messages(
        self,
        messages: list[dict[str, str]],
        model: str = "default",
        *,
        max_retries: int = _MAX_RETRIES,
    ) -> tuple[str, int]:
        """Send messages with automatic retry on transient failures.

        Retries on HTTP 429/502/503/504 with exponential backoff.
        """
        last_exc: Exception | None = None
        for attempt in range(max_retries + 1):
            try:
                return await self._send_messages_impl(messages, model=model)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code not in _RETRYABLE_STATUS_CODES:
                    raise
                last_exc = exc
                if attempt < max_retries:
                    delay = min(
                        _RETRY_BASE_DELAY * (2**attempt),
                        _RETRY_MAX_DELAY,
                    )
                    logger.warning(
                        "HTTP %d from target (attempt %d/%d), retrying in %.1fs",
                        exc.response.status_code,
                        attempt + 1,
                        max_retries + 1,
                        delay,
                    )
                    await asyncio.sleep(delay)
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout) as exc:
                last_exc = exc
                if attempt < max_retries:
                    delay = min(
                        _RETRY_BASE_DELAY * (2**attempt),
                        _RETRY_MAX_DELAY,
                    )
                    logger.warning(
                        "Connection error (attempt %d/%d): %s, retrying in %.1fs",
                        attempt + 1,
                        max_retries + 1,
                        type(exc).__name__,
                        delay,
                    )
                    await asyncio.sleep(delay)

        raise last_exc  # type: ignore[misc]

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the target is reachable."""

    @abstractmethod
    async def close(self) -> None:
        """Clean up resources."""

    def reset_session(self) -> None:
        """Reset conversational state so the next request starts a fresh session.

        Adapters with server-side thread/session state (e.g., LangGraph) should
        override this to clear the thread ID. Stateless adapters (OpenAI, HTTP)
        can use the default no-op since each request is independent.
        """

    @staticmethod
    def _last_user_message(messages: list[dict[str, str]]) -> str:
        """Extract the last user message from a messages list."""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                return msg["content"]
        return ""
