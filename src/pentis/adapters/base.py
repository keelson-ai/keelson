"""Abstract base adapter for target communication."""

from __future__ import annotations

from abc import ABC, abstractmethod


class BaseAdapter(ABC):
    """Abstract interface for sending messages to an AI agent target."""

    @abstractmethod
    async def send_messages(
        self, messages: list[dict[str, str]], model: str = "default"
    ) -> tuple[str, int]:
        """Send messages to the target and return (response_text, response_time_ms)."""

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the target is reachable."""

    @abstractmethod
    async def close(self) -> None:
        """Clean up resources."""

    @staticmethod
    def _last_user_message(messages: list[dict[str, str]]) -> str:
        """Extract the last user message from a messages list."""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                return msg["content"]
        return ""
