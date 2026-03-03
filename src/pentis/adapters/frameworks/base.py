"""Abstract base adapter for framework-native integrations (future)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from pentis.core.models import AgentResponse


class BaseFrameworkAdapter(ABC):
    """Base class for framework-native adapters (CrewAI, LangChain, MCP, etc.)."""

    @abstractmethod
    async def send(self, message: str) -> AgentResponse:
        """Send a message and return the agent's response."""

    @abstractmethod
    async def reset(self) -> None:
        """Reset conversation state."""
