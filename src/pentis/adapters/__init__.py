"""Pentis adapters — protocol adapters for communicating with AI agent targets."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pentis.adapters.a2a import A2AAdapter
from pentis.adapters.anthropic import AnthropicAdapter
from pentis.adapters.base import BaseAdapter
from pentis.adapters.http import GenericHTTPAdapter
from pentis.adapters.langgraph import LangGraphAdapter
from pentis.adapters.mcp import MCPAdapter
from pentis.adapters.openai import OpenAIAdapter

if TYPE_CHECKING:
    from pentis.adapters.crewai import CrewAIAdapter as CrewAIAdapter
    from pentis.adapters.langchain import LangChainAdapter as LangChainAdapter

# Optional-dependency adapters — imported lazily to avoid ImportError
# when crewai / langchain-core are not installed.


def __getattr__(name: str) -> type:
    if name == "CrewAIAdapter":
        from pentis.adapters.crewai import CrewAIAdapter

        return CrewAIAdapter
    if name == "LangChainAdapter":
        from pentis.adapters.langchain import LangChainAdapter

        return LangChainAdapter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "A2AAdapter",
    "AnthropicAdapter",
    "BaseAdapter",
    "CrewAIAdapter",
    "GenericHTTPAdapter",
    "LangChainAdapter",
    "LangGraphAdapter",
    "MCPAdapter",
    "OpenAIAdapter",
]
