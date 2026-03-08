"""Keelson adapters — protocol adapters for communicating with AI agent targets."""

from __future__ import annotations

from typing import TYPE_CHECKING

from keelson.adapters.a2a import A2AAdapter
from keelson.adapters.anthropic import AnthropicAdapter
from keelson.adapters.base import BaseAdapter
from keelson.adapters.http import GenericHTTPAdapter
from keelson.adapters.langgraph import LangGraphAdapter
from keelson.adapters.mcp import MCPAdapter
from keelson.adapters.openai import OpenAIAdapter

if TYPE_CHECKING:
    from keelson.adapters.crewai import CrewAIAdapter as CrewAIAdapter
    from keelson.adapters.langchain import LangChainAdapter as LangChainAdapter

# Optional-dependency adapters — imported lazily to avoid ImportError
# when crewai / langchain-core are not installed.


def __getattr__(name: str) -> type:
    if name == "CrewAIAdapter":
        from keelson.adapters.crewai import CrewAIAdapter

        return CrewAIAdapter
    if name == "LangChainAdapter":
        from keelson.adapters.langchain import LangChainAdapter

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
