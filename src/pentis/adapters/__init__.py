"""Pentis adapters — protocol adapters for communicating with AI agent targets."""

from pentis.adapters.a2a import A2AAdapter
from pentis.adapters.anthropic import AnthropicAdapter
from pentis.adapters.base import BaseAdapter
from pentis.adapters.crewai import CrewAIAdapter
from pentis.adapters.http import GenericHTTPAdapter
from pentis.adapters.langchain import LangChainAdapter
from pentis.adapters.langgraph import LangGraphAdapter
from pentis.adapters.mcp import MCPAdapter
from pentis.adapters.openai import OpenAIAdapter

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
