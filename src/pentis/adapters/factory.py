"""Adapter factory — shared adapter construction logic."""

from __future__ import annotations

from pentis.adapters.base import BaseAdapter
from pentis.adapters.openai import OpenAIAdapter


def make_adapter(
    url: str,
    api_key: str,
    adapter_type: str = "openai",
    cache: bool = False,
    assistant_id: str = "agent",
    tool_name: str = "chat",
) -> BaseAdapter:
    """Create the appropriate adapter stack based on configuration.

    Args:
        url: Target endpoint URL.
        api_key: API key for authentication.
        adapter_type: One of openai, anthropic, langgraph, mcp, a2a.
        cache: Whether to wrap with caching layer.
        assistant_id: Assistant ID for LangGraph adapter.
        tool_name: Tool name for MCP adapter.
    """
    base: BaseAdapter
    if adapter_type == "anthropic":
        from pentis.adapters.anthropic import AnthropicAdapter

        base = AnthropicAdapter(api_key=api_key, url=url)
    elif adapter_type == "langgraph":
        from pentis.adapters.langgraph import LangGraphAdapter

        base = LangGraphAdapter(url=url, api_key=api_key, assistant_id=assistant_id)
    elif adapter_type == "mcp":
        from pentis.adapters.mcp import MCPAdapter

        base = MCPAdapter(url=url, api_key=api_key, tool_name=tool_name)
    elif adapter_type == "a2a":
        from pentis.adapters.a2a import A2AAdapter

        base = A2AAdapter(url=url, api_key=api_key)
    else:
        base = OpenAIAdapter(url=url, api_key=api_key)

    if cache:
        from pentis.adapters.cache import CachingAdapter

        base = CachingAdapter(base)

    return base
