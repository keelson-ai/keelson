"""Pentis Defend hooks for CrewAI agents.

CrewAI uses decorator-based hooks: @before_tool_call, @after_tool_call,
@before_llm_call, @after_llm_call. These are registered globally and
intercept all agent tool/LLM calls.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from pentis.defend.engine import PolicyEngine
from pentis.defend.loader import default_policy
from pentis.defend.models import REDACTED_MESSAGE, DefendPolicy


def register_crewai_hooks(policy: DefendPolicy | None = None) -> PolicyEngine:
    """Register Pentis Defend hooks with CrewAI's global hook system.

    Returns the PolicyEngine for inspection (violations log, etc.).

    Raises:
        ImportError: If crewai is not installed.
    """
    engine = PolicyEngine(policy or default_policy())

    # Import crewai hooks (optional dependency)
    import crewai.hooks as _hooks  # type: ignore[import-untyped]

    _hooks_any: Any = _hooks
    before_tool_call_dec = cast(Callable[..., Any], _hooks_any.before_tool_call)
    after_tool_call_dec = cast(Callable[..., Any], _hooks_any.after_tool_call)
    before_llm_call_dec = cast(Callable[..., Any], _hooks_any.before_llm_call)

    @before_tool_call_dec
    def pentis_check_tool(context: Any) -> bool | None:
        tool_name: str = str(getattr(context, "tool_name", ""))
        arguments: dict[str, Any] | None = getattr(context, "arguments", None)
        decision = engine.check_tool(tool_name, arguments)
        if not decision.allowed:
            return False  # Block execution
        return None  # Allow

    @after_tool_call_dec
    def pentis_check_tool_output(context: Any) -> str | None:
        # Check tool output for sensitive data leakage
        result: Any = getattr(context, "result", None)
        if result is not None:
            decision = engine.check_content(str(result), is_input=False)
            if not decision.allowed:
                return REDACTED_MESSAGE
        return None

    @before_llm_call_dec
    def pentis_check_llm_input(context: Any) -> bool | None:
        # Check for prompt injection attempts in LLM inputs
        messages: list[Any] | None = getattr(context, "messages", None)
        if messages is not None:
            for msg in messages:
                content: str
                if isinstance(msg, dict):
                    msg_dict = cast(dict[str, str], msg)
                    content = msg_dict.get("content", "")
                else:
                    content = str(msg)
                decision = engine.check_content(content, is_input=True)
                if not decision.allowed:
                    return False
        return None

    # Suppress unused-variable warnings — decorators register the functions globally
    _ = pentis_check_tool
    _ = pentis_check_tool_output  # type: ignore[assignment]
    _ = pentis_check_llm_input  # type: ignore[assignment]

    return engine
