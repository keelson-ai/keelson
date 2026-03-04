"""Pentis Defend middleware for LangChain agents.

LangChain uses class-based AgentMiddleware with wrap_tool_call and
wrap_model_call methods.
"""

from __future__ import annotations

from typing import Any, cast

from pentis.defend.engine import PolicyEngine
from pentis.defend.loader import default_policy
from pentis.defend.models import BLOCKED_MESSAGE, REDACTED_MESSAGE, DefendPolicy


class PentisDefendMiddleware:
    """LangChain AgentMiddleware that enforces Pentis Defend policies.

    Usage::

        from pentis.defend.langchain_hook import PentisDefendMiddleware

        middleware = PentisDefendMiddleware(policy=my_policy)
        agent = create_agent(model=..., tools=..., middleware=[middleware])
    """

    def __init__(self, policy: DefendPolicy | None = None) -> None:
        self.engine = PolicyEngine(policy or default_policy())

    def wrap_tool_call(self, request: Any, handler: Any) -> Any:
        """Intercept tool calls and enforce policy."""
        tool_call: Any = getattr(request, "tool_call", None)
        tool_name: str = ""
        args: dict[str, Any] | None = None
        tool_call_id: str = ""

        if isinstance(tool_call, dict):
            tool_call_dict = cast(dict[str, Any], tool_call)
            tool_name = str(tool_call_dict.get("name", ""))
            raw_args: Any = tool_call_dict.get("args")
            if isinstance(raw_args, dict):
                args = cast(dict[str, Any], raw_args)
            tool_call_id = str(tool_call_dict.get("id", ""))
        elif tool_call is not None:
            tool_name = str(tool_call)

        decision = self.engine.check_tool(tool_name, args)
        if not decision.allowed:
            # Return a ToolMessage indicating the tool was blocked
            try:
                import langchain_core.messages as _lc_msgs  # type: ignore[import-untyped]

                _lc_any: Any = _lc_msgs
                _ToolMessage: type[Any] = _lc_any.ToolMessage
                return _ToolMessage(
                    content=f"{BLOCKED_MESSAGE} {decision.reason}",
                    tool_call_id=tool_call_id,
                )
            except ImportError:
                # Fallback: return a dict if langchain_core is not available
                return {
                    "content": f"{BLOCKED_MESSAGE} {decision.reason}",
                    "tool_call_id": tool_call_id,
                }

        result: Any = handler(request)

        # Check output for sensitive data
        content: str = str(getattr(result, "content", result))
        output_decision = self.engine.check_content(content, is_input=False)
        if not output_decision.allowed:
            if hasattr(result, "content"):
                result.content = REDACTED_MESSAGE

        return result

    def wrap_model_call(self, request: Any, handler: Any) -> Any:
        """Intercept LLM calls and check inputs for injection patterns."""
        messages: list[Any] | None = getattr(request, "messages", None)
        if messages is not None:
            for msg in messages:
                content: str
                if isinstance(msg, dict):
                    msg_dict = cast(dict[str, str], msg)
                    content = msg_dict.get("content", "")
                else:
                    content = str(getattr(msg, "content", msg))
                decision = self.engine.check_content(content, is_input=True)
                if not decision.allowed:
                    # Block the model call by returning a minimal response
                    try:
                        import langchain_core.messages as _lc_msgs  # type: ignore[import-untyped]

                        _lc_any2: Any = _lc_msgs
                        _AIMessage: type[Any] = _lc_any2.AIMessage
                        return _AIMessage(content=f"{BLOCKED_MESSAGE} {decision.reason}")
                    except ImportError:
                        return {"content": f"{BLOCKED_MESSAGE} {decision.reason}"}

        return handler(request)
