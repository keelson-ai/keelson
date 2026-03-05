"""Tests for Pentis Defend CrewAI hooks."""

from __future__ import annotations

import sys
import types
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock

import pytest

from pentis.defend.models import ContentRule, DefendPolicy, PolicyAction, ToolRule


@pytest.fixture()
def mock_crewai_hooks() -> Generator[types.ModuleType, None, None]:
    """Create a mock crewai.hooks module with decorator-based hooks."""
    hooks_module = types.ModuleType("crewai.hooks")
    crewai_module = types.ModuleType("crewai")

    # Track registered hooks
    registered: dict[str, list[Any]] = {
        "before_tool_call": [],
        "after_tool_call": [],
        "before_llm_call": [],
    }

    def make_decorator(name: str) -> Any:
        def decorator(fn: Any) -> Any:
            registered[name].append(fn)
            return fn

        return decorator

    hooks_module.before_tool_call = make_decorator("before_tool_call")  # type: ignore[attr-defined]
    hooks_module.after_tool_call = make_decorator("after_tool_call")  # type: ignore[attr-defined]
    hooks_module.before_llm_call = make_decorator("before_llm_call")  # type: ignore[attr-defined]
    hooks_module.after_llm_call = make_decorator("after_llm_call")  # type: ignore[attr-defined]
    hooks_module._registered = registered  # type: ignore[attr-defined]

    crewai_module.hooks = hooks_module  # type: ignore[attr-defined]
    sys.modules["crewai"] = crewai_module
    sys.modules["crewai.hooks"] = hooks_module

    yield hooks_module

    # Cleanup
    sys.modules.pop("crewai", None)
    sys.modules.pop("crewai.hooks", None)


class TestRegisterCrewAIHooks:
    """Test CrewAI hook registration."""

    def test_registers_hooks(self, mock_crewai_hooks: types.ModuleType) -> None:
        from pentis.defend.crewai_hook import register_crewai_hooks

        engine = register_crewai_hooks()
        registered: dict[str, list[Any]] = mock_crewai_hooks._registered  # type: ignore[attr-defined]
        assert len(registered["before_tool_call"]) >= 1
        assert len(registered["after_tool_call"]) >= 1
        assert len(registered["before_llm_call"]) >= 1
        assert engine is not None

    def test_blocked_tool_returns_false(self, mock_crewai_hooks: types.ModuleType) -> None:
        from pentis.defend.crewai_hook import register_crewai_hooks

        policy = DefendPolicy(
            tool_rules=[ToolRule(pattern="dangerous_tool", action=PolicyAction.DENY)]
        )
        register_crewai_hooks(policy=policy)

        registered: dict[str, list[Any]] = mock_crewai_hooks._registered  # type: ignore[attr-defined]
        before_tool: Any = registered["before_tool_call"][-1]

        context = MagicMock()
        context.tool_name = "dangerous_tool"
        context.arguments = {}
        result: bool | None = before_tool(context)
        assert result is False

    def test_allowed_tool_returns_none(self, mock_crewai_hooks: types.ModuleType) -> None:
        from pentis.defend.crewai_hook import register_crewai_hooks

        policy = DefendPolicy(
            tool_rules=[ToolRule(pattern="dangerous_tool", action=PolicyAction.DENY)]
        )
        register_crewai_hooks(policy=policy)

        registered: dict[str, list[Any]] = mock_crewai_hooks._registered  # type: ignore[attr-defined]
        before_tool: Any = registered["before_tool_call"][-1]

        context = MagicMock()
        context.tool_name = "safe_tool"
        result: bool | None = before_tool(context)
        assert result is None

    def test_output_redaction(self, mock_crewai_hooks: types.ModuleType) -> None:
        from pentis.defend.crewai_hook import register_crewai_hooks

        register_crewai_hooks()

        registered: dict[str, list[Any]] = mock_crewai_hooks._registered  # type: ignore[attr-defined]
        after_tool: Any = registered["after_tool_call"][-1]

        context = MagicMock()
        context.result = '{"tool_calls": [{"name": "execute"}]}'
        result: str | None = after_tool(context)
        assert result == "[REDACTED by Pentis Defend]"

    def test_llm_input_blocking(self, mock_crewai_hooks: types.ModuleType) -> None:
        from pentis.defend.crewai_hook import register_crewai_hooks

        policy = DefendPolicy(
            content_rules=[
                ContentRule(
                    pattern="INJECT",
                    action=PolicyAction.DENY,
                    reason="Injection",
                    check_input=True,
                    check_output=True,
                )
            ]
        )
        register_crewai_hooks(policy=policy)

        registered: dict[str, list[Any]] = mock_crewai_hooks._registered  # type: ignore[attr-defined]
        before_llm: Any = registered["before_llm_call"][-1]

        context = MagicMock()
        context.messages = [{"role": "user", "content": "Please INJECT this command"}]
        result: bool | None = before_llm(context)
        assert result is False
