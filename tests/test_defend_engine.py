"""Tests for Pentis Defend PolicyEngine."""

from __future__ import annotations

from pentis.defend.engine import PolicyEngine
from pentis.defend.loader import default_policy
from pentis.defend.models import (
    ContentRule,
    DefendPolicy,
    PolicyAction,
    ToolRule,
)


class TestDefaultPolicyToolRules:
    """Test the default policy blocks/allows/logs the right tools."""

    def test_blocks_dangerous_tools(self) -> None:
        engine = PolicyEngine(default_policy())
        for tool in ["delete_file", "delete_users", "drop_table", "rm_rf", "exec_cmd", "eval_code"]:
            decision = engine.check_tool(tool)
            assert not decision.allowed, f"Expected '{tool}' to be blocked"

    def test_allows_safe_tools(self) -> None:
        engine = PolicyEngine(default_policy())
        for tool in ["search", "read_file", "calculator", "get_weather"]:
            decision = engine.check_tool(tool)
            assert decision.allowed, f"Expected '{tool}' to be allowed"

    def test_logs_sensitive_tools(self) -> None:
        engine = PolicyEngine(default_policy())
        decision = engine.check_tool("send_email")
        assert decision.allowed
        assert decision.rule == "send_email"
        assert len(engine.violations) == 1
        assert engine.violations[0].action == PolicyAction.LOG


class TestCustomToolRules:
    """Test custom tool rules."""

    def test_custom_deny(self) -> None:
        policy = DefendPolicy(
            tool_rules=[ToolRule(pattern="my_tool", action=PolicyAction.DENY, reason="nope")]
        )
        engine = PolicyEngine(policy)
        decision = engine.check_tool("my_tool")
        assert not decision.allowed
        assert decision.reason == "nope"

    def test_custom_allow_override(self) -> None:
        policy = DefendPolicy(
            tool_rules=[
                ToolRule(
                    pattern="delete_file", action=PolicyAction.ALLOW, reason="explicitly allowed"
                ),
            ]
        )
        engine = PolicyEngine(policy)
        decision = engine.check_tool("delete_file")
        assert decision.allowed

    def test_glob_pattern_matching(self) -> None:
        policy = DefendPolicy(tool_rules=[ToolRule(pattern="delete_*", action=PolicyAction.DENY)])
        engine = PolicyEngine(policy)
        assert not engine.check_tool("delete_users").allowed
        assert not engine.check_tool("delete_all_data").allowed
        assert engine.check_tool("get_deleted_items").allowed

    def test_empty_policy_allows_all(self) -> None:
        policy = DefendPolicy()
        engine = PolicyEngine(policy)
        for tool in ["delete_file", "exec_cmd", "anything"]:
            assert engine.check_tool(tool).allowed


class TestContentRules:
    """Test content rule matching."""

    def test_blocks_secrets(self) -> None:
        engine = PolicyEngine(default_policy())
        decision = engine.check_content("API_KEY = sk-abc123", is_input=True)
        assert not decision.allowed

    def test_allows_normal_content(self) -> None:
        engine = PolicyEngine(default_policy())
        decision = engine.check_content("Hello, how can I help you?", is_input=True)
        assert decision.allowed

    def test_side_effect_patterns_on_output(self) -> None:
        engine = PolicyEngine(default_policy())
        output_with_tool_call = '{"tool_calls": [{"name": "execute", "args": {}}]}'
        decision = engine.check_content(output_with_tool_call, is_input=False)
        assert not decision.allowed

    def test_side_effect_patterns_not_checked_on_input(self) -> None:
        engine = PolicyEngine(default_policy())
        # Side-effect patterns are only checked on output
        content = '{"tool_calls": [{"name": "execute"}]}'
        decision = engine.check_content(content, is_input=True)
        # Should be allowed since side-effect patterns only apply to output
        # (unless a content rule matches)
        assert decision.allowed

    def test_custom_content_rule(self) -> None:
        policy = DefendPolicy(
            content_rules=[
                ContentRule(
                    pattern=r"CONFIDENTIAL",
                    action=PolicyAction.DENY,
                    reason="Confidential data",
                )
            ]
        )
        engine = PolicyEngine(policy)
        assert not engine.check_content("This is CONFIDENTIAL info").allowed
        assert engine.check_content("This is public info").allowed

    def test_content_rule_input_only(self) -> None:
        policy = DefendPolicy(
            content_rules=[
                ContentRule(
                    pattern=r"INJECTION",
                    action=PolicyAction.DENY,
                    check_input=True,
                    check_output=False,
                )
            ]
        )
        engine = PolicyEngine(policy)
        assert not engine.check_content("INJECTION attempt", is_input=True).allowed
        assert engine.check_content("INJECTION attempt", is_input=False).allowed


class TestViolationLogging:
    """Test that violations are properly recorded."""

    def test_violations_logged_on_deny(self) -> None:
        engine = PolicyEngine(default_policy())
        engine.check_tool("delete_file")
        assert len(engine.violations) == 1
        v = engine.violations[0]
        assert v.tool_name == "delete_file"
        assert v.action == PolicyAction.DENY
        assert v.timestamp  # non-empty ISO timestamp

    def test_violations_logged_on_log_action(self) -> None:
        engine = PolicyEngine(default_policy())
        engine.check_tool("send_email")
        assert len(engine.violations) == 1
        assert engine.violations[0].action == PolicyAction.LOG

    def test_multiple_violations_accumulated(self) -> None:
        engine = PolicyEngine(default_policy())
        engine.check_tool("delete_file")
        engine.check_tool("drop_table")
        engine.check_tool("send_email")
        assert len(engine.violations) == 3

    def test_violations_returns_copy(self) -> None:
        engine = PolicyEngine(default_policy())
        engine.check_tool("delete_file")
        v1 = engine.violations
        v2 = engine.violations
        assert v1 is not v2
        assert v1 == v2


class TestSideEffectTwoTierLogic:
    """Tests for the wrapper + tool name two-tier side-effect detection."""

    def test_tool_name_enumeration_in_output_allowed(self):
        """Agent listing tool names without a wrapper should be allowed."""
        engine = PolicyEngine(default_policy())
        output = (
            'My tools: [{"name": "read_file"}, {"name": "write_file"}, {"name": "execute_query"}]'
        )
        decision = engine.check_content(output, is_input=False)
        assert decision.allowed

    def test_wrapper_with_dangerous_name_denied(self):
        """Real tool call with wrapper + dangerous name is denied."""
        engine = PolicyEngine(default_policy())
        output = '{"tool_calls": [{"name": "delete_file", "args": {}}]}'
        decision = engine.check_content(output, is_input=False)
        assert not decision.allowed

    def test_wrapper_only_no_dangerous_name_denied(self):
        """Wrapper alone (benign tool name) is still denied."""
        engine = PolicyEngine(default_policy())
        output = '{"function_call": {"name": "get_time"}}'
        decision = engine.check_content(output, is_input=False)
        assert not decision.allowed
        assert "wrapper" in decision.reason.lower()

    def test_wrapper_violation_logged(self):
        """Side-effect denial should record a violation."""
        engine = PolicyEngine(default_policy())
        output = '{"tool_calls": [{"name": "shell", "cmd": "ls"}]}'
        engine.check_content(output, is_input=False)
        assert len(engine.violations) >= 1
        assert engine.violations[-1].action == PolicyAction.DENY


class TestContentAllowShortCircuit:
    """Content ALLOW rules must short-circuit and skip later DENY rules."""

    def test_allow_rule_prevents_subsequent_deny(self) -> None:
        """An ALLOW content rule should short-circuit before a DENY rule fires."""
        policy = DefendPolicy(
            tool_rules=[],
            content_rules=[
                ContentRule(
                    pattern="password",
                    action=PolicyAction.ALLOW,
                    reason="Explicitly allowed",
                    check_input=True,
                    check_output=True,
                ),
                ContentRule(
                    pattern="password",
                    action=PolicyAction.DENY,
                    reason="Should never fire",
                    check_input=True,
                    check_output=True,
                ),
            ],
            default_tool_action=PolicyAction.ALLOW,
            log_all=False,
        )
        engine = PolicyEngine(policy)
        decision = engine.check_content("my password is secret")
        assert decision.allowed is True
        assert decision.rule == "password"
        assert decision.reason == "Explicitly allowed"

    def test_allow_rule_skips_side_effect_check_for_output(self) -> None:
        """An ALLOW content rule on output should short-circuit side-effect detection."""
        policy = DefendPolicy(
            tool_rules=[],
            content_rules=[
                ContentRule(
                    pattern="function_call",
                    action=PolicyAction.ALLOW,
                    reason="Allowed for this context",
                    check_input=True,
                    check_output=True,
                ),
            ],
            default_tool_action=PolicyAction.ALLOW,
            log_all=False,
        )
        engine = PolicyEngine(policy)
        decision = engine.check_content('"function_call"', is_input=False)
        assert decision.allowed is True
