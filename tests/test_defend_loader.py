"""Tests for Pentis Defend YAML policy loader."""

from __future__ import annotations

import tempfile
from pathlib import Path

from pentis.defend.loader import default_policy, load_policy
from pentis.defend.models import PolicyAction


class TestLoadPolicy:
    """Test YAML policy loading."""

    def test_load_policy_from_yaml(self) -> None:
        yaml_content = """
tools:
  - pattern: "delete_*"
    action: deny
    reason: "No deletes"
  - pattern: "send_email"
    action: log
content:
  - pattern: "SECRET"
    action: deny
    reason: "Secret detected"
defaults:
  tool_action: allow
  log_all: false
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            policy = load_policy(f.name)

        assert len(policy.tool_rules) == 2
        assert policy.tool_rules[0].pattern == "delete_*"
        assert policy.tool_rules[0].action == PolicyAction.DENY
        assert policy.tool_rules[0].reason == "No deletes"
        assert policy.tool_rules[1].pattern == "send_email"
        assert policy.tool_rules[1].action == PolicyAction.LOG

        assert len(policy.content_rules) == 1
        assert policy.content_rules[0].pattern == "SECRET"

        assert policy.default_tool_action == PolicyAction.ALLOW
        assert policy.log_all is False

        Path(f.name).unlink()

    def test_yaml_with_all_fields(self) -> None:
        yaml_content = """
tools:
  - pattern: "tool_a"
    action: allow
    reason: "Allowed"
  - pattern: "tool_b"
    action: deny
    reason: "Denied"
  - pattern: "tool_c"
    action: log
    reason: "Logged"
content:
  - pattern: "PATTERN_A"
    action: deny
    reason: "Blocked"
    check_input: true
    check_output: false
  - pattern: "PATTERN_B"
    action: log
    reason: "Logged"
    check_input: false
    check_output: true
defaults:
  tool_action: deny
  log_all: true
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            policy = load_policy(f.name)

        assert len(policy.tool_rules) == 3
        assert len(policy.content_rules) == 2
        assert policy.content_rules[0].check_input is True
        assert policy.content_rules[0].check_output is False
        assert policy.content_rules[1].check_input is False
        assert policy.content_rules[1].check_output is True
        assert policy.default_tool_action == PolicyAction.DENY
        assert policy.log_all is True

        Path(f.name).unlink()

    def test_load_empty_yaml(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("{}\n")
            f.flush()
            policy = load_policy(f.name)

        assert len(policy.tool_rules) == 0
        assert len(policy.content_rules) == 0
        assert policy.default_tool_action == PolicyAction.ALLOW

        Path(f.name).unlink()


class TestDefaultPolicy:
    """Test the built-in default policy."""

    def test_default_policy_has_rules(self) -> None:
        policy = default_policy()
        assert len(policy.tool_rules) > 0
        assert len(policy.content_rules) > 0

    def test_default_policy_has_deny_rules(self) -> None:
        policy = default_policy()
        deny_rules = [r for r in policy.tool_rules if r.action == PolicyAction.DENY]
        assert len(deny_rules) > 0

    def test_default_policy_has_log_rules(self) -> None:
        policy = default_policy()
        log_rules = [r for r in policy.tool_rules if r.action == PolicyAction.LOG]
        assert len(log_rules) > 0
