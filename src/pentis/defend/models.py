"""Policy models for Pentis Defend runtime security hooks."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


BLOCKED_MESSAGE = "[BLOCKED by Pentis Defend]"
REDACTED_MESSAGE = "[REDACTED by Pentis Defend]"


class PolicyAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    LOG = "log"  # allow but log warning


@dataclass
class ToolRule:
    """Rule for a specific tool or tool pattern."""

    pattern: str  # tool name or glob pattern (e.g. "delete_*", "send_email")
    action: PolicyAction = PolicyAction.DENY
    reason: str = ""


@dataclass
class ContentRule:
    """Rule for content pattern matching in LLM inputs/outputs."""

    pattern: str  # regex pattern to match
    action: PolicyAction = PolicyAction.DENY
    reason: str = ""
    check_input: bool = True
    check_output: bool = True


@dataclass
class DefendPolicy:
    """Complete defend policy configuration."""

    tool_rules: list[ToolRule] = field(default_factory=lambda: list[ToolRule]())
    content_rules: list[ContentRule] = field(default_factory=lambda: list[ContentRule]())
    default_tool_action: PolicyAction = PolicyAction.ALLOW
    log_all: bool = False
