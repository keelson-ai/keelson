"""YAML policy loader for Keelson Defend."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from keelson.defend.models import ContentRule, DefendPolicy, PolicyAction, ToolRule


def load_policy(path: str | Path) -> DefendPolicy:
    """Load a DefendPolicy from a YAML file.

    Expected YAML structure::

        tools:
          - pattern: "delete_*"
            action: deny
            reason: "Destructive operations blocked"
          - pattern: "send_email"
            action: log
        content:
          - pattern: "API_KEY|SECRET|PASSWORD"
            action: deny
            reason: "Sensitive data detected"
        defaults:
          tool_action: allow
          log_all: false
    """
    path = Path(path)
    raw: dict[str, Any] = yaml.safe_load(path.read_text()) or {}

    tool_rules: list[ToolRule] = []
    for item in raw.get("tools", []):
        tool_rules.append(
            ToolRule(
                pattern=str(item.get("pattern", "")),
                action=PolicyAction(str(item.get("action", "deny")).lower()),
                reason=str(item.get("reason", "")),
            )
        )

    content_rules: list[ContentRule] = []
    for item in raw.get("content", []):
        content_rules.append(
            ContentRule(
                pattern=str(item.get("pattern", "")),
                action=PolicyAction(str(item.get("action", "deny")).lower()),
                reason=str(item.get("reason", "")),
                check_input=bool(item.get("check_input", True)),
                check_output=bool(item.get("check_output", True)),
            )
        )

    defaults: dict[str, Any] = raw.get("defaults", {})
    default_tool_action = PolicyAction(str(defaults.get("tool_action", "allow")).lower())
    log_all = bool(defaults.get("log_all", False))

    return DefendPolicy(
        tool_rules=tool_rules,
        content_rules=content_rules,
        default_tool_action=default_tool_action,
        log_all=log_all,
    )


def default_policy() -> DefendPolicy:
    """Return a sensible default policy with common dangerous tools blocked."""
    tool_rules = [
        # Block destructive operations
        ToolRule(pattern="delete_*", action=PolicyAction.DENY, reason="Destructive operation"),
        ToolRule(pattern="drop_*", action=PolicyAction.DENY, reason="Destructive operation"),
        ToolRule(pattern="rm_*", action=PolicyAction.DENY, reason="Destructive operation"),
        ToolRule(pattern="remove_*", action=PolicyAction.DENY, reason="Destructive operation"),
        # Block code execution
        ToolRule(pattern="system_*", action=PolicyAction.DENY, reason="System command execution"),
        ToolRule(pattern="exec_*", action=PolicyAction.DENY, reason="Code execution"),
        ToolRule(pattern="eval_*", action=PolicyAction.DENY, reason="Code evaluation"),
        ToolRule(pattern="execute_*", action=PolicyAction.DENY, reason="Code execution"),
        # Log sensitive operations
        ToolRule(pattern="send_email", action=PolicyAction.LOG, reason="Email sending"),
        ToolRule(pattern="send_message", action=PolicyAction.LOG, reason="Message sending"),
        ToolRule(pattern="http_request", action=PolicyAction.LOG, reason="HTTP request"),
        ToolRule(pattern="charge_payment", action=PolicyAction.LOG, reason="Payment operation"),
    ]

    content_rules = [
        ContentRule(
            pattern=r"(?:API_KEY|SECRET_KEY|PASSWORD|PRIVATE_KEY|ACCESS_TOKEN)\s*[=:]\s*\S+",
            action=PolicyAction.DENY,
            reason="Sensitive credential detected",
        ),
        ContentRule(
            pattern=r"(?:Bearer\s+[A-Za-z0-9\-._~+/]+=*)",
            action=PolicyAction.DENY,
            reason="Bearer token detected",
        ),
    ]

    return DefendPolicy(
        tool_rules=tool_rules,
        content_rules=content_rules,
        default_tool_action=PolicyAction.ALLOW,
        log_all=False,
    )
