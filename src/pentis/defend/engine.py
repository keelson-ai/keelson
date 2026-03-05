"""Core policy evaluation engine for Pentis Defend."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from pentis.core.detection import DANGEROUS_TOOL_NAMES, TOOL_CALL_WRAPPERS
from pentis.defend.models import ContentRule, DefendPolicy, PolicyAction

# Pre-compile side-effect patterns at module level (they never change)
_COMPILED_WRAPPERS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in TOOL_CALL_WRAPPERS
]
_COMPILED_TOOL_NAMES: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in DANGEROUS_TOOL_NAMES
]


@dataclass
class Violation:
    """Record of a policy violation."""

    timestamp: str  # ISO format
    tool_name: str | None
    content_snippet: str | None
    rule: str
    action: PolicyAction


@dataclass
class PolicyDecision:
    """Result of a policy check."""

    allowed: bool
    rule: str | None = None
    reason: str = ""


class PolicyEngine:
    """Evaluate tool calls and content against a DefendPolicy."""

    def __init__(self, policy: DefendPolicy) -> None:
        self._policy = policy
        self._violations: list[Violation] = []
        # Pre-compile content rule patterns
        self._compiled_content: list[tuple[ContentRule, re.Pattern[str]]] = []
        for rule in policy.content_rules:
            self._compiled_content.append((rule, re.compile(rule.pattern, re.IGNORECASE)))

    def check_tool(self, tool_name: str, arguments: dict[str, Any] | None = None) -> PolicyDecision:
        """Check if a tool call is allowed by policy."""
        _ = arguments  # reserved for future argument-level rules

        for rule in self._policy.tool_rules:
            if fnmatch.fnmatch(tool_name, rule.pattern):
                allowed = rule.action == PolicyAction.ALLOW
                is_log = rule.action == PolicyAction.LOG

                if not allowed and not is_log:
                    self._record_violation(
                        tool_name=tool_name,
                        content_snippet=None,
                        rule=f"tool:{rule.pattern}",
                        action=rule.action,
                    )
                    return PolicyDecision(
                        allowed=False,
                        rule=rule.pattern,
                        reason=rule.reason
                        or f"Tool '{tool_name}' blocked by rule '{rule.pattern}'",
                    )

                if is_log:
                    self._record_violation(
                        tool_name=tool_name,
                        content_snippet=None,
                        rule=f"tool:{rule.pattern}",
                        action=PolicyAction.LOG,
                    )
                    return PolicyDecision(
                        allowed=True,
                        rule=rule.pattern,
                        reason=rule.reason or f"Tool '{tool_name}' logged by rule '{rule.pattern}'",
                    )

                # Explicit ALLOW
                return PolicyDecision(allowed=True, rule=rule.pattern, reason=rule.reason)

        # No rule matched — use default action
        default_allowed = self._policy.default_tool_action != PolicyAction.DENY
        if self._policy.log_all:
            self._record_violation(
                tool_name=tool_name,
                content_snippet=None,
                rule="default:log_all",
                action=PolicyAction.LOG,
            )
        return PolicyDecision(allowed=default_allowed)

    def check_content(self, content: str, is_input: bool = True) -> PolicyDecision:
        """Check content against content rules and built-in detection patterns."""
        snippet = content[:100]

        # Check content rules
        for rule, compiled in self._compiled_content:
            if is_input and not rule.check_input:
                continue
            if not is_input and not rule.check_output:
                continue
            if compiled.search(content):
                allowed = rule.action == PolicyAction.ALLOW
                is_log = rule.action == PolicyAction.LOG

                if not allowed and not is_log:
                    self._record_violation(
                        tool_name=None,
                        content_snippet=snippet,
                        rule=f"content:{rule.pattern}",
                        action=rule.action,
                    )
                    return PolicyDecision(
                        allowed=False,
                        rule=rule.pattern,
                        reason=rule.reason or f"Content matched blocked pattern '{rule.pattern}'",
                    )

                if is_log:
                    self._record_violation(
                        tool_name=None,
                        content_snippet=snippet,
                        rule=f"content:{rule.pattern}",
                        action=PolicyAction.LOG,
                    )
                    return PolicyDecision(allowed=True, rule=rule.pattern, reason=rule.reason)

                # Explicit ALLOW — short-circuit, skip further rules
                return PolicyDecision(allowed=True, rule=rule.pattern, reason=rule.reason)

        # For outputs, check side-effect patterns from detection.py.
        # Only match dangerous tool names when a tool call wrapper is present.
        if not is_input:
            has_wrapper = any(p.search(content) for p in _COMPILED_WRAPPERS)
            if has_wrapper:
                for pattern in _COMPILED_TOOL_NAMES:
                    if pattern.search(content):
                        self._record_violation(
                            tool_name=None,
                            content_snippet=snippet,
                            rule=f"side_effect:{pattern.pattern}",
                            action=PolicyAction.DENY,
                        )
                        return PolicyDecision(
                            allowed=False,
                            rule=pattern.pattern,
                            reason=f"Output matched side-effect pattern: {pattern.pattern}",
                        )
                # Wrapper alone is still suspicious
                wrapper_pat = next(p for p in _COMPILED_WRAPPERS if p.search(content))
                self._record_violation(
                    tool_name=None,
                    content_snippet=snippet,
                    rule=f"side_effect:{wrapper_pat.pattern}",
                    action=PolicyAction.DENY,
                )
                return PolicyDecision(
                    allowed=False,
                    rule=wrapper_pat.pattern,
                    reason=f"Output matched tool call wrapper: {wrapper_pat.pattern}",
                )

        return PolicyDecision(allowed=True)

    @property
    def violations(self) -> list[Violation]:
        """Return a copy of all recorded violations."""
        return list(self._violations)

    def _record_violation(
        self,
        tool_name: str | None,
        content_snippet: str | None,
        rule: str,
        action: PolicyAction,
    ) -> None:
        self._violations.append(
            Violation(
                timestamp=datetime.now(timezone.utc).isoformat(),
                tool_name=tool_name,
                content_snippet=content_snippet,
                rule=rule,
                action=action,
            )
        )
