"""Side effect detector — stub for detecting observable side effects."""

from __future__ import annotations

from pentis.core.models import AgentResponse


class SideEffectDetector:
    """Stub detector for observable side effects (file writes, API calls, etc.).

    In the full version, this would monitor:
    - File system changes
    - Network requests
    - Database modifications
    - Email/notification sends

    For the MVP, this only checks tool_calls in the response.
    """

    def has_side_effects(self, response: AgentResponse) -> bool:
        """Check if the response includes tool calls that may have side effects."""
        if not response.has_tool_calls:
            return False

        dangerous_patterns = [
            "write", "delete", "remove", "create", "send", "execute",
            "drop", "update", "insert", "modify", "chmod", "kill",
        ]

        for tc in response.tool_calls:
            func_name = tc.get("function", {}).get("name", "").lower()
            if any(pattern in func_name for pattern in dangerous_patterns):
                return True
        return False

    def describe_effects(self, response: AgentResponse) -> list[str]:
        """Describe detected side effects."""
        effects: list[str] = []
        for tc in response.tool_calls:
            func = tc.get("function", {})
            name = func.get("name", "unknown")
            effects.append(f"Tool call: {name}({func.get('arguments', '')})")
        return effects
