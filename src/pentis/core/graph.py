"""Tool-chain graph utilities and dangerous-combo detection."""

from __future__ import annotations

import re
from dataclasses import dataclass

try:
    import networkx as nx
except Exception:  # pragma: no cover - exercised only when dependency missing
    class _MiniDiGraph:
        def __init__(self) -> None:
            self._nodes: set[str] = set()
            self._edges: set[tuple[str, str]] = set()

        @property
        def nodes(self) -> set[str]:
            return self._nodes

        @property
        def edges(self) -> set[tuple[str, str]]:
            return self._edges

        def add_node(self, node: str) -> None:
            self._nodes.add(node)

        def add_edge(self, src: str, dst: str) -> None:
            self._nodes.add(src)
            self._nodes.add(dst)
            self._edges.add((src, dst))

    class _NxCompat:
        DiGraph = _MiniDiGraph

    nx = _NxCompat()


@dataclass(frozen=True)
class DangerousComboRule:
    name: str
    left_aliases: tuple[str, ...]
    right_aliases: tuple[str, ...]
    risk: str


DANGEROUS_COMBO_RULES: tuple[DangerousComboRule, ...] = (
    DangerousComboRule(
        name="data_exfiltration",
        left_aliases=("read_file", "read", "db_query", "search", "fetch", "retrieve"),
        right_aliases=("http_request", "http", "post", "send", "webhook", "upload"),
        risk="Sensitive data can be fetched and exfiltrated out-of-band.",
    ),
    DangerousComboRule(
        name="remote_code_exec",
        left_aliases=("write_file", "save_file", "create_file"),
        right_aliases=("exec", "os.system", "subprocess", "shell"),
        risk="Agent can stage and execute attacker-influenced code.",
    ),
    DangerousComboRule(
        name="privilege_escalation_chain",
        left_aliases=("delegate", "spawn_agent", "assign_task"),
        right_aliases=("admin", "grant_role", "set_permission"),
        risk="Delegation path can elevate privileges beyond intended scope.",
    ),
)


def _normalize_tool(tool_name: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "_", tool_name.strip().lower())


def _matches_alias(tool_name: str, aliases: tuple[str, ...]) -> bool:
    normalized = _normalize_tool(tool_name)
    return any(alias in normalized for alias in aliases)


def build_tool_chain_graph(tools: list[str]) -> nx.DiGraph:
    """Build a directed graph of discovered tools."""
    graph = nx.DiGraph()
    normalized_tools = [_normalize_tool(t) for t in tools if t]

    graph.add_node("agent")
    for tool in normalized_tools:
        graph.add_node(tool)
        graph.add_edge("agent", tool)

    for left in normalized_tools:
        for right in normalized_tools:
            if left != right:
                graph.add_edge(left, right)
    return graph


def detect_dangerous_tool_combos(tools: list[str]) -> list[str]:
    """Return matched dangerous combo names based on discovered tool names."""
    normalized_tools = [_normalize_tool(t) for t in tools if t]
    matches: list[str] = []
    for rule in DANGEROUS_COMBO_RULES:
        has_left = any(_matches_alias(tool, rule.left_aliases) for tool in normalized_tools)
        has_right = any(_matches_alias(tool, rule.right_aliases) for tool in normalized_tools)
        if has_left and has_right:
            matches.append(rule.name)
    return sorted(set(matches))
