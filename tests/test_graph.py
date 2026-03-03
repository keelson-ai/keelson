"""Tests for tool-chain graph utilities."""

from pentis.core.graph import build_tool_chain_graph, detect_dangerous_tool_combos


class TestToolChainGraph:
    def test_build_graph_contains_agent_and_tool_edges(self):
        graph = build_tool_chain_graph(["read_file", "http_request"])
        assert "agent" in graph.nodes
        assert "read_file" in graph.nodes
        assert "http_request" in graph.nodes
        assert ("agent", "read_file") in graph.edges
        assert ("agent", "http_request") in graph.edges

    def test_detects_data_exfiltration_combo(self):
        combos = detect_dangerous_tool_combos(["read_file", "http_request"])
        assert "data_exfiltration" in combos

    def test_detects_remote_code_exec_combo(self):
        combos = detect_dangerous_tool_combos(["write_file", "os.system"])
        assert "remote_code_exec" in combos

    def test_no_combo_for_safe_tools(self):
        combos = detect_dangerous_tool_combos(["calendar_lookup", "weather"])
        assert combos == []

