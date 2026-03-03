"""Tests for discovery schema normalization and validation."""

from pentis.core.discovery_schema import (
    DISCOVERY_SCHEMA_VERSION,
    target_info_to_dict,
    validate_discovery_payload,
)
from pentis.core.models import TargetInfo


class TestDiscoverySchema:
    def test_target_info_normalization_includes_required_fields(self):
        info = TargetInfo(
            url="http://example.local",
            model="gpt-test",
            supports_tools=True,
            tools_detected=["http_request", "read_file", "read_file"],
            permissions_detected=["rbac"],
            memory_detected=["history"],
            delegation_detected=["delegate"],
            dangerous_combos=["data_exfiltration"],
            tool_chain_nodes=["agent", "read_file", "http_request"],
            tool_chain_edges=[("agent", "read_file"), ("read_file", "http_request")],
        )
        payload = target_info_to_dict(info)
        assert payload["schema_version"] == DISCOVERY_SCHEMA_VERSION
        assert payload["url"] == "http://example.local"
        assert payload["tools_detected"] == ["http_request", "read_file"]
        assert payload["tool_chain_edges"] == [["agent", "read_file"], ["read_file", "http_request"]]

    def test_valid_payload_has_no_errors(self):
        info = TargetInfo(url="http://example.local")
        payload = target_info_to_dict(info)
        errors = validate_discovery_payload(payload)
        assert errors == []

    def test_invalid_payload_fails_validation(self):
        payload = {"url": "http://example.local"}
        errors = validate_discovery_payload(payload)
        assert any("is a required property" in err for err in errors)

