"""Schema and helpers for normalized discovery capability output."""

from __future__ import annotations

from typing import Any

import jsonschema

from pentis.core.models import TargetInfo

DISCOVERY_SCHEMA_VERSION = "1.0.0"

DISCOVERY_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": [
        "schema_version",
        "url",
        "model",
        "supports_tools",
        "tools_detected",
        "supports_history",
        "response_format",
        "permissions_detected",
        "memory_detected",
        "delegation_detected",
        "dangerous_combos",
        "tool_chain_nodes",
        "tool_chain_edges",
    ],
    "properties": {
        "schema_version": {"type": "string"},
        "url": {"type": "string", "minLength": 1},
        "model": {"type": "string"},
        "supports_tools": {"type": "boolean"},
        "tools_detected": {"type": "array", "items": {"type": "string"}},
        "supports_history": {"type": "boolean"},
        "response_format": {"type": "string"},
        "system_prompt_leaked": {"type": "boolean"},
        "permissions_detected": {"type": "array", "items": {"type": "string"}},
        "memory_detected": {"type": "array", "items": {"type": "string"}},
        "delegation_detected": {"type": "array", "items": {"type": "string"}},
        "dangerous_combos": {"type": "array", "items": {"type": "string"}},
        "tool_chain_nodes": {"type": "array", "items": {"type": "string"}},
        "tool_chain_edges": {
            "type": "array",
            "items": {
                "type": "array",
                "minItems": 2,
                "maxItems": 2,
                "items": {"type": "string"},
            },
        },
    },
    "additionalProperties": False,
}


def target_info_to_dict(info: TargetInfo) -> dict[str, Any]:
    """Normalize TargetInfo to a schema-validated dict contract."""
    return {
        "schema_version": DISCOVERY_SCHEMA_VERSION,
        "url": info.url,
        "model": info.model,
        "supports_tools": info.supports_tools,
        "tools_detected": sorted(set(info.tools_detected)),
        "supports_history": info.supports_history,
        "response_format": info.response_format,
        "system_prompt_leaked": bool(info.system_prompt_leaked),
        "permissions_detected": sorted(set(info.permissions_detected)),
        "memory_detected": sorted(set(info.memory_detected)),
        "delegation_detected": sorted(set(info.delegation_detected)),
        "dangerous_combos": sorted(set(info.dangerous_combos)),
        "tool_chain_nodes": sorted(set(info.tool_chain_nodes)),
        "tool_chain_edges": [list(edge) for edge in sorted(set(info.tool_chain_edges))],
    }


def validate_discovery_payload(payload: dict[str, Any]) -> list[str]:
    """Return schema validation errors for discovery payload."""
    validator = jsonschema.Draft202012Validator(DISCOVERY_SCHEMA)
    return sorted(error.message for error in validator.iter_errors(payload))

