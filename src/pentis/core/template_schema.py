"""JSON Schema for YAML attack templates."""

TEMPLATE_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["id", "name", "behavior", "severity", "steps"],
    "properties": {
        "id": {
            "type": "string",
            "pattern": "^[A-Z]{2}-\\d{3}$",
            "description": "Template ID (e.g., GA-001, TS-002, MI-003)",
        },
        "name": {
            "type": "string",
            "minLength": 3,
            "maxLength": 100,
        },
        "behavior": {
            "type": "string",
            "enum": ["goal_adherence", "tool_safety", "memory_integrity"],
        },
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low", "info"],
        },
        "description": {
            "type": "string",
        },
        "owasp_id": {
            "type": "string",
            "description": "OWASP Top 10 for LLMs ID (e.g., LLM01)",
        },
        "owasp_name": {
            "type": "string",
            "description": "OWASP vulnerability name",
        },
        "steps": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["role", "content"],
                "properties": {
                    "role": {
                        "type": "string",
                        "enum": ["user", "system"],
                    },
                    "content": {
                        "type": "string",
                        "minLength": 1,
                    },
                    "expect_refusal": {
                        "type": "boolean",
                        "default": False,
                    },
                    "reset_history": {
                        "type": "boolean",
                        "default": False,
                    },
                },
            },
        },
        "indicators": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["type", "value"],
                "properties": {
                    "type": {
                        "type": "string",
                        "enum": ["word", "regex", "absence"],
                    },
                    "value": {
                        "type": "string",
                        "minLength": 1,
                    },
                    "weight": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 10,
                        "default": 1.0,
                    },
                },
            },
        },
        "metadata": {
            "type": "object",
            "properties": {
                "author": {"type": "string"},
                "references": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
        },
    },
}
