"""Template loader and validator."""

from __future__ import annotations

from pathlib import Path

import jsonschema
import yaml

from pentis.core.models import AttackStep, AttackTemplate, Indicator
from pentis.core.template_schema import TEMPLATE_SCHEMA

TEMPLATES_DIR = Path(__file__).parent.parent / "attacks"


class TemplateValidationError(Exception):
    """Raised when a template fails schema validation."""


class TemplateLoader:
    """Load and validate YAML attack templates."""

    def __init__(self, templates_dir: Path | None = None) -> None:
        self.templates_dir = templates_dir or TEMPLATES_DIR

    def load_all(self) -> list[AttackTemplate]:
        """Load all templates from the templates directory."""
        templates: list[AttackTemplate] = []
        for yaml_file in sorted(self.templates_dir.rglob("*.yaml")):
            try:
                template = self.load_file(yaml_file)
                templates.append(template)
            except (TemplateValidationError, yaml.YAMLError) as e:
                raise TemplateValidationError(f"Error loading {yaml_file}: {e}") from e
        return templates

    def load_file(self, path: Path) -> AttackTemplate:
        """Load and validate a single template file."""
        with open(path) as f:
            data = yaml.safe_load(f)
        self.validate(data, path)
        return self._parse(data)

    def validate(self, data: dict, path: Path | None = None) -> None:
        """Validate template data against the schema."""
        try:
            jsonschema.validate(instance=data, schema=TEMPLATE_SCHEMA)
        except jsonschema.ValidationError as e:
            source = f" in {path}" if path else ""
            raise TemplateValidationError(f"Validation failed{source}: {e.message}") from e

    def _parse(self, data: dict) -> AttackTemplate:
        """Parse validated data into an AttackTemplate."""
        steps = [
            AttackStep(
                role=s["role"],
                content=s["content"],
                expect_refusal=s.get("expect_refusal", False),
                reset_history=s.get("reset_history", False),
            )
            for s in data["steps"]
        ]

        indicators = [
            Indicator(
                type=i["type"],
                value=i["value"],
                weight=i.get("weight", 1.0),
            )
            for i in data.get("indicators", [])
        ]

        return AttackTemplate(
            id=data["id"],
            name=data["name"],
            behavior=data["behavior"],
            severity=data["severity"],
            description=data.get("description", ""),
            owasp_id=data.get("owasp_id"),
            owasp_name=data.get("owasp_name"),
            steps=steps,
            indicators=indicators,
            metadata=data.get("metadata", {}),
        )

    def load_by_behavior(self, behavior: str) -> list[AttackTemplate]:
        """Load templates filtered by behavior category."""
        return [t for t in self.load_all() if t.behavior == behavior]

    def load_by_id(self, template_id: str) -> AttackTemplate | None:
        """Load a specific template by ID."""
        for t in self.load_all():
            if t.id == template_id:
                return t
        return None
