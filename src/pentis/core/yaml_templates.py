"""YAML attack template loader — parallel format to the existing Markdown parser."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from pentis.core.models import AttackStep, AttackTemplate, Category, EvalCriteria, Severity


def _build_category_map() -> dict[str, Category]:
    """Derive category map from Category enum — snake_case and kebab-case keys."""
    m: dict[str, Category] = {}
    for cat in Category:
        snake = cat.name.lower()
        kebab = snake.replace("_", "-")
        m[snake] = cat
        m[kebab] = cat
    return m


CATEGORY_MAP: dict[str, Category] = _build_category_map()

SEVERITY_MAP: dict[str, Severity] = {s.name.lower(): s for s in Severity}

_REQUIRED = ("id", "name", "severity", "category", "owasp_id", "objective", "turns", "evaluation")


def validate_yaml_template(data: dict[str, Any]) -> None:
    """Raise ValueError if required fields are missing or invalid."""
    for field in _REQUIRED:
        if field not in data:
            raise ValueError(f"YAML template missing required field: '{field}'")
    if data["severity"].lower() not in SEVERITY_MAP:
        raise ValueError(f"Unknown severity: {data['severity']!r}")
    if data["category"].lower() not in CATEGORY_MAP:
        raise ValueError(f"Unknown category: {data['category']!r}")


def load_yaml_template(path: Path) -> AttackTemplate:
    """Parse a YAML attack template file into an AttackTemplate."""
    text = path.read_text(encoding="utf-8")
    data: dict[str, Any] = yaml.safe_load(text)
    validate_yaml_template(data)

    steps: list[AttackStep] = []
    for i, turn in enumerate(data["turns"]):
        new_session = bool(turn.get("new_session", False))
        role = str(turn.get("role", "user"))
        steps.append(
            AttackStep(
                index=i + 1,
                prompt=str(turn["content"]),
                is_followup=i > 0,
                new_session=new_session,
                role=role,
            )
        )

    ev = data["evaluation"]
    eval_criteria = EvalCriteria(
        vulnerable_if=list(ev.get("vulnerable_if", [])),
        safe_if=list(ev.get("safe_if", [])),
        inconclusive_if=list(ev.get("inconclusive_if", [])),
    )

    return AttackTemplate(
        id=str(data["id"]),
        name=str(data["name"]),
        severity=SEVERITY_MAP[data["severity"].lower()],
        category=CATEGORY_MAP[data["category"].lower()],
        owasp=str(data["owasp_id"]),
        objective=str(data["objective"]),
        steps=steps,
        eval_criteria=eval_criteria,
        source_path=str(path),
    )


def load_yaml_templates_dir(directory: Path) -> list[AttackTemplate]:
    """Load all *.yaml templates from a directory tree."""
    templates: list[AttackTemplate] = []
    for path in sorted(directory.rglob("*.yaml")):
        templates.append(load_yaml_template(path))
    return templates
