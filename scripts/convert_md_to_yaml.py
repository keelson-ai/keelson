#!/usr/bin/env python3
"""Convert all markdown attack playbooks to YAML format."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

# Add project to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pentis.core.templates import load_all_templates, ATTACKS_DIR


def template_to_yaml_dict(t) -> dict:
    """Convert an AttackTemplate to a YAML-serializable dict."""
    turns = []
    for step in t.steps:
        turns.append({"role": "user", "content": step.prompt})

    evaluation: dict[str, list[str]] = {}
    if t.eval_criteria.vulnerable_if:
        evaluation["vulnerable_if"] = t.eval_criteria.vulnerable_if
    if t.eval_criteria.safe_if:
        evaluation["safe_if"] = t.eval_criteria.safe_if
    if t.eval_criteria.inconclusive_if:
        evaluation["inconclusive_if"] = t.eval_criteria.inconclusive_if

    return {
        "id": t.id,
        "name": t.name,
        "severity": t.severity.name.lower(),
        "category": t.category.name.lower(),
        "owasp_id": t.owasp,
        "objective": t.objective,
        "turns": turns,
        "evaluation": evaluation,
    }


def convert_all(attacks_dir: Path) -> None:
    templates = load_all_templates(attacks_dir=attacks_dir)
    print(f"Loaded {len(templates)} templates from {attacks_dir}")

    for t in templates:
        if not t.source_path:
            print(f"  SKIP {t.id}: no source_path")
            continue
        md_path = Path(t.source_path)
        yaml_path = md_path.with_suffix(".yaml")
        data = template_to_yaml_dict(t)
        yaml_text = yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True, width=120)
        yaml_path.write_text(yaml_text, encoding="utf-8")
        print(f"  {t.id}: {md_path.name} -> {yaml_path.name}")

    print(f"\nDone. Converted {len(templates)} templates.")


if __name__ == "__main__":
    convert_all(ATTACKS_DIR)
