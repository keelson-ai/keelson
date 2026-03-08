"""YAML probe template loader — parallel format to the existing Markdown parser."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, cast

import yaml

from keelson.core.models import (
    Category,
    EvalCriteria,
    Finding,
    ProbeStep,
    ProbeTemplate,
    Severity,
    Verdict,
)

logger = logging.getLogger(__name__)


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


def load_yaml_template(path: Path) -> ProbeTemplate:
    """Parse a YAML probe template file into an ProbeTemplate."""
    text = path.read_text(encoding="utf-8")
    raw: object = yaml.safe_load(text)
    if not isinstance(raw, dict):
        raise ValueError(f"YAML template must be a mapping, got {type(raw).__name__} in {path}")
    data: dict[str, Any] = cast(dict[str, Any], raw)
    try:
        validate_yaml_template(data)
    except ValueError as exc:
        raise ValueError(f"Invalid template {path}: {exc}") from exc

    turns_raw: object = data["turns"]
    if not isinstance(turns_raw, list):
        raise ValueError(f"'turns' must be a list in {path}, got {type(turns_raw).__name__}")
    turns = cast(list[dict[str, Any]], turns_raw)

    steps: list[ProbeStep] = []
    for i, turn in enumerate(turns):
        new_session = bool(turn.get("new_session", False))
        role = str(turn.get("role", "user"))
        steps.append(
            ProbeStep(
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

    success_rate = 0.0
    times_tested = 0
    eff_raw: object = data.get("effectiveness")
    if isinstance(eff_raw, dict):
        eff: dict[str, Any] = cast(dict[str, Any], eff_raw)
        success_rate = float(eff.get("success_rate", 0.0))
        times_tested = int(eff.get("times_tested", 0))

    return ProbeTemplate(
        id=str(data["id"]),
        name=str(data["name"]),
        severity=SEVERITY_MAP[data["severity"].lower()],
        category=CATEGORY_MAP[data["category"].lower()],
        owasp=str(data["owasp_id"]),
        objective=str(data["objective"]),
        steps=steps,
        eval_criteria=eval_criteria,
        source_path=str(path),
        success_rate=success_rate,
        times_tested=times_tested,
    )


def load_yaml_templates_dir(directory: Path) -> list[ProbeTemplate]:
    """Load all *.yaml templates from a directory tree."""
    templates: list[ProbeTemplate] = []
    for path in sorted(directory.rglob("*.yaml")):
        templates.append(load_yaml_template(path))
    return templates


# Regex matching the effectiveness block in YAML files
_EFF_BLOCK_RE = re.compile(
    r"^effectiveness:\n\s+success_rate:\s*[\d.]+\n\s+times_tested:\s*\d+",
    re.MULTILINE,
)


def _update_yaml_effectiveness(path: Path, new_rate: float, new_tested: int) -> bool:
    """Rewrite the effectiveness block in a YAML file. Returns True on success."""
    text = path.read_text(encoding="utf-8")
    replacement = (
        f"effectiveness:\n  success_rate: {round(new_rate, 2)}\n  times_tested: {new_tested}"
    )
    updated, count = _EFF_BLOCK_RE.subn(replacement, text, count=1)
    if count == 0:
        return False
    path.write_text(updated, encoding="utf-8")
    return True


def update_effectiveness_scores(
    findings: list[Finding],
    templates: list[ProbeTemplate],
) -> int:
    """Update YAML probe files with new effectiveness scores from scan findings.

    Computes an incremental weighted average: new results are merged with the
    existing success_rate and times_tested already stored in each template.
    Skips probe findings (template_id contains '-probe-').

    Returns the number of YAML files updated.
    """
    # Group findings by template_id (skip probes)
    by_template: dict[str, list[Finding]] = {}
    for f in findings:
        if "-probe-" in f.template_id:
            continue
        by_template.setdefault(f.template_id, []).append(f)

    templates_by_id = {t.id: t for t in templates}
    updated = 0

    for template_id, template_findings in by_template.items():
        template = templates_by_id.get(template_id)
        if not template or not template.source_path:
            continue

        new_tests = len(template_findings)
        new_vulns = sum(1 for f in template_findings if f.verdict == Verdict.VULNERABLE)

        # Incremental average: merge with existing scores
        old_tested = template.times_tested
        old_rate = template.success_rate
        total_tested = old_tested + new_tests
        total_vulns = round(old_rate * old_tested) + new_vulns
        merged_rate = total_vulns / total_tested if total_tested > 0 else 0.0

        source = Path(template.source_path)
        if not source.exists():
            logger.debug("Template file not found: %s", source)
            continue

        if _update_yaml_effectiveness(source, merged_rate, total_tested):
            updated += 1

            # Update the mirror copy if it exists
            mirror = _find_mirror(source)
            if mirror and mirror.exists():
                _update_yaml_effectiveness(mirror, merged_rate, total_tested)

    if updated:
        logger.info("Updated effectiveness scores for %d probes", updated)
    return updated


def _find_mirror(source: Path) -> Path | None:
    """Find the mirror copy of a YAML file (src/keelson/probes ↔ probes)."""
    parts = source.parts
    # Find the 'probes' directory in the path
    try:
        idx = parts.index("probes")
    except ValueError:
        return None

    relative = Path(*parts[idx:])  # probes/category/XX-NNN.yaml

    # Determine which root this file belongs to and find the other
    src_marker = "keelson"
    if src_marker in parts:
        # source is in src/keelson/probes/ → mirror is at repo-root probes/
        repo_root = source
        for _ in range(len(parts) - idx):
            repo_root = repo_root.parent
        # Go up past src/keelson to repo root
        while repo_root.name in ("probes", "keelson", "src"):
            repo_root = repo_root.parent
        return repo_root / relative
    else:
        # source is at repo-root probes/ → mirror is in src/keelson/probes/
        repo_root = source
        for _ in range(len(parts) - idx):
            repo_root = repo_root.parent
        return repo_root / "src" / "keelson" / relative
