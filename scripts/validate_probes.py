# pyright: basic
"""Validate all YAML probe playbooks against the required schema."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

# Required top-level fields
_REQUIRED_FIELDS = (
    "id",
    "name",
    "severity",
    "category",
    "owasp_id",
    "objective",
    "turns",
    "evaluation",
)

# Valid severity values
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}

# Valid category directory names (kebab-case)
_VALID_CATEGORIES = {
    "goal-adherence",
    "goal_adherence",
    "tool-safety",
    "tool_safety",
    "memory-integrity",
    "memory_integrity",
    "session-isolation",
    "session_isolation",
    "execution-safety",
    "execution_safety",
    "permission-boundaries",
    "permission_boundaries",
    "delegation-integrity",
    "delegation_integrity",
    "output-weaponization",
    "output_weaponization",
    "multi-agent-security",
    "multi_agent_security",
    "temporal-persistence",
    "temporal_persistence",
    "cognitive-architecture",
    "cognitive_architecture",
    "conversational-exfiltration",
    "conversational_exfiltration",
    "supply-chain-language",
    "supply_chain_language",
    "content-safety",
    "content_safety",
    "agentic-security",
    "agentic_security",
}


def validate_file(path: Path) -> list[str]:
    """Validate a single YAML probe file, returning a list of errors."""
    errors: list[str] = []

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"Invalid YAML: {exc}"]

    if not isinstance(data, dict):
        return ["File does not contain a YAML mapping"]

    # Check required fields
    for field in _REQUIRED_FIELDS:
        if field not in data:
            errors.append(f"Missing required field: '{field}'")

    # Validate severity
    severity = data.get("severity", "")
    if isinstance(severity, str) and severity.lower() not in _VALID_SEVERITIES:
        errors.append(
            f"Invalid severity: '{severity}' (expected: {', '.join(sorted(_VALID_SEVERITIES))})"
        )

    # Validate category
    category = data.get("category", "")
    if isinstance(category, str) and category.lower() not in _VALID_CATEGORIES:
        errors.append(f"Invalid category: '{category}' (expected one of the known categories)")

    # Validate turns
    turns = data.get("turns", [])
    if not isinstance(turns, list):
        errors.append("'turns' must be a list")
    elif len(turns) == 0:
        errors.append("'turns' must have at least one entry")
    else:
        for i, turn in enumerate(turns):
            if not isinstance(turn, dict):
                errors.append(f"turns[{i}]: must be a mapping")
                continue
            if "content" not in turn:
                errors.append(f"turns[{i}]: missing 'content' field")

    # Validate evaluation
    evaluation = data.get("evaluation", {})
    if not isinstance(evaluation, dict):
        errors.append("'evaluation' must be a mapping")
    else:
        if "vulnerable_if" not in evaluation:
            errors.append("evaluation: missing 'vulnerable_if'")
        if "safe_if" not in evaluation:
            errors.append("evaluation: missing 'safe_if'")

    return errors


def main() -> int:
    """Validate all YAML probe files and report errors."""
    attacks_dir = Path(__file__).resolve().parents[1] / "probes"

    if not attacks_dir.is_dir():
        print(f"ERROR: probes directory not found at {attacks_dir}")
        return 1

    yaml_files = sorted(attacks_dir.rglob("*.yaml"))
    if not yaml_files:
        print(f"ERROR: no YAML files found in {attacks_dir}")
        return 1

    total_errors = 0
    for path in yaml_files:
        errors = validate_file(path)
        if errors:
            rel = path.relative_to(attacks_dir)
            for error in errors:
                print(f"  {rel}: {error}")
            total_errors += len(errors)

    print(f"\nValidated {len(yaml_files)} probe playbooks")
    if total_errors > 0:
        print(f"FAILED: {total_errors} error(s) found")
        return 1

    print("All playbooks valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
