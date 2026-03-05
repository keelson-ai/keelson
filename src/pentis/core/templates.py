"""Attack template loader — loads YAML playbooks."""

from __future__ import annotations

from pathlib import Path

from pentis.core.models import AttackTemplate
from pentis.core.yaml_templates import (
    CATEGORY_MAP as CATEGORY_MAP,
)
from pentis.core.yaml_templates import (
    load_yaml_template,
    load_yaml_templates_dir,
)

# Packaged attacks live at src/pentis/attacks/ (installed via pip)
# Fallback to repo-root attacks/ for development
_PACKAGE_ATTACKS = Path(__file__).resolve().parent.parent / "attacks"
_REPO_ATTACKS = Path(__file__).resolve().parents[2].parent / "attacks"
ATTACKS_DIR = _PACKAGE_ATTACKS if _PACKAGE_ATTACKS.is_dir() else _REPO_ATTACKS


def load_template(path: Path) -> AttackTemplate:
    """Load and parse a single attack template from a YAML file."""
    return load_yaml_template(path)


def load_all_templates(
    attacks_dir: Path | None = None, category: str | None = None
) -> list[AttackTemplate]:
    """Load all attack templates from the attacks directory."""
    root = attacks_dir or ATTACKS_DIR
    if category:
        root = root / category
    return load_yaml_templates_dir(root)
