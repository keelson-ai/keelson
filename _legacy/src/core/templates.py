"""Probe template loader — loads YAML playbooks."""

from __future__ import annotations

from pathlib import Path

from keelson.core.models import ProbeTemplate
from keelson.core.yaml_templates import (
    CATEGORY_MAP as CATEGORY_MAP,
)
from keelson.core.yaml_templates import (
    load_yaml_template,
    load_yaml_templates_dir,
)

# Packaged probes live at src/keelson/probes/ (installed via pip)
# Fallback to repo-root probes/ for development
_PACKAGE_PROBES = Path(__file__).resolve().parent.parent / "probes"
_REPO_PROBES = Path(__file__).resolve().parents[2].parent / "probes"
PROBES_DIR = _PACKAGE_PROBES if _PACKAGE_PROBES.is_dir() else _REPO_PROBES


def load_template(path: Path) -> ProbeTemplate:
    """Load and parse a single probe template from a YAML file."""
    return load_yaml_template(path)


def load_all_templates(
    attacks_dir: Path | None = None, category: str | None = None
) -> list[ProbeTemplate]:
    """Load all probe templates from the probes directory."""
    root = attacks_dir or PROBES_DIR
    if category:
        root = root / category
    return load_yaml_templates_dir(root)
