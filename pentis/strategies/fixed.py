"""Fixed strategy — sequential execution of all templates."""

from __future__ import annotations

from pentis.core.models import AttackTemplate


class FixedStrategy:
    """Execute templates in fixed order: by behavior, then by ID."""

    def order(self, templates: list[AttackTemplate]) -> list[AttackTemplate]:
        """Return templates in execution order."""
        return sorted(templates, key=lambda t: (t.behavior, t.id))
