"""Tests for execution strategies."""

from pentis.core.models import AttackStep, AttackTemplate
from pentis.strategies.fixed import FixedStrategy


def _make_template(template_id: str, behavior: str) -> AttackTemplate:
    return AttackTemplate(
        id=template_id,
        name=f"Test {template_id}",
        behavior=behavior,
        severity="high",
        description="Test",
        steps=[AttackStep(role="user", content="test")],
    )


class TestFixedStrategy:
    def test_sorts_by_behavior_then_id(self):
        strategy = FixedStrategy()
        templates = [
            _make_template("TS-002", "tool_safety"),
            _make_template("GA-003", "goal_adherence"),
            _make_template("MI-001", "memory_integrity"),
            _make_template("GA-001", "goal_adherence"),
            _make_template("TS-001", "tool_safety"),
        ]
        ordered = strategy.order(templates)
        ids = [t.id for t in ordered]
        assert ids == ["GA-001", "GA-003", "MI-001", "TS-001", "TS-002"]

    def test_empty_list(self):
        strategy = FixedStrategy()
        assert strategy.order([]) == []

    def test_single_template(self):
        strategy = FixedStrategy()
        templates = [_make_template("GA-001", "goal_adherence")]
        assert len(strategy.order(templates)) == 1

    def test_preserves_all_templates(self):
        strategy = FixedStrategy()
        templates = [
            _make_template("GA-001", "goal_adherence"),
            _make_template("TS-001", "tool_safety"),
            _make_template("MI-001", "memory_integrity"),
        ]
        ordered = strategy.order(templates)
        assert len(ordered) == 3

    def test_same_behavior_sorted_by_id(self):
        strategy = FixedStrategy()
        templates = [
            _make_template("GA-010", "goal_adherence"),
            _make_template("GA-001", "goal_adherence"),
            _make_template("GA-005", "goal_adherence"),
        ]
        ordered = strategy.order(templates)
        ids = [t.id for t in ordered]
        assert ids == ["GA-001", "GA-005", "GA-010"]

    def test_does_not_mutate_input(self):
        strategy = FixedStrategy()
        templates = [
            _make_template("TS-001", "tool_safety"),
            _make_template("GA-001", "goal_adherence"),
        ]
        original_ids = [t.id for t in templates]
        strategy.order(templates)
        assert [t.id for t in templates] == original_ids
