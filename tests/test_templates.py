"""Tests for the attack template loader."""

from pentis.core.models import Category
from pentis.core.templates import ATTACKS_DIR, load_all_templates, load_template


class TestLoadTemplates:
    def test_load_all_templates(self):
        templates = load_all_templates(attacks_dir=ATTACKS_DIR)
        assert len(templates) >= 71

    def test_all_templates_have_required_fields(self):
        templates = load_all_templates(attacks_dir=ATTACKS_DIR)
        for t in templates:
            assert t.id, "Template missing id"
            assert t.name, f"{t.id} missing name"
            assert t.severity, f"{t.id} missing severity"
            assert t.category, f"{t.id} missing category"
            assert t.owasp, f"{t.id} missing owasp"
            assert t.objective, f"{t.id} missing objective"
            assert len(t.steps) >= 1, f"{t.id} has no steps"
            assert t.steps[0].prompt, f"{t.id} step 1 has no prompt"
            assert t.eval_criteria.vulnerable_if, f"{t.id} missing vulnerable_if"
            assert t.eval_criteria.safe_if, f"{t.id} missing safe_if"

    def test_id_format(self):
        templates = load_all_templates(attacks_dir=ATTACKS_DIR)
        valid_prefixes = ("GA", "TS", "MI", "PB", "DI", "ES", "SI")
        for t in templates:
            assert t.id[:2] in valid_prefixes, f"Unexpected id prefix: {t.id}"
            assert "-" in t.id, f"ID missing dash: {t.id}"

    def test_category_counts(self):
        templates = load_all_templates(attacks_dir=ATTACKS_DIR)
        ga = [t for t in templates if t.category == Category.GOAL_ADHERENCE]
        ts = [t for t in templates if t.category == Category.TOOL_SAFETY]
        mi = [t for t in templates if t.category == Category.MEMORY_INTEGRITY]
        assert len(ga) == 55
        assert len(ts) == 38
        assert len(mi) == 23

    def test_filter_by_category(self):
        ga = load_all_templates(attacks_dir=ATTACKS_DIR, category="goal-adherence")
        assert len(ga) == 55
        assert all(t.category == Category.GOAL_ADHERENCE for t in ga)

        ts = load_all_templates(attacks_dir=ATTACKS_DIR, category="tool-safety")
        assert len(ts) == 38

        mi = load_all_templates(attacks_dir=ATTACKS_DIR, category="memory-integrity")
        assert len(mi) == 23

    def test_load_single_template(self):
        path = ATTACKS_DIR / "goal-adherence" / "GA-001.yaml"
        t = load_template(path)
        assert t.id == "GA-001"
        assert t.source_path == str(path)

    def test_multi_turn_attacks_detected(self):
        templates = load_all_templates(attacks_dir=ATTACKS_DIR)
        multi = [t for t in templates if len(t.steps) > 1]
        assert len(multi) >= 3, "Expected at least 3 multi-turn attacks"
        for t in multi:
            assert any(s.is_followup for s in t.steps[1:]), f"{t.id} multi-step but no followup"
