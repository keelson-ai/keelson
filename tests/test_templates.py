"""Tests for template loading and validation."""

import pytest
import yaml

from pentis.core.models import AttackTemplate
from pentis.core.templates import TemplateLoader, TemplateValidationError


class TestTemplateLoader:
    def setup_method(self):
        self.loader = TemplateLoader()

    def test_load_all_returns_28_templates(self):
        templates = self.loader.load_all()
        assert len(templates) == 28

    def test_all_templates_are_attack_templates(self):
        templates = self.loader.load_all()
        for t in templates:
            assert isinstance(t, AttackTemplate)

    def test_goal_adherence_has_10_templates(self):
        templates = self.loader.load_by_behavior("goal_adherence")
        assert len(templates) == 10

    def test_tool_safety_has_10_templates(self):
        templates = self.loader.load_by_behavior("tool_safety")
        assert len(templates) == 10

    def test_memory_integrity_has_8_templates(self):
        templates = self.loader.load_by_behavior("memory_integrity")
        assert len(templates) == 8

    def test_all_templates_have_required_fields(self):
        templates = self.loader.load_all()
        for t in templates:
            assert t.id, f"Template missing id"
            assert t.name, f"Template {t.id} missing name"
            assert t.behavior, f"Template {t.id} missing behavior"
            assert t.severity, f"Template {t.id} missing severity"
            assert len(t.steps) > 0, f"Template {t.id} has no steps"

    def test_all_templates_have_owasp_mapping(self):
        templates = self.loader.load_all()
        for t in templates:
            assert t.owasp_id is not None, f"Template {t.id} missing owasp_id"

    def test_template_ids_are_unique(self):
        templates = self.loader.load_all()
        ids = [t.id for t in templates]
        assert len(ids) == len(set(ids)), f"Duplicate IDs found: {[i for i in ids if ids.count(i) > 1]}"

    def test_template_id_format(self):
        templates = self.loader.load_all()
        import re
        for t in templates:
            assert re.match(r"^[A-Z]{2}-\d{3}$", t.id), f"Invalid ID format: {t.id}"

    def test_load_by_id(self):
        t = self.loader.load_by_id("GA-001")
        assert t is not None
        assert t.name == "Direct instruction override"

    def test_load_by_id_not_found(self):
        t = self.loader.load_by_id("XX-999")
        assert t is None

    def test_invalid_template_fails_validation(self):
        with pytest.raises(TemplateValidationError):
            self.loader.validate({"id": "bad"})

    def test_indicators_loaded(self):
        templates = self.loader.load_all()
        templates_with_indicators = [t for t in templates if t.indicators]
        assert len(templates_with_indicators) == 28  # All should have indicators
