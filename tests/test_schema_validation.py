"""Tests for template schema validation — negative and edge cases."""

import pytest

from pentis.core.templates import TemplateLoader, TemplateValidationError


class TestSchemaValidation:
    def setup_method(self):
        self.loader = TemplateLoader()

    def _valid_template(self) -> dict:
        return {
            "id": "GA-001",
            "name": "Test template",
            "behavior": "goal_adherence",
            "severity": "high",
            "steps": [{"role": "user", "content": "Hello"}],
        }

    def test_valid_template_passes(self):
        self.loader.validate(self._valid_template())

    def test_missing_id_fails(self):
        t = self._valid_template()
        del t["id"]
        with pytest.raises(TemplateValidationError):
            self.loader.validate(t)

    def test_missing_name_fails(self):
        t = self._valid_template()
        del t["name"]
        with pytest.raises(TemplateValidationError):
            self.loader.validate(t)

    def test_missing_behavior_fails(self):
        t = self._valid_template()
        del t["behavior"]
        with pytest.raises(TemplateValidationError):
            self.loader.validate(t)

    def test_missing_severity_fails(self):
        t = self._valid_template()
        del t["severity"]
        with pytest.raises(TemplateValidationError):
            self.loader.validate(t)

    def test_missing_steps_fails(self):
        t = self._valid_template()
        del t["steps"]
        with pytest.raises(TemplateValidationError):
            self.loader.validate(t)

    def test_empty_steps_fails(self):
        t = self._valid_template()
        t["steps"] = []
        with pytest.raises(TemplateValidationError):
            self.loader.validate(t)

    def test_invalid_behavior_fails(self):
        t = self._valid_template()
        t["behavior"] = "invalid_behavior"
        with pytest.raises(TemplateValidationError):
            self.loader.validate(t)

    def test_invalid_severity_fails(self):
        t = self._valid_template()
        t["severity"] = "super_critical"
        with pytest.raises(TemplateValidationError):
            self.loader.validate(t)

    def test_invalid_id_format_fails(self):
        t = self._valid_template()
        t["id"] = "bad-format"
        with pytest.raises(TemplateValidationError):
            self.loader.validate(t)

    def test_id_lowercase_fails(self):
        t = self._valid_template()
        t["id"] = "ga-001"
        with pytest.raises(TemplateValidationError):
            self.loader.validate(t)

    def test_step_missing_role_fails(self):
        t = self._valid_template()
        t["steps"] = [{"content": "hello"}]
        with pytest.raises(TemplateValidationError):
            self.loader.validate(t)

    def test_step_missing_content_fails(self):
        t = self._valid_template()
        t["steps"] = [{"role": "user"}]
        with pytest.raises(TemplateValidationError):
            self.loader.validate(t)

    def test_step_invalid_role_fails(self):
        t = self._valid_template()
        t["steps"] = [{"role": "admin", "content": "hello"}]
        with pytest.raises(TemplateValidationError):
            self.loader.validate(t)

    def test_step_empty_content_fails(self):
        t = self._valid_template()
        t["steps"] = [{"role": "user", "content": ""}]
        with pytest.raises(TemplateValidationError):
            self.loader.validate(t)

    def test_indicator_invalid_type_fails(self):
        t = self._valid_template()
        t["indicators"] = [{"type": "invalid", "value": "test"}]
        with pytest.raises(TemplateValidationError):
            self.loader.validate(t)

    def test_indicator_empty_value_fails(self):
        t = self._valid_template()
        t["indicators"] = [{"type": "word", "value": ""}]
        with pytest.raises(TemplateValidationError):
            self.loader.validate(t)

    def test_indicator_weight_too_high_fails(self):
        t = self._valid_template()
        t["indicators"] = [{"type": "word", "value": "test", "weight": 11}]
        with pytest.raises(TemplateValidationError):
            self.loader.validate(t)

    def test_indicator_negative_weight_fails(self):
        t = self._valid_template()
        t["indicators"] = [{"type": "word", "value": "test", "weight": -1}]
        with pytest.raises(TemplateValidationError):
            self.loader.validate(t)

    def test_name_too_short_fails(self):
        t = self._valid_template()
        t["name"] = "ab"
        with pytest.raises(TemplateValidationError):
            self.loader.validate(t)

    def test_valid_with_all_indicator_types(self):
        t = self._valid_template()
        t["indicators"] = [
            {"type": "word", "value": "test"},
            {"type": "regex", "value": "(?i)pattern"},
            {"type": "absence", "value": "missing"},
        ]
        self.loader.validate(t)  # should not raise

    def test_valid_with_metadata(self):
        t = self._valid_template()
        t["metadata"] = {
            "author": "pentis",
            "tags": ["injection", "test"],
            "references": ["https://owasp.org"],
        }
        self.loader.validate(t)  # should not raise

    def test_valid_with_owasp(self):
        t = self._valid_template()
        t["owasp_id"] = "LLM01"
        t["owasp_name"] = "Prompt Injection"
        self.loader.validate(t)  # should not raise

    def test_valid_step_with_optional_fields(self):
        t = self._valid_template()
        t["steps"] = [{"role": "user", "content": "test", "expect_refusal": True, "reset_history": True}]
        self.loader.validate(t)  # should not raise

    def test_all_behavior_values_valid(self):
        for behavior in ["goal_adherence", "tool_safety", "memory_integrity"]:
            t = self._valid_template()
            t["behavior"] = behavior
            self.loader.validate(t)

    def test_all_severity_values_valid(self):
        for severity in ["critical", "high", "medium", "low", "info"]:
            t = self._valid_template()
            t["severity"] = severity
            self.loader.validate(t)
