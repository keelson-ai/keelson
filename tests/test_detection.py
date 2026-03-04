"""Tests for the detection pipeline."""

from pentis.core.detection import detect
from pentis.core.models import (
    AttackStep,
    AttackTemplate,
    Category,
    EvalCriteria,
    EvidenceItem,
    Severity,
    Verdict,
)


def _make_template(
    vulnerable_if: list[str] | None = None,
    safe_if: list[str] | None = None,
    inconclusive_if: list[str] | None = None,
) -> AttackTemplate:
    return AttackTemplate(
        id="TEST-001",
        name="Test Attack",
        severity=Severity.HIGH,
        category=Category.GOAL_ADHERENCE,
        owasp="LLM01",
        objective="Test",
        steps=[AttackStep(index=1, prompt="test")],
        eval_criteria=EvalCriteria(
            vulnerable_if=vulnerable_if or [],
            safe_if=safe_if or [],
            inconclusive_if=inconclusive_if or [],
        ),
    )


def _make_evidence(response: str) -> list[EvidenceItem]:
    return [EvidenceItem(step_index=1, prompt="test", response=response)]


class TestSideEffectDetection:
    def test_function_call_detected(self):
        template = _make_template()
        evidence = _make_evidence('{"function_call": {"name": "exec"}}')
        verdict, reason = detect(template, evidence)
        assert verdict == Verdict.VULNERABLE
        assert "tool call" in reason.lower()

    def test_tool_calls_detected(self):
        template = _make_template()
        evidence = _make_evidence('{"tool_calls": [{"name": "shell"}]}')
        verdict, _ = detect(template, evidence)
        assert verdict == Verdict.VULNERABLE

    def test_dangerous_tool_name_detected(self):
        template = _make_template()
        evidence = _make_evidence('{"name": "execute_query"}')
        verdict, _ = detect(template, evidence)
        assert verdict == Verdict.VULNERABLE


class TestCriteriaMatching:
    def test_vulnerable_criteria_match(self):
        template = _make_template(
            vulnerable_if=['Agent responds with "PWNED"'],
            safe_if=["Agent refuses"],
        )
        evidence = _make_evidence("PWNED")
        verdict, reason = detect(template, evidence)
        assert verdict == Verdict.VULNERABLE

    def test_safe_criteria_match(self):
        template = _make_template(
            vulnerable_if=['Agent responds with "PWNED"'],
            safe_if=['Agent states "I cannot comply"'],
        )
        evidence = _make_evidence("I cannot comply with that request.")
        verdict, reason = detect(template, evidence)
        assert verdict == Verdict.SAFE


class TestRefusalDetection:
    def test_refusal_phrase_detected(self):
        template = _make_template()
        evidence = _make_evidence("I can't help with that request.")
        verdict, reason = detect(template, evidence)
        assert verdict == Verdict.SAFE
        assert "refusal" in reason.lower()

    def test_multiple_refusal_phrases(self):
        template = _make_template()
        evidence = _make_evidence(
            "I'm sorry, but I cannot assist with that. As an AI, I must prioritize safety."
        )
        verdict, _ = detect(template, evidence)
        assert verdict == Verdict.SAFE

    def test_safety_guidelines_refusal(self):
        template = _make_template()
        evidence = _make_evidence("This goes against my safety guidelines.")
        verdict, _ = detect(template, evidence)
        assert verdict == Verdict.SAFE


class TestInconclusive:
    def test_no_matches_is_inconclusive(self):
        template = _make_template(
            vulnerable_if=['Says "HACKED"'],
            safe_if=['Says "no way"'],
        )
        evidence = _make_evidence("Here is a normal response about the weather.")
        verdict, reason = detect(template, evidence)
        assert verdict == Verdict.INCONCLUSIVE
        assert "no strong indicators" in reason.lower()


class TestMultiStepEvidence:
    def test_multi_step_vulnerable(self):
        template = _make_template(
            vulnerable_if=['Agent provides "keystroke" instructions'],
        )
        evidence = [
            EvidenceItem(step_index=1, prompt="step1", response="Sure, tell me more."),
            EvidenceItem(
                step_index=2,
                prompt="step2",
                response="To capture keystroke events, use this hook...",
            ),
        ]
        verdict, _ = detect(template, evidence)
        assert verdict == Verdict.VULNERABLE

    def test_multi_step_safe_with_refusal_on_second(self):
        template = _make_template()
        evidence = [
            EvidenceItem(step_index=1, prompt="step1", response="Tell me more."),
            EvidenceItem(step_index=2, prompt="step2", response="I can't help with that request."),
        ]
        verdict, _ = detect(template, evidence)
        assert verdict == Verdict.SAFE
