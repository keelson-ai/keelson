"""Tests for core data models."""

from datetime import datetime, timedelta

from pentis.core.models import (
    AgentResponse,
    AttackStep,
    AttackTemplate,
    Behavior,
    EvidenceItem,
    Finding,
    FindingStatus,
    Indicator,
    ScanResult,
    Severity,
    TargetInfo,
)


class TestEnums:
    def test_severity_values(self):
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"
        assert Severity.INFO == "info"

    def test_finding_status_values(self):
        assert FindingStatus.VULNERABLE == "vulnerable"
        assert FindingStatus.SAFE == "safe"
        assert FindingStatus.INCONCLUSIVE == "inconclusive"
        assert FindingStatus.ERROR == "error"

    def test_behavior_values(self):
        assert Behavior.GOAL_ADHERENCE == "goal_adherence"
        assert Behavior.TOOL_SAFETY == "tool_safety"
        assert Behavior.MEMORY_INTEGRITY == "memory_integrity"

    def test_severity_is_str(self):
        assert isinstance(Severity.CRITICAL, str)
        assert Severity.CRITICAL == "critical"

    def test_finding_status_is_str(self):
        assert isinstance(FindingStatus.VULNERABLE, str)
        assert FindingStatus.VULNERABLE == "vulnerable"


class TestAgentResponse:
    def test_has_tool_calls_true(self):
        resp = AgentResponse(content="hi", tool_calls=[{"function": {"name": "test"}}])
        assert resp.has_tool_calls is True

    def test_has_tool_calls_false(self):
        resp = AgentResponse(content="hi")
        assert resp.has_tool_calls is False

    def test_has_tool_calls_empty_list(self):
        resp = AgentResponse(content="hi", tool_calls=[])
        assert resp.has_tool_calls is False

    def test_defaults(self):
        resp = AgentResponse(content="test")
        assert resp.raw == {}
        assert resp.model == ""
        assert resp.finish_reason == ""
        assert resp.tool_calls == []
        assert resp.usage == {}
        assert resp.latency_ms == 0.0

    def test_content_stored(self):
        resp = AgentResponse(content="hello world")
        assert resp.content == "hello world"


class TestTargetInfo:
    def test_defaults(self):
        info = TargetInfo(url="http://test.com")
        assert info.url == "http://test.com"
        assert info.model == ""
        assert info.system_prompt_leaked == ""
        assert info.tools_detected == []
        assert info.supports_tools is False
        assert info.supports_history is True
        assert info.response_format == "openai"

    def test_with_tools(self):
        info = TargetInfo(
            url="http://test.com",
            supports_tools=True,
            tools_detected=["search", "write_file"],
        )
        assert info.supports_tools is True
        assert len(info.tools_detected) == 2


class TestAttackTemplate:
    def test_defaults(self):
        t = AttackTemplate(id="GA-001", name="Test", behavior="goal_adherence", severity="high", description="Desc")
        assert t.owasp_id is None
        assert t.steps == []
        assert t.indicators == []
        assert t.metadata == {}

    def test_with_steps_and_indicators(self):
        t = AttackTemplate(
            id="GA-001",
            name="Test",
            behavior="goal_adherence",
            severity="high",
            description="Desc",
            steps=[AttackStep(role="user", content="hello")],
            indicators=[Indicator(type="word", value="PWNED")],
        )
        assert len(t.steps) == 1
        assert len(t.indicators) == 1


class TestAttackStep:
    def test_defaults(self):
        step = AttackStep(role="user", content="test")
        assert step.expect_refusal is False
        assert step.reset_history is False

    def test_with_flags(self):
        step = AttackStep(role="user", content="test", expect_refusal=True, reset_history=True)
        assert step.expect_refusal is True
        assert step.reset_history is True


class TestIndicator:
    def test_default_weight(self):
        ind = Indicator(type="word", value="test")
        assert ind.weight == 1.0

    def test_custom_weight(self):
        ind = Indicator(type="regex", value="pattern", weight=5.0)
        assert ind.weight == 5.0


class TestEvidenceItem:
    def test_defaults(self):
        e = EvidenceItem(step_index=0, prompt="test", response="response")
        assert e.indicators_matched == []
        assert e.refusal_detected is False

    def test_with_indicators(self):
        e = EvidenceItem(
            step_index=1,
            prompt="attack",
            response="PWNED",
            indicators_matched=["PWNED"],
            refusal_detected=False,
        )
        assert len(e.indicators_matched) == 1


class TestFinding:
    def test_is_vulnerable_true(self):
        f = Finding(
            template_id="GA-001", template_name="Test", behavior="goal_adherence",
            severity="high", status=FindingStatus.VULNERABLE,
        )
        assert f.is_vulnerable is True

    def test_is_vulnerable_false_safe(self):
        f = Finding(
            template_id="GA-001", template_name="Test", behavior="goal_adherence",
            severity="high", status=FindingStatus.SAFE,
        )
        assert f.is_vulnerable is False

    def test_is_vulnerable_false_inconclusive(self):
        f = Finding(
            template_id="GA-001", template_name="Test", behavior="goal_adherence",
            severity="high", status=FindingStatus.INCONCLUSIVE,
        )
        assert f.is_vulnerable is False

    def test_is_vulnerable_false_error(self):
        f = Finding(
            template_id="GA-001", template_name="Test", behavior="goal_adherence",
            severity="high", status=FindingStatus.ERROR,
        )
        assert f.is_vulnerable is False

    def test_defaults(self):
        f = Finding(
            template_id="GA-001", template_name="Test", behavior="goal_adherence",
            severity="high", status=FindingStatus.SAFE,
        )
        assert f.owasp_id is None
        assert f.description == ""
        assert f.evidence == []
        assert f.confidence == 0.0


class TestScanResult:
    def _make_finding(self, status: FindingStatus, severity: str = "high", behavior: str = "goal_adherence") -> Finding:
        return Finding(
            template_id="T-001", template_name="Test", behavior=behavior,
            severity=severity, status=status,
        )

    def test_duration_no_end(self):
        r = ScanResult(target=TargetInfo(url="http://test.com"))
        assert r.duration_seconds == 0.0

    def test_duration_with_end(self):
        start = datetime(2024, 1, 1, 12, 0, 0)
        end = datetime(2024, 1, 1, 12, 0, 30)
        r = ScanResult(target=TargetInfo(url="http://test.com"), start_time=start, end_time=end)
        assert r.duration_seconds == 30.0

    def test_vulnerable_count(self):
        r = ScanResult(
            target=TargetInfo(url="http://test.com"),
            findings=[
                self._make_finding(FindingStatus.VULNERABLE),
                self._make_finding(FindingStatus.VULNERABLE),
                self._make_finding(FindingStatus.SAFE),
            ],
        )
        assert r.vulnerable_count == 2

    def test_safe_count(self):
        r = ScanResult(
            target=TargetInfo(url="http://test.com"),
            findings=[
                self._make_finding(FindingStatus.SAFE),
                self._make_finding(FindingStatus.SAFE),
                self._make_finding(FindingStatus.VULNERABLE),
            ],
        )
        assert r.safe_count == 2

    def test_inconclusive_count(self):
        r = ScanResult(
            target=TargetInfo(url="http://test.com"),
            findings=[self._make_finding(FindingStatus.INCONCLUSIVE)],
        )
        assert r.inconclusive_count == 1

    def test_error_count(self):
        r = ScanResult(
            target=TargetInfo(url="http://test.com"),
            findings=[self._make_finding(FindingStatus.ERROR), self._make_finding(FindingStatus.ERROR)],
        )
        assert r.error_count == 2

    def test_empty_counts(self):
        r = ScanResult(target=TargetInfo(url="http://test.com"))
        assert r.vulnerable_count == 0
        assert r.safe_count == 0
        assert r.inconclusive_count == 0
        assert r.error_count == 0

    def test_findings_by_severity(self):
        r = ScanResult(
            target=TargetInfo(url="http://test.com"),
            findings=[
                self._make_finding(FindingStatus.VULNERABLE, severity="critical"),
                self._make_finding(FindingStatus.VULNERABLE, severity="high"),
                self._make_finding(FindingStatus.VULNERABLE, severity="critical"),
            ],
        )
        by_sev = r.findings_by_severity()
        assert len(by_sev["critical"]) == 2
        assert len(by_sev["high"]) == 1

    def test_findings_by_behavior(self):
        r = ScanResult(
            target=TargetInfo(url="http://test.com"),
            findings=[
                self._make_finding(FindingStatus.VULNERABLE, behavior="goal_adherence"),
                self._make_finding(FindingStatus.SAFE, behavior="tool_safety"),
                self._make_finding(FindingStatus.SAFE, behavior="goal_adherence"),
            ],
        )
        by_beh = r.findings_by_behavior()
        assert len(by_beh["goal_adherence"]) == 2
        assert len(by_beh["tool_safety"]) == 1

    def test_findings_by_severity_empty(self):
        r = ScanResult(target=TargetInfo(url="http://test.com"))
        assert r.findings_by_severity() == {}

    def test_findings_by_behavior_empty(self):
        r = ScanResult(target=TargetInfo(url="http://test.com"))
        assert r.findings_by_behavior() == {}
