"""Tests for SARIF v2.1.0 output generation."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from pentis.core.models import (
    CampaignConfig,
    CampaignResult,
    Category,
    EvidenceItem,
    Finding,
    ScanResult,
    Severity,
    StatisticalFinding,
    Target,
    TrialResult,
    Verdict,
)
from pentis.core.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    TOOL_NAME,
    campaign_to_sarif,
    scan_to_sarif,
    to_sarif_json,
)


def _make_finding(
    template_id: str = "GA-001",
    name: str = "Direct Instruction Override",
    verdict: Verdict = Verdict.VULNERABLE,
    severity: Severity = Severity.HIGH,
    category: Category = Category.GOAL_ADHERENCE,
    owasp: str = "LLM01 — Prompt Injection",
) -> Finding:
    return Finding(
        template_id=template_id,
        template_name=name,
        verdict=verdict,
        severity=severity,
        category=category,
        owasp=owasp,
        evidence=[EvidenceItem(step_index=1, prompt="test prompt", response="test response")],
        reasoning="Test reasoning",
    )


def _make_scan(*findings: Finding) -> ScanResult:
    return ScanResult(
        scan_id="test123",
        target=Target(url="https://example.com/v1/chat/completions", model="gpt-4"),
        findings=list(findings),
        started_at=datetime(2026, 3, 4, 12, 0, 0, tzinfo=timezone.utc),
        finished_at=datetime(2026, 3, 4, 12, 5, 0, tzinfo=timezone.utc),
    )


class TestScanToSarif:
    def test_basic_structure(self):
        scan = _make_scan(_make_finding())
        sarif = scan_to_sarif(scan)

        assert sarif["$schema"] == SARIF_SCHEMA
        assert sarif["version"] == SARIF_VERSION
        assert len(sarif["runs"]) == 1

    def test_tool_info(self):
        sarif = scan_to_sarif(_make_scan(_make_finding()))
        driver = sarif["runs"][0]["tool"]["driver"]

        assert driver["name"] == TOOL_NAME
        assert "rules" in driver
        assert len(driver["rules"]) == 1

    def test_rule_from_finding(self):
        finding = _make_finding()
        sarif = scan_to_sarif(_make_scan(finding))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]

        assert rule["id"] == "GA-001"
        assert rule["shortDescription"]["text"] == "Direct Instruction Override"
        assert rule["defaultConfiguration"]["level"] == "error"
        assert rule["properties"]["category"] == "Goal Adherence"

    def test_result_from_vulnerable_finding(self):
        finding = _make_finding(verdict=Verdict.VULNERABLE)
        sarif = scan_to_sarif(_make_scan(finding))
        result = sarif["runs"][0]["results"][0]

        assert result["ruleId"] == "GA-001"
        assert result["kind"] == "fail"
        assert result["level"] == "error"
        assert result["message"]["text"] == "Test reasoning"

    def test_result_from_safe_finding(self):
        finding = _make_finding(verdict=Verdict.SAFE)
        sarif = scan_to_sarif(_make_scan(finding))
        result = sarif["runs"][0]["results"][0]

        assert result["kind"] == "pass"
        assert result["level"] == "none"

    def test_result_from_inconclusive_finding(self):
        finding = _make_finding(verdict=Verdict.INCONCLUSIVE)
        sarif = scan_to_sarif(_make_scan(finding))
        result = sarif["runs"][0]["results"][0]

        assert result["kind"] == "review"
        assert result["level"] == "none"

    def test_severity_mapping(self):
        for sev, expected_level in [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "note"),
        ]:
            finding = _make_finding(severity=sev, verdict=Verdict.VULNERABLE)
            sarif = scan_to_sarif(_make_scan(finding))
            result = sarif["runs"][0]["results"][0]
            assert result["level"] == expected_level, f"Expected {expected_level} for {sev}"

    def test_multiple_findings(self):
        f1 = _make_finding(template_id="GA-001", name="Attack 1")
        f2 = _make_finding(template_id="TS-001", name="Attack 2", category=Category.TOOL_SAFETY)
        sarif = scan_to_sarif(_make_scan(f1, f2))

        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 2
        assert len(sarif["runs"][0]["results"]) == 2

    def test_invocation_timestamps(self):
        scan = _make_scan(_make_finding())
        sarif = scan_to_sarif(scan)
        inv = sarif["runs"][0]["invocations"][0]

        assert inv["executionSuccessful"] is True
        assert "startTimeUtc" in inv
        assert "endTimeUtc" in inv

    def test_scan_properties(self):
        scan = _make_scan(_make_finding())
        sarif = scan_to_sarif(scan)
        props = sarif["runs"][0]["properties"]

        assert props["target"] == "https://example.com/v1/chat/completions"
        assert props["model"] == "gpt-4"
        assert props["scanId"] == "test123"

    def test_empty_scan(self):
        scan = _make_scan()
        sarif = scan_to_sarif(scan)

        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_new_categories(self):
        """Verify SARIF handles all 9 categories including new ones."""
        for cat in [
            Category.PERMISSION_BOUNDARIES,
            Category.DELEGATION_INTEGRITY,
            Category.EXECUTION_SAFETY,
            Category.SESSION_ISOLATION,
        ]:
            finding = _make_finding(category=cat)
            sarif = scan_to_sarif(_make_scan(finding))
            rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
            assert rule["properties"]["category"] == cat.value


class TestCampaignToSarif:
    def test_basic_structure(self):
        campaign = CampaignResult(
            campaign_id="camp123",
            config=CampaignConfig(trials_per_attack=5),
            target=Target(url="https://example.com/v1/chat/completions", model="gpt-4"),
            findings=[
                StatisticalFinding(
                    template_id="GA-001",
                    template_name="Direct Instruction Override",
                    severity=Severity.HIGH,
                    category=Category.GOAL_ADHERENCE,
                    owasp="LLM01",
                    trials=[TrialResult(trial_index=1, verdict=Verdict.VULNERABLE)],
                    success_rate=1.0,
                    ci_lower=0.5,
                    ci_upper=1.0,
                    verdict=Verdict.VULNERABLE,
                ),
            ],
            started_at=datetime(2026, 3, 4, 12, 0, 0, tzinfo=timezone.utc),
        )
        sarif = campaign_to_sarif(campaign)

        assert sarif["version"] == SARIF_VERSION
        assert len(sarif["runs"][0]["results"]) == 1
        result = sarif["runs"][0]["results"][0]
        assert result["kind"] == "fail"
        assert "success rate" in result["message"]["text"]


class TestToSarifJson:
    def test_scan_json_is_valid(self):
        scan = _make_scan(_make_finding())
        json_str = to_sarif_json(scan)
        parsed = json.loads(json_str)
        assert parsed["version"] == SARIF_VERSION

    def test_campaign_json_is_valid(self):
        campaign = CampaignResult(
            target=Target(url="https://example.com"),
            started_at=datetime(2026, 3, 4, 12, 0, 0, tzinfo=timezone.utc),
        )
        json_str = to_sarif_json(campaign)
        parsed = json.loads(json_str)
        assert parsed["version"] == SARIF_VERSION
