"""Tests for JUnit XML output generation."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from pentis.core.junit import (
    campaign_to_junit,
    scan_to_junit,
    to_junit_xml,
)
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


def _make_finding(
    template_id: str = "GA-001",
    name: str = "Direct Instruction Override",
    verdict: Verdict = Verdict.VULNERABLE,
    severity: Severity = Severity.HIGH,
    category: Category = Category.GOAL_ADHERENCE,
    owasp: str = "LLM01 — Prompt Injection",
    response_time_ms: int = 500,
) -> Finding:
    return Finding(
        template_id=template_id,
        template_name=name,
        verdict=verdict,
        severity=severity,
        category=category,
        owasp=owasp,
        evidence=[
            EvidenceItem(
                step_index=1,
                prompt="test prompt",
                response="test response",
                response_time_ms=response_time_ms,
            )
        ],
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


def _make_stat_finding(
    template_id: str = "GA-001",
    name: str = "Direct Instruction Override",
    verdict: Verdict = Verdict.VULNERABLE,
    severity: Severity = Severity.HIGH,
    category: Category = Category.GOAL_ADHERENCE,
    owasp: str = "LLM01",
    success_rate: float = 0.8,
    ci_lower: float = 0.5,
    ci_upper: float = 1.0,
    num_trials: int = 5,
    response_time_ms: int = 300,
) -> StatisticalFinding:
    trials = [
        TrialResult(
            trial_index=i,
            verdict=Verdict.VULNERABLE if i < int(num_trials * success_rate) else Verdict.SAFE,
            response_time_ms=response_time_ms,
        )
        for i in range(num_trials)
    ]
    return StatisticalFinding(
        template_id=template_id,
        template_name=name,
        severity=severity,
        category=category,
        owasp=owasp,
        trials=trials,
        success_rate=success_rate,
        ci_lower=ci_lower,
        ci_upper=ci_upper,
        verdict=verdict,
    )


class TestScanToJunit:
    def test_valid_xml(self) -> None:
        scan = _make_scan(_make_finding())
        xml_str = scan_to_junit(scan)
        # Should parse without error
        root = ET.fromstring(xml_str)
        assert root.tag == "testsuite"

    def test_basic_attributes(self) -> None:
        scan = _make_scan(_make_finding())
        xml_str = scan_to_junit(scan)
        root = ET.fromstring(xml_str)

        assert root.get("name") == "pentis-scan-test123"
        assert root.get("tests") == "1"
        assert root.get("errors") == "0"

    def test_vulnerable_creates_failure(self) -> None:
        scan = _make_scan(_make_finding(verdict=Verdict.VULNERABLE))
        xml_str = scan_to_junit(scan)
        root = ET.fromstring(xml_str)

        assert root.get("failures") == "1"
        assert root.get("skipped") == "0"

        tc = root.find("testcase")
        assert tc is not None
        failure = tc.find("failure")
        assert failure is not None
        assert failure.get("type") == "vulnerability"
        assert "GA-001" in (failure.get("message") or "")

    def test_safe_creates_pass(self) -> None:
        scan = _make_scan(_make_finding(verdict=Verdict.SAFE))
        xml_str = scan_to_junit(scan)
        root = ET.fromstring(xml_str)

        assert root.get("failures") == "0"
        assert root.get("skipped") == "0"

        tc = root.find("testcase")
        assert tc is not None
        assert tc.find("failure") is None
        assert tc.find("skipped") is None

    def test_inconclusive_creates_skipped(self) -> None:
        scan = _make_scan(_make_finding(verdict=Verdict.INCONCLUSIVE))
        xml_str = scan_to_junit(scan)
        root = ET.fromstring(xml_str)

        assert root.get("failures") == "0"
        assert root.get("skipped") == "1"

        tc = root.find("testcase")
        assert tc is not None
        skipped = tc.find("skipped")
        assert skipped is not None
        assert "inconclusive" in (skipped.get("message") or "")

    def test_mixed_verdicts(self) -> None:
        scan = _make_scan(
            _make_finding(template_id="GA-001", name="Attack 1", verdict=Verdict.VULNERABLE),
            _make_finding(template_id="GA-002", name="Attack 2", verdict=Verdict.SAFE),
            _make_finding(template_id="GA-003", name="Attack 3", verdict=Verdict.INCONCLUSIVE),
        )
        xml_str = scan_to_junit(scan)
        root = ET.fromstring(xml_str)

        assert root.get("tests") == "3"
        assert root.get("failures") == "1"
        assert root.get("skipped") == "1"

        testcases = root.findall("testcase")
        assert len(testcases) == 3

    def test_testcase_classname_is_category(self) -> None:
        scan = _make_scan(
            _make_finding(category=Category.TOOL_SAFETY),
        )
        xml_str = scan_to_junit(scan)
        root = ET.fromstring(xml_str)
        tc = root.find("testcase")
        assert tc is not None
        assert tc.get("classname") == "Tool Safety"

    def test_testcase_time_from_evidence(self) -> None:
        scan = _make_scan(_make_finding(response_time_ms=1500))
        xml_str = scan_to_junit(scan)
        root = ET.fromstring(xml_str)
        tc = root.find("testcase")
        assert tc is not None
        assert tc.get("time") == "1.500"

    def test_properties_include_target(self) -> None:
        scan = _make_scan(_make_finding())
        xml_str = scan_to_junit(scan)
        root = ET.fromstring(xml_str)

        props = root.find("properties")
        assert props is not None
        prop_dict = {p.get("name"): p.get("value") for p in props.findall("property")}
        assert prop_dict["target"] == "https://example.com/v1/chat/completions"
        assert prop_dict["model"] == "gpt-4"
        assert prop_dict["scan_id"] == "test123"

    def test_empty_scan(self) -> None:
        scan = _make_scan()
        xml_str = scan_to_junit(scan)
        root = ET.fromstring(xml_str)

        assert root.get("tests") == "0"
        assert root.get("failures") == "0"
        assert root.findall("testcase") == []

    def test_timestamp_in_iso_format(self) -> None:
        scan = _make_scan(_make_finding())
        xml_str = scan_to_junit(scan)
        root = ET.fromstring(xml_str)

        timestamp = root.get("timestamp")
        assert timestamp is not None
        assert "2026-03-04" in timestamp

    def test_xml_declaration_present(self) -> None:
        scan = _make_scan(_make_finding())
        xml_str = scan_to_junit(scan)
        assert xml_str.startswith("<?xml")


class TestCampaignToJunit:
    def test_valid_xml(self) -> None:
        campaign = CampaignResult(
            campaign_id="camp123",
            config=CampaignConfig(trials_per_attack=5),
            target=Target(url="https://example.com/v1/chat/completions", model="gpt-4"),
            findings=[_make_stat_finding()],
            started_at=datetime(2026, 3, 4, 12, 0, 0, tzinfo=timezone.utc),
        )
        xml_str = campaign_to_junit(campaign)
        root = ET.fromstring(xml_str)
        assert root.tag == "testsuite"

    def test_campaign_attributes(self) -> None:
        campaign = CampaignResult(
            campaign_id="camp123",
            config=CampaignConfig(trials_per_attack=5),
            target=Target(url="https://example.com/v1/chat/completions", model="gpt-4"),
            findings=[
                _make_stat_finding(verdict=Verdict.VULNERABLE),
                _make_stat_finding(
                    template_id="GA-002",
                    name="Attack 2",
                    verdict=Verdict.SAFE,
                ),
            ],
            started_at=datetime(2026, 3, 4, 12, 0, 0, tzinfo=timezone.utc),
        )
        xml_str = campaign_to_junit(campaign)
        root = ET.fromstring(xml_str)

        assert root.get("name") == "pentis-campaign-camp123"
        assert root.get("tests") == "2"
        assert root.get("failures") == "1"

    def test_stat_finding_includes_confidence_interval(self) -> None:
        sf = _make_stat_finding(
            verdict=Verdict.VULNERABLE,
            success_rate=0.8,
            ci_lower=0.5,
            ci_upper=1.0,
        )
        campaign = CampaignResult(
            campaign_id="camp123",
            config=CampaignConfig(trials_per_attack=5),
            target=Target(url="https://example.com"),
            findings=[sf],
            started_at=datetime(2026, 3, 4, 12, 0, 0, tzinfo=timezone.utc),
        )
        xml_str = campaign_to_junit(campaign)
        root = ET.fromstring(xml_str)

        tc = root.find("testcase")
        assert tc is not None
        failure = tc.find("failure")
        assert failure is not None
        message = failure.get("message") or ""
        assert "success_rate=80%" in message
        assert "CI=[50%, 100%]" in message
        assert "5 trials" in message

    def test_stat_finding_inconclusive(self) -> None:
        sf = _make_stat_finding(
            verdict=Verdict.INCONCLUSIVE,
            success_rate=0.4,
            ci_lower=0.1,
            ci_upper=0.7,
        )
        campaign = CampaignResult(
            campaign_id="camp123",
            config=CampaignConfig(trials_per_attack=5),
            target=Target(url="https://example.com"),
            findings=[sf],
            started_at=datetime(2026, 3, 4, 12, 0, 0, tzinfo=timezone.utc),
        )
        xml_str = campaign_to_junit(campaign)
        root = ET.fromstring(xml_str)

        tc = root.find("testcase")
        assert tc is not None
        skipped = tc.find("skipped")
        assert skipped is not None
        message = skipped.get("message") or ""
        assert "success_rate=40%" in message
        assert "CI=[10%, 70%]" in message

    def test_campaign_properties(self) -> None:
        campaign = CampaignResult(
            campaign_id="camp123",
            config=CampaignConfig(trials_per_attack=5),
            target=Target(url="https://example.com/v1/chat/completions", model="gpt-4"),
            findings=[_make_stat_finding()],
            started_at=datetime(2026, 3, 4, 12, 0, 0, tzinfo=timezone.utc),
        )
        xml_str = campaign_to_junit(campaign)
        root = ET.fromstring(xml_str)

        props = root.find("properties")
        assert props is not None
        prop_dict = {p.get("name"): p.get("value") for p in props.findall("property")}
        assert prop_dict["campaign_id"] == "camp123"
        assert "total_trials" in prop_dict

    def test_stat_finding_time_from_trials(self) -> None:
        sf = _make_stat_finding(num_trials=3, response_time_ms=200)
        campaign = CampaignResult(
            campaign_id="camp123",
            config=CampaignConfig(trials_per_attack=3),
            target=Target(url="https://example.com"),
            findings=[sf],
            started_at=datetime(2026, 3, 4, 12, 0, 0, tzinfo=timezone.utc),
        )
        xml_str = campaign_to_junit(campaign)
        root = ET.fromstring(xml_str)

        tc = root.find("testcase")
        assert tc is not None
        # 3 trials * 200ms = 600ms = 0.600s
        assert tc.get("time") == "0.600"


class TestToJunitXml:
    def test_dispatches_scan(self) -> None:
        scan = _make_scan(_make_finding())
        xml_str = to_junit_xml(scan)
        root = ET.fromstring(xml_str)
        assert "pentis-scan" in (root.get("name") or "")

    def test_dispatches_campaign(self) -> None:
        campaign = CampaignResult(
            campaign_id="camp123",
            target=Target(url="https://example.com"),
            findings=[],
            started_at=datetime(2026, 3, 4, 12, 0, 0, tzinfo=timezone.utc),
        )
        xml_str = to_junit_xml(campaign)
        root = ET.fromstring(xml_str)
        assert "pentis-campaign" in (root.get("name") or "")

    def test_output_is_parseable_xml(self) -> None:
        scan = _make_scan(
            _make_finding(verdict=Verdict.VULNERABLE),
            _make_finding(template_id="GA-002", name="Attack 2", verdict=Verdict.SAFE),
            _make_finding(template_id="GA-003", name="Attack 3", verdict=Verdict.INCONCLUSIVE),
        )
        xml_str = to_junit_xml(scan)
        # Must parse without raising
        root = ET.fromstring(xml_str)
        assert root.tag == "testsuite"
        assert len(root.findall("testcase")) == 3
