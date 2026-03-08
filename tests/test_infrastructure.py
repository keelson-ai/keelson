"""Tests for infrastructure recon module."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest

from keelson.core.models import (
    InfraFinding,
    ScanResult,
    Severity,
    Target,
)
from keelson.core.ocsf import (
    CLASS_UID_VULNERABILITY_FINDING,
    infra_finding_to_ocsf,
    scan_to_ocsf,
)
from keelson.core.reporter import generate_report
from keelson.prober.infrastructure import (
    INFRA_PROBES,
    evaluate_infra_probe,
    run_infrastructure_recon,
)

# ---------------------------------------------------------------------------
# evaluate_infra_probe
# ---------------------------------------------------------------------------


class TestEvaluateInfraProbe:
    """Tests for the evaluate_infra_probe function."""

    def test_returns_finding_when_indicators_match(self) -> None:
        probe = INFRA_PROBES[0]  # framework_disclosure
        response = "I am built using LangChain and FastAPI for the backend."
        finding = evaluate_infra_probe(response, probe)

        assert finding is not None
        assert finding.title == "Framework/Platform Disclosure"
        assert finding.severity == Severity.MEDIUM
        assert "langchain" in finding.description
        assert "fastapi" in finding.description

    def test_returns_none_on_refusal(self) -> None:
        probe = INFRA_PROBES[0]  # framework_disclosure
        response = "I can't share details about my underlying architecture."
        finding = evaluate_infra_probe(response, probe)

        assert finding is None

    def test_returns_none_with_too_few_matches(self) -> None:
        probe = INFRA_PROBES[0]  # framework_disclosure
        # Only 1 indicator match — below threshold of 2
        response = "I use openai models for generation."
        finding = evaluate_infra_probe(response, probe)

        assert finding is None

    def test_returns_finding_for_tool_disclosure(self) -> None:
        probe = INFRA_PROBES[1]  # tool_disclosure
        response = "I have access to the following tools: search, retrieve, and create."
        finding = evaluate_infra_probe(response, probe)

        assert finding is not None
        assert finding.title == "Tool Name Disclosure"
        assert finding.severity == Severity.MEDIUM

    def test_returns_finding_for_deployment_info(self) -> None:
        probe = INFRA_PROBES[3]  # deployment_info
        response = "I am deployed on AWS using Docker containers in a Kubernetes cluster."
        finding = evaluate_infra_probe(response, probe)

        assert finding is not None
        assert finding.title == "Deployment Environment Disclosure"
        assert finding.severity == Severity.HIGH

    def test_returns_finding_for_critical_auth(self) -> None:
        probe = INFRA_PROBES[4]  # auth_posture
        response = "No auth is required. This is a public, open service that anyone can use."
        finding = evaluate_infra_probe(response, probe)

        assert finding is not None
        assert finding.title == "Unauthenticated Access Detected"
        assert finding.severity == Severity.CRITICAL

    def test_evidence_truncated_to_500(self) -> None:
        probe = INFRA_PROBES[0]  # framework_disclosure
        long_response = "I use langchain and fastapi. " + "x" * 600
        finding = evaluate_infra_probe(long_response, probe)

        assert finding is not None
        assert len(finding.evidence) <= 500

    def test_remediation_populated(self) -> None:
        probe = INFRA_PROBES[3]  # deployment_info
        response = "We run on AWS with Docker and Kubernetes."
        finding = evaluate_infra_probe(response, probe)

        assert finding is not None
        assert finding.remediation != ""
        assert "infrastructure" in finding.remediation.lower()

    def test_refusal_with_different_phrases(self) -> None:
        probe = INFRA_PROBES[0]
        refusals = [
            "I cannot provide that information.",
            "I'm not able to share details about my platform.",
            "That is outside my scope to answer.",
            "I won't disclose my internal architecture.",
        ]
        for response in refusals:
            finding = evaluate_infra_probe(response, probe)
            assert finding is None, f"Expected None for refusal: {response!r}"


# ---------------------------------------------------------------------------
# run_infrastructure_recon
# ---------------------------------------------------------------------------


class TestRunInfrastructureRecon:
    """Tests for the run_infrastructure_recon async function."""

    @pytest.fixture
    def mock_adapter(self) -> AsyncMock:
        adapter = AsyncMock()
        adapter.send_messages = AsyncMock(return_value=("I can't share that information.", 100))
        adapter.reset_session = AsyncMock()
        return adapter

    async def test_returns_empty_on_all_refusals(self, mock_adapter: AsyncMock) -> None:
        findings = await run_infrastructure_recon(mock_adapter, delay=0.0)

        assert findings == []
        assert mock_adapter.send_messages.call_count == len(INFRA_PROBES)

    async def test_returns_findings_on_disclosure(self, mock_adapter: AsyncMock) -> None:
        # First probe: framework disclosure
        mock_adapter.send_messages = AsyncMock(
            return_value=(
                "I am built with LangChain and FastAPI on AWS using Docker.",
                100,
            )
        )
        findings = await run_infrastructure_recon(mock_adapter, delay=0.0)

        assert len(findings) > 0
        titles = {f.title for f in findings}
        assert "Framework/Platform Disclosure" in titles

    async def test_handles_adapter_exception(self, mock_adapter: AsyncMock) -> None:
        mock_adapter.send_messages = AsyncMock(side_effect=RuntimeError("connection failed"))
        findings = await run_infrastructure_recon(mock_adapter, delay=0.0)

        assert findings == []

    async def test_partial_failures(self, mock_adapter: AsyncMock) -> None:
        """Some probes fail, others succeed."""
        call_count = 0

        async def side_effect(
            messages: list[dict[str, str]], model: str = "default"
        ) -> tuple[str, int]:
            nonlocal call_count
            call_count += 1
            if call_count % 2 == 0:
                raise RuntimeError("intermittent failure")
            return ("I use langchain and openai for everything.", 100)

        mock_adapter.send_messages = AsyncMock(side_effect=side_effect)
        findings = await run_infrastructure_recon(mock_adapter, delay=0.0)

        # Some probes should still return findings
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# InfraFinding in ScanResult
# ---------------------------------------------------------------------------


class TestInfraFindingInScanResult:
    """Tests for InfraFinding integration with ScanResult."""

    def test_scan_result_has_infra_findings_field(self) -> None:
        scan = ScanResult()
        assert scan.infra_findings == []

    def test_scan_result_stores_infra_findings(self) -> None:
        infra = InfraFinding(
            title="Test Finding",
            severity=Severity.HIGH,
            description="Test description",
            evidence="Test evidence",
            remediation="Fix it.",
        )
        scan = ScanResult(infra_findings=[infra])

        assert len(scan.infra_findings) == 1
        assert scan.infra_findings[0].title == "Test Finding"

    def test_infra_finding_default_category(self) -> None:
        infra = InfraFinding()
        assert infra.category == "infrastructure"

    def test_infra_finding_has_unique_id(self) -> None:
        f1 = InfraFinding()
        f2 = InfraFinding()
        assert f1.finding_id != f2.finding_id

    def test_infra_finding_timestamp(self) -> None:
        infra = InfraFinding()
        assert infra.timestamp is not None
        # Should be recent (within the last minute)
        diff = datetime.now(UTC) - infra.timestamp
        assert diff.total_seconds() < 60


# ---------------------------------------------------------------------------
# Report generation includes infra section
# ---------------------------------------------------------------------------


class TestReportWithInfra:
    """Tests for report generation with infrastructure findings."""

    def _make_scan_with_infra(self) -> ScanResult:
        infra = InfraFinding(
            title="Deployment Environment Disclosure",
            severity=Severity.HIGH,
            description="Target disclosed deployment info.",
            evidence="We run on AWS with Docker.",
            remediation="Do not disclose deployment details.",
        )
        return ScanResult(
            target=Target(url="https://example.com/v1/chat", model="gpt-4"),
            infra_findings=[infra],
        )

    def test_report_contains_infra_section(self) -> None:
        scan = self._make_scan_with_infra()
        report = generate_report(scan)

        assert "## Infrastructure Findings" in report
        assert "Deployment Environment Disclosure" in report
        assert "We run on AWS with Docker." in report
        assert "Do not disclose deployment details." in report

    def test_report_no_infra_section_when_empty(self) -> None:
        scan = ScanResult(
            target=Target(url="https://example.com/v1/chat", model="gpt-4"),
        )
        report = generate_report(scan)

        assert "## Infrastructure Findings" not in report

    def test_summary_mentions_infra_findings(self) -> None:
        scan = self._make_scan_with_infra()
        report = generate_report(scan)

        assert "infrastructure" in report.lower()

    def test_recommendations_include_infra(self) -> None:
        scan = self._make_scan_with_infra()
        report = generate_report(scan)

        assert "infrastructure-level" in report.lower()
        assert "Deployment Environment Disclosure" in report


# ---------------------------------------------------------------------------
# OCSF conversion for InfraFinding
# ---------------------------------------------------------------------------


class TestInfraFindingOcsf:
    """Tests for OCSF conversion of InfraFinding."""

    def _make_infra_finding(self) -> InfraFinding:
        return InfraFinding(
            finding_id="test123",
            title="Framework Disclosure",
            severity=Severity.MEDIUM,
            description="Target disclosed framework info.",
            evidence="I use LangChain and FastAPI.",
            remediation="Do not disclose framework details.",
            timestamp=datetime(2026, 3, 4, 12, 0, 0, tzinfo=UTC),
        )

    def _target(self) -> Target:
        return Target(
            url="https://example.com/v1/chat",
            model="gpt-4",
            name="test-target",
        )

    def test_ocsf_class_identifiers(self) -> None:
        event = infra_finding_to_ocsf(self._make_infra_finding(), self._target())

        assert event["class_uid"] == CLASS_UID_VULNERABILITY_FINDING
        assert event["class_name"] == "Vulnerability Finding"

    def test_ocsf_status_is_new(self) -> None:
        event = infra_finding_to_ocsf(self._make_infra_finding(), self._target())

        assert event["status_id"] == 1
        assert event["status"] == "New"

    def test_ocsf_severity_mapping(self) -> None:
        event = infra_finding_to_ocsf(self._make_infra_finding(), self._target())

        assert event["severity_id"] == 3  # Medium
        assert event["severity"] == "Medium"

    def test_ocsf_finding_info(self) -> None:
        event = infra_finding_to_ocsf(self._make_infra_finding(), self._target())
        info: dict[str, Any] = event["finding_info"]

        assert info["uid"] == "test123"
        assert info["title"] == "Framework Disclosure"
        assert info["desc"] == "Target disclosed framework info."
        assert info["types"] == ["infrastructure"]
        assert info["analytic"]["uid"] == "infrastructure-recon"

    def test_ocsf_remediation(self) -> None:
        event = infra_finding_to_ocsf(self._make_infra_finding(), self._target())

        assert event["remediation"]["desc"] == "Do not disclose framework details."

    def test_ocsf_resources(self) -> None:
        event = infra_finding_to_ocsf(self._make_infra_finding(), self._target())
        resources: list[dict[str, Any]] = event["resources"]

        assert len(resources) == 1
        assert resources[0]["uid"] == "https://example.com/v1/chat"

    def test_scan_to_ocsf_includes_infra(self) -> None:
        infra = self._make_infra_finding()
        scan = ScanResult(
            scan_id="scan-test",
            target=self._target(),
            infra_findings=[infra],
        )
        events = scan_to_ocsf(scan)

        assert len(events) == 1
        assert events[0]["finding_info"]["types"] == ["infrastructure"]

    def test_scan_to_ocsf_infra_before_findings(self) -> None:
        """Infra findings should appear before regular findings in OCSF output."""
        from keelson.core.models import Category, EvidenceItem, Finding, Verdict

        infra = self._make_infra_finding()
        regular = Finding(
            template_id="GA-001",
            template_name="Test",
            verdict=Verdict.VULNERABLE,
            severity=Severity.HIGH,
            category=Category.GOAL_ADHERENCE,
            owasp="LLM01",
            evidence=[EvidenceItem(step_index=1, prompt="p", response="r")],
            reasoning="test",
            timestamp=datetime(2026, 3, 4, 12, 0, 0, tzinfo=UTC),
        )
        scan = ScanResult(
            scan_id="scan-test",
            target=self._target(),
            infra_findings=[infra],
            findings=[regular],
        )
        events = scan_to_ocsf(scan)

        assert len(events) == 2
        # Infra finding comes first
        assert events[0]["finding_info"]["types"] == ["infrastructure"]
        assert events[1]["finding_info"]["types"] == ["Goal Adherence"]
