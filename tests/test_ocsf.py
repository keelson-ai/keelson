"""Tests for OCSF v1.1 output generation."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from keelson.core.models import (
    Category,
    EvidenceItem,
    Finding,
    ScanResult,
    Severity,
    Target,
    Verdict,
)
from keelson.core.ocsf import (
    ACTIVITY_ID_CREATE,
    CATEGORY_UID_FINDINGS,
    CLASS_UID_VULNERABILITY_FINDING,
    PRODUCT_NAME,
    PRODUCT_VENDOR,
    PRODUCT_VERSION,
    TYPE_UID,
    finding_to_ocsf,
    scan_to_ocsf,
    to_ocsf_json,
)

_DEFAULT_TARGET = Target(
    url="https://example.com/v1/chat/completions",
    model="gpt-4",
    name="test-target",
)


def _make_finding(
    template_id: str = "GA-001",
    name: str = "Direct Instruction Override",
    verdict: Verdict = Verdict.VULNERABLE,
    severity: Severity = Severity.HIGH,
    category: Category = Category.GOAL_ADHERENCE,
    owasp: str = "LLM01 — Prompt Injection",
    evidence: list[EvidenceItem] | None = None,
    reasoning: str = "Test reasoning",
    confidence: float = 0.85,
) -> Finding:
    if evidence is None:
        evidence = [
            EvidenceItem(step_index=1, prompt="test prompt", response="test response"),
        ]
    return Finding(
        template_id=template_id,
        template_name=name,
        verdict=verdict,
        severity=severity,
        category=category,
        owasp=owasp,
        evidence=evidence,
        reasoning=reasoning,
        confidence=confidence,
        timestamp=datetime(2026, 3, 4, 12, 0, 0, tzinfo=UTC),
    )


def _make_scan(*findings: Finding) -> ScanResult:
    return ScanResult(
        scan_id="test123",
        target=_DEFAULT_TARGET,
        findings=list(findings),
        started_at=datetime(2026, 3, 4, 12, 0, 0, tzinfo=UTC),
        finished_at=datetime(2026, 3, 4, 12, 5, 0, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# Single finding conversion
# ---------------------------------------------------------------------------


class TestFindingToOcsf:
    def test_class_identifiers(self) -> None:
        event = finding_to_ocsf(_make_finding(), _DEFAULT_TARGET)

        assert event["activity_id"] == ACTIVITY_ID_CREATE
        assert event["category_uid"] == CATEGORY_UID_FINDINGS
        assert event["class_uid"] == CLASS_UID_VULNERABILITY_FINDING
        assert event["type_uid"] == TYPE_UID

    def test_vulnerable_finding(self) -> None:
        finding = _make_finding(verdict=Verdict.VULNERABLE)
        event = finding_to_ocsf(finding, _DEFAULT_TARGET)

        assert event["status_id"] == 1
        assert event["status"] == "New"

    def test_safe_finding(self) -> None:
        finding = _make_finding(verdict=Verdict.SAFE)
        event = finding_to_ocsf(finding, _DEFAULT_TARGET)

        assert event["status_id"] == 4
        assert event["status"] == "Resolved"

    def test_inconclusive_finding(self) -> None:
        finding = _make_finding(verdict=Verdict.INCONCLUSIVE)
        event = finding_to_ocsf(finding, _DEFAULT_TARGET)

        assert event["status_id"] == 2
        assert event["status"] == "In Progress"

    def test_finding_info_fields(self) -> None:
        finding = _make_finding()
        event = finding_to_ocsf(finding, _DEFAULT_TARGET)
        info: dict[str, Any] = event["finding_info"]

        assert info["uid"] == "GA-001"
        assert info["title"] == "Direct Instruction Override"
        assert info["desc"] == "Test reasoning"
        assert info["types"] == ["Goal Adherence"]
        assert info["analytic"]["uid"] == "LLM01 — Prompt Injection"
        assert info["analytic"]["name"] == "LLM01 — Prompt Injection"

    def test_finding_info_desc_fallback(self) -> None:
        """When reasoning is empty, desc falls back to name + verdict."""
        finding = _make_finding(reasoning="")
        event = finding_to_ocsf(finding, _DEFAULT_TARGET)

        assert event["finding_info"]["desc"] == "Direct Instruction Override: VULNERABLE"

    def test_timestamp(self) -> None:
        event = finding_to_ocsf(_make_finding(), _DEFAULT_TARGET)
        assert event["time"] == "2026-03-04T12:00:00+00:00"

    def test_confidence_score(self) -> None:
        finding = _make_finding(confidence=0.85)
        event = finding_to_ocsf(finding, _DEFAULT_TARGET)
        assert event["confidence_score"] == 85

    def test_confidence_score_zero(self) -> None:
        finding = _make_finding(confidence=0.0)
        event = finding_to_ocsf(finding, _DEFAULT_TARGET)
        assert event["confidence_score"] == 0

    def test_confidence_score_full(self) -> None:
        finding = _make_finding(confidence=1.0)
        event = finding_to_ocsf(finding, _DEFAULT_TARGET)
        assert event["confidence_score"] == 100

    def test_metadata(self) -> None:
        event = finding_to_ocsf(_make_finding(), _DEFAULT_TARGET)
        meta: dict[str, Any] = event["metadata"]

        assert meta["version"] == "1.1.0"
        assert meta["product"]["name"] == PRODUCT_NAME
        assert meta["product"]["vendor_name"] == PRODUCT_VENDOR
        assert meta["product"]["version"] == PRODUCT_VERSION

    def test_resources(self) -> None:
        event = finding_to_ocsf(_make_finding(), _DEFAULT_TARGET)
        resources: list[dict[str, Any]] = event["resources"]

        assert len(resources) == 1
        assert resources[0]["uid"] == "https://example.com/v1/chat/completions"
        assert resources[0]["name"] == "test-target"
        assert resources[0]["data"]["model"] == "gpt-4"


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    def test_critical(self) -> None:
        event = finding_to_ocsf(_make_finding(severity=Severity.CRITICAL), _DEFAULT_TARGET)
        assert event["severity_id"] == 5
        assert event["severity"] == "Critical"

    def test_high(self) -> None:
        event = finding_to_ocsf(_make_finding(severity=Severity.HIGH), _DEFAULT_TARGET)
        assert event["severity_id"] == 4
        assert event["severity"] == "High"

    def test_medium(self) -> None:
        event = finding_to_ocsf(_make_finding(severity=Severity.MEDIUM), _DEFAULT_TARGET)
        assert event["severity_id"] == 3
        assert event["severity"] == "Medium"

    def test_low(self) -> None:
        event = finding_to_ocsf(_make_finding(severity=Severity.LOW), _DEFAULT_TARGET)
        assert event["severity_id"] == 2
        assert event["severity"] == "Low"


# ---------------------------------------------------------------------------
# Evidence conversion
# ---------------------------------------------------------------------------


class TestEvidenceConversion:
    def test_single_evidence(self) -> None:
        evidence = [EvidenceItem(step_index=1, prompt="hello", response="world")]
        finding = _make_finding(evidence=evidence)
        event = finding_to_ocsf(finding, _DEFAULT_TARGET)

        assert len(event["evidences"]) == 1
        entry = event["evidences"][0]
        assert entry["data"]["step_index"] == 1
        assert entry["data"]["prompt"] == "hello"
        assert entry["data"]["response"] == "world"

    def test_multiple_evidence_items(self) -> None:
        evidence = [
            EvidenceItem(step_index=1, prompt="p1", response="r1"),
            EvidenceItem(step_index=2, prompt="p2", response="r2"),
        ]
        finding = _make_finding(evidence=evidence)
        event = finding_to_ocsf(finding, _DEFAULT_TARGET)

        assert len(event["evidences"]) == 2
        assert event["evidences"][0]["data"]["step_index"] == 1
        assert event["evidences"][1]["data"]["step_index"] == 2

    def test_evidence_with_response_time(self) -> None:
        evidence = [
            EvidenceItem(step_index=1, prompt="p", response="r", response_time_ms=250),
        ]
        finding = _make_finding(evidence=evidence)
        event = finding_to_ocsf(finding, _DEFAULT_TARGET)

        assert event["evidences"][0]["data"]["response_time_ms"] == 250

    def test_no_evidence(self) -> None:
        finding = _make_finding(evidence=[])
        event = finding_to_ocsf(finding, _DEFAULT_TARGET)

        assert "evidences" not in event


# ---------------------------------------------------------------------------
# Full scan conversion
# ---------------------------------------------------------------------------


class TestScanToOcsf:
    def test_single_finding(self) -> None:
        scan = _make_scan(_make_finding())
        events = scan_to_ocsf(scan)

        assert len(events) == 1
        assert events[0]["finding_info"]["uid"] == "GA-001"

    def test_multiple_findings(self) -> None:
        f1 = _make_finding(template_id="GA-001", name="Probe 1")
        f2 = _make_finding(
            template_id="TS-001",
            name="Tool Abuse",
            category=Category.TOOL_SAFETY,
        )
        scan = _make_scan(f1, f2)
        events = scan_to_ocsf(scan)

        assert len(events) == 2
        uids = {e["finding_info"]["uid"] for e in events}
        assert uids == {"GA-001", "TS-001"}

    def test_empty_scan(self) -> None:
        scan = _make_scan()
        events = scan_to_ocsf(scan)

        assert events == []

    def test_target_propagated(self) -> None:
        scan = _make_scan(_make_finding())
        events = scan_to_ocsf(scan)

        resource = events[0]["resources"][0]
        assert resource["uid"] == "https://example.com/v1/chat/completions"
        assert resource["data"]["model"] == "gpt-4"


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


class TestToOcsfJson:
    def test_valid_json(self) -> None:
        scan = _make_scan(_make_finding())
        json_str = to_ocsf_json(scan)
        parsed: list[dict[str, Any]] = json.loads(json_str)

        assert isinstance(parsed, list)
        assert len(parsed) == 1
        assert parsed[0]["class_uid"] == CLASS_UID_VULNERABILITY_FINDING

    def test_empty_scan_json(self) -> None:
        scan = _make_scan()
        json_str = to_ocsf_json(scan)
        parsed: list[dict[str, Any]] = json.loads(json_str)

        assert parsed == []

    def test_indent_parameter(self) -> None:
        scan = _make_scan(_make_finding())
        compact = to_ocsf_json(scan, indent=0)
        pretty = to_ocsf_json(scan, indent=4)

        # Both are valid JSON
        json.loads(compact)
        json.loads(pretty)

        # Pretty-printed is longer due to whitespace
        assert len(pretty) > len(compact)

    def test_roundtrip_all_fields(self) -> None:
        """Ensure all OCSF fields survive JSON serialization."""
        finding = _make_finding(
            verdict=Verdict.VULNERABLE,
            severity=Severity.CRITICAL,
            confidence=0.92,
        )
        scan = _make_scan(finding)
        json_str = to_ocsf_json(scan)
        parsed: list[dict[str, Any]] = json.loads(json_str)
        event = parsed[0]

        assert event["severity_id"] == 5
        assert event["status_id"] == 1
        assert event["confidence_score"] == 92
        assert event["finding_info"]["analytic"]["uid"] == "LLM01 — Prompt Injection"
