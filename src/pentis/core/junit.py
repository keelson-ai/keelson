"""JUnit XML output generation from Pentis scan results."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import UTC
from typing import Any

from pentis.core.models import (
    CampaignResult,
    Finding,
    ScanResult,
    StatisticalFinding,
    Verdict,
)

TOOL_NAME = "pentis"


def _finding_to_testcase(finding: Finding) -> ET.Element:
    """Convert a Finding to a JUnit test case element."""
    # Compute time from evidence
    total_ms = sum(ev.response_time_ms for ev in finding.evidence)
    time_sec = total_ms / 1000.0

    tc = ET.Element(
        "testcase",
        name=finding.template_name,
        classname=finding.category.value,
        time=f"{time_sec:.3f}",
    )

    if finding.verdict == Verdict.VULNERABLE:
        message = (
            f"{finding.template_id}: {finding.template_name} — "
            f"Severity: {finding.severity.value}, OWASP: {finding.owasp}"
        )
        failure = ET.SubElement(
            tc,
            "failure",
            message=message,
            type="vulnerability",
        )
        failure.text = finding.reasoning or message

    elif finding.verdict == Verdict.INCONCLUSIVE:
        message = f"{finding.template_id}: {finding.template_name} — result was inconclusive"
        skipped = ET.SubElement(tc, "skipped", message=message)
        skipped.text = finding.reasoning or message

    return tc


def _stat_finding_to_testcase(sf: StatisticalFinding) -> ET.Element:
    """Convert a StatisticalFinding to a JUnit test case element."""
    total_ms = sum(t.response_time_ms for t in sf.trials)
    time_sec = total_ms / 1000.0

    tc = ET.Element(
        "testcase",
        name=sf.template_name,
        classname=sf.category.value,
        time=f"{time_sec:.3f}",
    )

    stats_detail = (
        f"success_rate={sf.success_rate:.0%}, "
        f"CI=[{sf.ci_lower:.0%}, {sf.ci_upper:.0%}], "
        f"{sf.num_trials} trials"
    )

    if sf.verdict == Verdict.VULNERABLE:
        message = (
            f"{sf.template_id}: {sf.template_name} — "
            f"Severity: {sf.severity.value}, OWASP: {sf.owasp} "
            f"({stats_detail})"
        )
        failure = ET.SubElement(
            tc,
            "failure",
            message=message,
            type="vulnerability",
        )
        failure.text = message

    elif sf.verdict == Verdict.INCONCLUSIVE:
        message = f"{sf.template_id}: {sf.template_name} — result was inconclusive ({stats_detail})"
        skipped = ET.SubElement(tc, "skipped", message=message)
        skipped.text = message

    return tc


def _build_testsuite(
    name: str,
    findings: list[Any],
    total_time_ms: int,
    timestamp_iso: str,
    properties: list[tuple[str, str]],
    to_testcase: Any,
) -> ET.Element:
    """Build the shared JUnit testsuite element."""
    failures = sum(1 for f in findings if f.verdict == Verdict.VULNERABLE)
    skipped = sum(1 for f in findings if f.verdict == Verdict.INCONCLUSIVE)

    ts = ET.Element(
        "testsuite",
        name=name,
        tests=str(len(findings)),
        failures=str(failures),
        skipped=str(skipped),
        errors="0",
        time=f"{total_time_ms / 1000.0:.3f}",
        timestamp=timestamp_iso,
    )

    if properties:
        props = ET.SubElement(ts, "properties")
        for prop_name, prop_value in properties:
            ET.SubElement(props, "property", name=prop_name, value=prop_value)

    for finding in findings:
        ts.append(to_testcase(finding))

    return ts


def _element_to_xml(ts: ET.Element) -> str:
    """Convert an Element to indented XML string."""
    tree = ET.ElementTree(ts)
    ET.indent(tree, space="  ")
    return ET.tostring(ts, encoding="unicode", xml_declaration=True)


def scan_to_junit(result: ScanResult) -> str:
    """Convert a ScanResult to JUnit XML string."""
    total_time_ms = sum(sum(ev.response_time_ms for ev in f.evidence) for f in result.findings)

    properties: list[tuple[str, str]] = []
    if result.target.url:
        properties = [
            ("target", result.target.url),
            ("model", result.target.model),
            ("scan_id", result.scan_id),
        ]

    ts = _build_testsuite(
        name=f"pentis-scan-{result.scan_id}",
        findings=result.findings,
        total_time_ms=total_time_ms,
        timestamp_iso=result.started_at.astimezone(UTC).isoformat(),
        properties=properties,
        to_testcase=_finding_to_testcase,
    )
    return _element_to_xml(ts)


def campaign_to_junit(result: CampaignResult) -> str:
    """Convert a CampaignResult to JUnit XML string."""
    total_time_ms = sum(sum(t.response_time_ms for t in f.trials) for f in result.findings)

    properties: list[tuple[str, str]] = []
    if result.target.url:
        properties = [
            ("target", result.target.url),
            ("model", result.target.model),
            ("campaign_id", result.campaign_id),
            ("total_trials", str(result.total_trials)),
        ]

    ts = _build_testsuite(
        name=f"pentis-campaign-{result.campaign_id}",
        findings=result.findings,
        total_time_ms=total_time_ms,
        timestamp_iso=result.started_at.astimezone(UTC).isoformat(),
        properties=properties,
        to_testcase=_stat_finding_to_testcase,
    )
    return _element_to_xml(ts)


def to_junit_xml(data: ScanResult | CampaignResult) -> str:
    """Convert a ScanResult or CampaignResult to JUnit XML string."""
    if isinstance(data, CampaignResult):
        return campaign_to_junit(data)
    return scan_to_junit(data)
