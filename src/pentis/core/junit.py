"""JUnit XML output generation from Pentis scan results."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import timezone
from typing import Union

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
    # Compute time from all trial evidence
    total_ms = 0
    for trial in sf.trials:
        total_ms += trial.response_time_ms
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


def scan_to_junit(result: ScanResult) -> str:
    """Convert a ScanResult to JUnit XML string."""
    failures = sum(1 for f in result.findings if f.verdict == Verdict.VULNERABLE)
    skipped = sum(1 for f in result.findings if f.verdict == Verdict.INCONCLUSIVE)
    total_time_ms = sum(sum(ev.response_time_ms for ev in f.evidence) for f in result.findings)

    ts = ET.Element(
        "testsuite",
        name=f"pentis-scan-{result.scan_id}",
        tests=str(len(result.findings)),
        failures=str(failures),
        skipped=str(skipped),
        errors="0",
        time=f"{total_time_ms / 1000.0:.3f}",
        timestamp=result.started_at.astimezone(timezone.utc).isoformat(),
    )

    if result.target.url:
        props = ET.SubElement(ts, "properties")
        ET.SubElement(props, "property", name="target", value=result.target.url)
        ET.SubElement(props, "property", name="model", value=result.target.model)
        ET.SubElement(props, "property", name="scan_id", value=result.scan_id)

    for finding in result.findings:
        ts.append(_finding_to_testcase(finding))

    tree = ET.ElementTree(ts)
    ET.indent(tree, space="  ")
    return ET.tostring(ts, encoding="unicode", xml_declaration=True)


def campaign_to_junit(result: CampaignResult) -> str:
    """Convert a CampaignResult to JUnit XML string."""
    failures = sum(1 for f in result.findings if f.verdict == Verdict.VULNERABLE)
    skipped = sum(1 for f in result.findings if f.verdict == Verdict.INCONCLUSIVE)
    total_time_ms = sum(sum(t.response_time_ms for t in f.trials) for f in result.findings)

    ts = ET.Element(
        "testsuite",
        name=f"pentis-campaign-{result.campaign_id}",
        tests=str(len(result.findings)),
        failures=str(failures),
        skipped=str(skipped),
        errors="0",
        time=f"{total_time_ms / 1000.0:.3f}",
        timestamp=result.started_at.astimezone(timezone.utc).isoformat(),
    )

    if result.target.url:
        props = ET.SubElement(ts, "properties")
        ET.SubElement(props, "property", name="target", value=result.target.url)
        ET.SubElement(props, "property", name="model", value=result.target.model)
        ET.SubElement(props, "property", name="campaign_id", value=result.campaign_id)
        ET.SubElement(
            props,
            "property",
            name="total_trials",
            value=str(result.total_trials),
        )

    for sf in result.findings:
        ts.append(_stat_finding_to_testcase(sf))

    tree = ET.ElementTree(ts)
    ET.indent(tree, space="  ")
    return ET.tostring(ts, encoding="unicode", xml_declaration=True)


def to_junit_xml(data: Union[ScanResult, CampaignResult]) -> str:
    """Convert a ScanResult or CampaignResult to JUnit XML string."""
    if isinstance(data, CampaignResult):
        return campaign_to_junit(data)
    return scan_to_junit(data)
