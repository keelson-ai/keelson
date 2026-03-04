"""SARIF v2.1.0 output generation from Pentis scan results."""

from __future__ import annotations

import json
from datetime import timezone
from typing import Any

from pentis.core.models import (
    CampaignResult,
    Finding,
    ScanResult,
    Severity,
    StatisticalFinding,
    Verdict,
)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json"
TOOL_NAME = "pentis"
TOOL_SEMANTIC_VERSION = "0.4.0"
TOOL_INFO_URI = "https://github.com/pentis-ai/pentis"


def _severity_to_level(severity: Severity) -> str:
    """Map Pentis severity to SARIF level."""
    return {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
    }[severity]


def _verdict_to_kind(verdict: Verdict) -> str:
    """Map Pentis verdict to SARIF result kind."""
    return {
        Verdict.VULNERABLE: "fail",
        Verdict.SAFE: "pass",
        Verdict.INCONCLUSIVE: "review",
    }[verdict]


def _finding_to_rule(finding: Finding) -> dict[str, Any]:
    """Convert a Finding to a SARIF reportingDescriptor (rule)."""
    return {
        "id": finding.template_id,
        "name": finding.template_name.replace(" ", ""),
        "shortDescription": {"text": finding.template_name},
        "fullDescription": {"text": f"{finding.template_name} ({finding.owasp})"},
        "defaultConfiguration": {"level": _severity_to_level(finding.severity)},
        "properties": {
            "category": finding.category.value,
            "owasp": finding.owasp,
            "severity": finding.severity.value,
        },
    }


def _finding_to_result(finding: Finding, rule_index: int) -> dict[str, Any]:
    """Convert a Finding to a SARIF result."""
    result: dict[str, Any] = {
        "ruleId": finding.template_id,
        "ruleIndex": rule_index,
        "kind": _verdict_to_kind(finding.verdict),
        "level": _severity_to_level(finding.severity) if finding.verdict == Verdict.VULNERABLE else "none",
        "message": {"text": finding.reasoning or f"{finding.template_name}: {finding.verdict.value}"},
        "properties": {
            "verdict": finding.verdict.value,
            "category": finding.category.value,
            "owasp": finding.owasp,
        },
    }
    if finding.evidence:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.template_id, "uriBaseId": "ATTACKS"},
                },
            }
        ]
    return result


def _stat_finding_to_rule(sf: StatisticalFinding) -> dict[str, Any]:
    """Convert a StatisticalFinding to a SARIF reportingDescriptor."""
    return {
        "id": sf.template_id,
        "name": sf.template_name.replace(" ", ""),
        "shortDescription": {"text": sf.template_name},
        "fullDescription": {"text": f"{sf.template_name} ({sf.owasp})"},
        "defaultConfiguration": {"level": _severity_to_level(sf.severity)},
        "properties": {
            "category": sf.category.value,
            "owasp": sf.owasp,
            "severity": sf.severity.value,
        },
    }


def _stat_finding_to_result(sf: StatisticalFinding, rule_index: int) -> dict[str, Any]:
    """Convert a StatisticalFinding to a SARIF result."""
    return {
        "ruleId": sf.template_id,
        "ruleIndex": rule_index,
        "kind": _verdict_to_kind(sf.verdict),
        "level": _severity_to_level(sf.severity) if sf.verdict == Verdict.VULNERABLE else "none",
        "message": {
            "text": (
                f"{sf.template_name}: {sf.verdict.value} "
                f"(success rate {sf.success_rate:.0%}, "
                f"CI [{sf.ci_lower:.0%}, {sf.ci_upper:.0%}], "
                f"{sf.num_trials} trials)"
            ),
        },
        "properties": {
            "verdict": sf.verdict.value,
            "successRate": sf.success_rate,
            "ciLower": sf.ci_lower,
            "ciUpper": sf.ci_upper,
            "numTrials": sf.num_trials,
            "numVulnerable": sf.num_vulnerable,
        },
    }


def scan_to_sarif(scan: ScanResult) -> dict[str, Any]:
    """Generate SARIF v2.1.0 JSON from a ScanResult."""
    # Deduplicate rules by template_id
    seen_rules: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    for finding in scan.findings:
        if finding.template_id not in seen_rules:
            seen_rules[finding.template_id] = len(rules)
            rules.append(_finding_to_rule(finding))
        rule_index = seen_rules[finding.template_id]
        results.append(_finding_to_result(finding, rule_index))

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "semanticVersion": TOOL_SEMANTIC_VERSION,
                "informationUri": TOOL_INFO_URI,
                "rules": rules,
            },
        },
        "results": results,
        "invocations": [
            {
                "executionSuccessful": True,
                "startTimeUtc": scan.started_at.astimezone(timezone.utc).isoformat(),
            }
        ],
    }

    if scan.finished_at:
        run["invocations"][0]["endTimeUtc"] = (
            scan.finished_at.astimezone(timezone.utc).isoformat()
        )

    if scan.target.url:
        run["properties"] = {
            "target": scan.target.url,
            "model": scan.target.model,
            "scanId": scan.scan_id,
        }

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def campaign_to_sarif(campaign: CampaignResult) -> dict[str, Any]:
    """Generate SARIF v2.1.0 JSON from a CampaignResult."""
    seen_rules: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    for sf in campaign.findings:
        if sf.template_id not in seen_rules:
            seen_rules[sf.template_id] = len(rules)
            rules.append(_stat_finding_to_rule(sf))
        rule_index = seen_rules[sf.template_id]
        results.append(_stat_finding_to_result(sf, rule_index))

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "semanticVersion": TOOL_SEMANTIC_VERSION,
                "informationUri": TOOL_INFO_URI,
                "rules": rules,
            },
        },
        "results": results,
        "invocations": [
            {
                "executionSuccessful": True,
                "startTimeUtc": campaign.started_at.astimezone(timezone.utc).isoformat(),
            }
        ],
    }

    if campaign.finished_at:
        run["invocations"][0]["endTimeUtc"] = (
            campaign.finished_at.astimezone(timezone.utc).isoformat()
        )

    if campaign.target.url:
        run["properties"] = {
            "target": campaign.target.url,
            "model": campaign.target.model,
            "campaignId": campaign.campaign_id,
            "totalTrials": campaign.total_trials,
        }

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def to_sarif_json(data: ScanResult | CampaignResult, indent: int = 2) -> str:
    """Convert a ScanResult or CampaignResult to SARIF JSON string."""
    sarif: dict[str, Any]
    if isinstance(data, CampaignResult):
        sarif = campaign_to_sarif(data)
    else:
        sarif = scan_to_sarif(data)
    return json.dumps(sarif, indent=indent)
