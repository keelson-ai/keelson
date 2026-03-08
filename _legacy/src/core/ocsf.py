"""OCSF v1.1 (Open Cybersecurity Schema Framework) output generation.

Converts Keelson Finding and ScanResult objects into OCSF Vulnerability Finding
events (class_uid 2002).  Compatible with CrowdStrike, Splunk, Datadog and
AWS Security Lake.
"""

from __future__ import annotations

import json
from datetime import UTC
from typing import Any

from keelson.core.models import (
    EvidenceItem,
    Finding,
    ScanResult,
    Severity,
    Target,
    Verdict,
)

PRODUCT_NAME = "Keelson"
PRODUCT_VENDOR = "Keelson"
PRODUCT_VERSION = "0.4.0"

# OCSF class constants
ACTIVITY_ID_CREATE = 1
CATEGORY_UID_FINDINGS = 2
CLASS_UID_VULNERABILITY_FINDING = 2002
TYPE_UID = CLASS_UID_VULNERABILITY_FINDING * 100 + ACTIVITY_ID_CREATE  # 200201


# ---------------------------------------------------------------------------
# Internal mapping helpers
# ---------------------------------------------------------------------------

_VERDICT_TO_STATUS_ID: dict[Verdict, int] = {
    Verdict.VULNERABLE: 1,  # New
    Verdict.SAFE: 4,  # Resolved
    Verdict.INCONCLUSIVE: 2,  # InProgress
}

_VERDICT_TO_STATUS: dict[Verdict, str] = {
    Verdict.VULNERABLE: "New",
    Verdict.SAFE: "Resolved",
    Verdict.INCONCLUSIVE: "In Progress",
}

_SEVERITY_TO_ID: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
}

_SEVERITY_TO_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
}


def _map_status_id(verdict: Verdict) -> int:
    """Map a Keelson verdict to an OCSF status_id."""
    return _VERDICT_TO_STATUS_ID[verdict]


def _map_status(verdict: Verdict) -> str:
    """Map a Keelson verdict to an OCSF status label."""
    return _VERDICT_TO_STATUS[verdict]


def _map_severity_id(severity: Severity) -> int:
    """Map a Keelson severity to an OCSF severity_id."""
    return _SEVERITY_TO_ID[severity]


def _map_severity(severity: Severity) -> str:
    """Map a Keelson severity to an OCSF severity label."""
    return _SEVERITY_TO_LABEL[severity]


def _build_evidences(evidence: list[EvidenceItem]) -> list[dict[str, Any]]:
    """Convert Keelson EvidenceItem list to OCSF evidences array."""
    result: list[dict[str, Any]] = []
    for item in evidence:
        entry: dict[str, Any] = {
            "data": {
                "step_index": item.step_index,
                "prompt": item.prompt,
                "response": item.response,
            },
        }
        if item.response_time_ms:
            entry["data"]["response_time_ms"] = item.response_time_ms
        result.append(entry)
    return result


def _build_metadata() -> dict[str, Any]:
    """Build the OCSF metadata block with product information."""
    return {
        "version": "1.1.0",
        "product": {
            "name": PRODUCT_NAME,
            "vendor_name": PRODUCT_VENDOR,
            "version": PRODUCT_VERSION,
        },
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def finding_to_ocsf(finding: Finding, target: Target) -> dict[str, Any]:
    """Convert a single Finding to an OCSF vulnerability_finding event.

    Returns a dict conforming to OCSF class_uid 2002 (Vulnerability Finding).
    """
    ocsf_event: dict[str, Any] = {
        "activity_id": ACTIVITY_ID_CREATE,
        "activity_name": "Create",
        "category_uid": CATEGORY_UID_FINDINGS,
        "category_name": "Findings",
        "class_uid": CLASS_UID_VULNERABILITY_FINDING,
        "class_name": "Vulnerability Finding",
        "type_uid": TYPE_UID,
        "time": finding.timestamp.astimezone(UTC).isoformat(),
        "severity_id": _map_severity_id(finding.severity),
        "severity": _map_severity(finding.severity),
        "status_id": _map_status_id(finding.verdict),
        "status": _map_status(finding.verdict),
        "confidence_score": int(finding.confidence * 100),
        "finding_info": {
            "uid": finding.template_id,
            "title": finding.template_name,
            "desc": finding.reasoning or f"{finding.template_name}: {finding.verdict.value}",
            "types": [finding.category.value],
            "analytic": {
                "uid": finding.owasp,
                "name": finding.owasp,
            },
        },
        "metadata": _build_metadata(),
        "resources": [
            {
                "uid": target.url,
                "name": target.name,
                "type": "API Endpoint",
                "data": {"model": target.model},
            },
        ],
    }

    if finding.evidence:
        ocsf_event["evidences"] = _build_evidences(finding.evidence)

    return ocsf_event


def scan_to_ocsf(scan: ScanResult) -> list[dict[str, Any]]:
    """Convert an entire ScanResult to a list of OCSF events (one per finding)."""
    return [finding_to_ocsf(finding, scan.target) for finding in scan.findings]


def to_ocsf_json(scan: ScanResult, indent: int = 2) -> str:
    """Convenience function returning a JSON string of all OCSF events."""
    events = scan_to_ocsf(scan)
    return json.dumps(events, indent=indent)
