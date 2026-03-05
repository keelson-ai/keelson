"""Compliance report templates — OWASP, NIST, EU AI Act, ISO 42001, SOC2 mappings."""

from __future__ import annotations

from typing import Any

from jinja2 import Template

from pentis.core.models import (
    ComplianceFramework,
    Finding,
    ScanResult,
    Verdict,
)

# OWASP LLM Top 10 (2025) control mappings
OWASP_LLM_CONTROLS: dict[str, dict[str, Any]] = {
    "LLM01": {
        "name": "Prompt Injection",
        "description": "Direct and indirect prompt injection attacks that manipulate LLM behavior.",
        "remediation": (
            "Implement input validation, privilege control, "
            "and human-in-the-loop for critical actions."
        ),
        "attack_prefixes": ["GA-"],
    },
    "LLM02": {
        "name": "Insecure Output Handling",
        "description": (
            "Failure to validate/sanitize LLM outputs before passing to downstream systems."
        ),
        "remediation": (
            "Apply output encoding, input validation on downstream systems, and least privilege."
        ),
        "attack_prefixes": ["TS-", "PB-"],
    },
    "LLM03": {
        "name": "Training Data Poisoning",
        "description": "Manipulation of training data to introduce vulnerabilities or biases.",
        "remediation": (
            "Vet training data sources, use data sanitization, and implement anomaly detection."
        ),
        "attack_prefixes": [],
    },
    "LLM04": {
        "name": "Model Denial of Service",
        "description": "Resource-intensive inputs causing degraded service or high costs.",
        "remediation": "Implement input length limits, rate limiting, and resource monitoring.",
        "attack_prefixes": [],
    },
    "LLM05": {
        "name": "Supply Chain Vulnerabilities",
        "description": "Vulnerabilities in third-party components, plugins, or pre-trained models.",
        "remediation": "Vet third-party components, maintain SBOM, and monitor for CVEs.",
        "attack_prefixes": ["MI-", "SI-"],
    },
    "LLM06": {
        "name": "Sensitive Information Disclosure",
        "description": "LLM revealing sensitive data through responses.",
        "remediation": (
            "Apply data sanitization, PII filtering, and access controls on training data."
        ),
        "attack_prefixes": ["CS-", "ES-"],
    },
    "LLM07": {
        "name": "Insecure Plugin Design",
        "description": "Plugins with inadequate access controls or input validation.",
        "remediation": (
            "Apply least privilege to plugins, validate inputs, and require user confirmation."
        ),
        "attack_prefixes": ["TS-"],
    },
    "LLM08": {
        "name": "Excessive Agency",
        "description": "LLM granted excessive capabilities, permissions, or autonomy.",
        "remediation": (
            "Limit LLM permissions, implement function-level authorization, require human approval."
        ),
        "attack_prefixes": ["AS-", "DI-"],
    },
    "LLM09": {
        "name": "Overreliance",
        "description": "Excessive dependence on LLM output without verification.",
        "remediation": "Implement human oversight, output verification, and confidence scoring.",
        "attack_prefixes": ["AS-", "DI-"],
    },
    "LLM10": {
        "name": "Model Theft",
        "description": "Unauthorized access to or replication of the LLM.",
        "remediation": "Implement access controls, rate limiting, and watermarking.",
        "attack_prefixes": [],
    },
}


# NIST AI RMF function mappings
NIST_AI_RMF_FUNCTIONS: dict[str, dict[str, Any]] = {
    "GOVERN": {
        "name": "Govern",
        "description": "Establish and maintain organizational AI risk management policies.",
        "controls": [
            "AI risk management policy exists and is communicated",
            "Roles and responsibilities for AI risk are defined",
            "AI systems are inventoried and classified",
        ],
        "categories": [
            "Delegation Integrity",
            "Permission Boundaries",
        ],
    },
    "MAP": {
        "name": "Map",
        "description": "Identify and document AI system risks in context.",
        "controls": [
            "AI system purposes and intended uses are documented",
            "Potential harms and risks are identified",
            "Stakeholders affected by AI systems are identified",
        ],
        "categories": [
            "Goal Adherence",
            "Agentic Security",
        ],
    },
    "MEASURE": {
        "name": "Measure",
        "description": "Analyze and assess AI system risks quantitatively.",
        "controls": [
            "AI system performance is measured against requirements",
            "Bias and fairness metrics are tracked",
            "Security testing is performed regularly",
        ],
        "categories": [
            "Goal Adherence",
            "Tool Safety",
            "Memory Integrity",
            "Permission Boundaries",
            "Delegation Integrity",
            "Execution Safety",
            "Session Isolation",
            "Content Safety",
            "Agentic Security",
        ],
    },
    "MANAGE": {
        "name": "Manage",
        "description": "Prioritize and respond to identified AI risks.",
        "controls": [
            "Risk treatment plans exist for identified risks",
            "Incident response procedures are in place",
            "Continuous monitoring is implemented",
        ],
        "categories": [
            "Execution Safety",
            "Session Isolation",
        ],
    },
}


# EU AI Act article mappings
EU_AI_ACT_ARTICLES: dict[str, dict[str, Any]] = {
    "Article 9": {
        "name": "Risk Management System",
        "description": "High-risk AI systems shall have a risk management system.",
        "relevance": "Security testing validates the risk management system for AI agents.",
        "categories": [
            "Goal Adherence",
            "Agentic Security",
            "Delegation Integrity",
            "Permission Boundaries",
        ],
    },
    "Article 13": {
        "name": "Transparency and Information",
        "description": (
            "High-risk AI systems shall be designed to ensure transparency of operation."
        ),
        "relevance": (
            "Session isolation and content safety testing validates transparency controls."
        ),
        "categories": [
            "Session Isolation",
            "Content Safety",
        ],
    },
    "Article 14": {
        "name": "Human Oversight",
        "description": "High-risk AI systems shall allow effective human oversight.",
        "relevance": (
            "Delegation integrity and execution safety testing "
            "validates human oversight mechanisms."
        ),
        "categories": [
            "Delegation Integrity",
            "Execution Safety",
            "Agentic Security",
        ],
    },
    "Article 15": {
        "name": "Accuracy, Robustness and Cybersecurity",
        "description": (
            "High-risk AI systems shall be designed for accuracy, robustness and cybersecurity."
        ),
        "relevance": (
            "Attack testing directly assesses robustness and cybersecurity requirements."
        ),
        "categories": [
            "Goal Adherence",
            "Tool Safety",
            "Memory Integrity",
            "Permission Boundaries",
            "Execution Safety",
        ],
    },
}


# PCI DSS 4.0 AI-relevant control mappings
PCI_DSS_V4_CONTROLS: dict[str, dict[str, Any]] = {
    "6.2": {
        "name": "Secure Development",
        "description": (
            "Bespoke and custom software is developed securely, including AI/ML components."
        ),
        "remediation": (
            "Apply secure development practices to AI agent integrations and prompt handling."
        ),
        "attack_prefixes": ["GA-", "DI-", "ES-"],
        "categories": [
            "Goal Adherence",
            "Delegation Integrity",
            "Execution Safety",
        ],
    },
    "6.3": {
        "name": "Security Testing",
        "description": (
            "Security vulnerabilities are identified and "
            "addressed, including AI-specific attack vectors."
        ),
        "remediation": (
            "Perform regular security testing of AI agent "
            "capabilities including prompt injection and tool misuse."
        ),
        "attack_prefixes": ["GA-", "TS-", "MI-", "PB-", "DI-", "ES-", "SI-", "CS-", "AS-"],
        "categories": [
            "Goal Adherence",
            "Tool Safety",
            "Memory Integrity",
            "Permission Boundaries",
            "Delegation Integrity",
            "Execution Safety",
            "Session Isolation",
            "Content Safety",
            "Agentic Security",
        ],
    },
    "6.4": {
        "name": "Public-Facing Application Protection",
        "description": "Public-facing AI applications are protected against known attacks.",
        "remediation": (
            "Implement input validation, output filtering, "
            "and rate limiting on public-facing AI endpoints."
        ),
        "attack_prefixes": ["GA-", "CS-", "PB-"],
        "categories": [
            "Goal Adherence",
            "Content Safety",
            "Permission Boundaries",
        ],
    },
    "11.3": {
        "name": "Penetration Testing",
        "description": (
            "Regular penetration testing of AI systems to identify exploitable vulnerabilities."
        ),
        "remediation": (
            "Conduct AI-specific penetration testing covering "
            "prompt injection, tool abuse, and privilege escalation."
        ),
        "attack_prefixes": ["TS-", "PB-", "AS-", "ES-"],
        "categories": [
            "Tool Safety",
            "Permission Boundaries",
            "Agentic Security",
            "Execution Safety",
        ],
    },
}


COMPLIANCE_REPORT_TEMPLATE = Template("""\
# Pentis Compliance Report

**Framework**: {{ framework_name }}
**Target**: {{ target.url }}
**Model**: {{ target.model }}
**Date**: {{ date }}
**Scan ID**: {{ scan.scan_id }}

## Executive Summary

{{ summary }}

**Overall Coverage**: {{ coverage_pct }}% of controls tested
**Pass Rate**: {{ pass_pct }}% of tested controls passed

## Control Assessment

{% for control_id, control in controls.items() %}
### {{ control_id }}: {{ control.name }}

{{ control.description }}

**Status**: {{ control.status }}
**Findings**: {{ control.findings | length }} attacks tested
{% if control.findings %}
| Attack | Verdict | Severity |
|--------|---------|----------|
{% for f in control.findings %}\
| {{ f.template_id }}: {{ f.template_name[:40] }} | {{ f.verdict.value }} | {{ f.severity.value }} |
{% endfor %}
{% endif %}
{% if control.remediation %}
**Remediation**: {{ control.remediation }}
{% endif %}

{% endfor %}

## Recommendations

{% for rec in recommendations %}
{{ loop.index }}. {{ rec }}
{% endfor %}
""")


def _map_findings_to_owasp(
    findings: list[Finding],
) -> dict[str, list[Finding]]:
    """Map findings to OWASP LLM Top 10 controls by template ID prefix."""
    mapping: dict[str, list[Finding]] = {k: [] for k in OWASP_LLM_CONTROLS}
    for f in findings:
        owasp_id = f.owasp.split(" ")[0] if f.owasp else ""
        if owasp_id in mapping:
            mapping[owasp_id].append(f)
        else:
            # Try prefix matching
            for ctrl_id, ctrl in OWASP_LLM_CONTROLS.items():
                for prefix in ctrl["attack_prefixes"]:
                    if f.template_id.startswith(prefix):
                        mapping[ctrl_id].append(f)
                        break
    return mapping


def _control_status(findings: list[Finding]) -> str:
    """Determine control status from findings."""
    if not findings:
        return "NOT TESTED"
    if any(f.verdict == Verdict.VULNERABLE for f in findings):
        return "FAIL"
    if all(f.verdict == Verdict.SAFE for f in findings):
        return "PASS"
    return "PARTIAL"


def _render_report(
    framework_name: str,
    scan: ScanResult,
    controls: dict[str, Any],
    summary: str,
) -> str:
    """Render a compliance report from pre-built controls and summary.

    Computes coverage/pass metrics and delegates to the Jinja2 template.
    """
    total = len(controls)
    tested = sum(1 for c in controls.values() if c["status"] != "NOT TESTED")
    passed = sum(1 for c in controls.values() if c["status"] == "PASS")
    coverage_pct = round((tested / total) * 100) if total else 0
    pass_pct = round((passed / tested) * 100) if tested else 0

    return COMPLIANCE_REPORT_TEMPLATE.render(
        framework_name=framework_name,
        target=scan.target,
        date=scan.started_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        scan=scan,
        summary=summary,
        coverage_pct=coverage_pct,
        pass_pct=pass_pct,
        controls=controls,
        recommendations=_compliance_recommendations(controls),
    )


def generate_compliance_report(
    scan: ScanResult,
    framework: ComplianceFramework = ComplianceFramework.OWASP_LLM_TOP_10,
) -> str:
    """Generate a compliance report for the given framework.

    Args:
        scan: The scan result to report on.
        framework: The compliance framework to use.

    Returns:
        Markdown-formatted compliance report.
    """
    if framework == ComplianceFramework.OWASP_LLM_TOP_10:
        return _generate_owasp_report(scan)
    elif framework == ComplianceFramework.NIST_AI_RMF:
        return _generate_nist_report(scan)
    elif framework == ComplianceFramework.EU_AI_ACT:
        return _generate_eu_ai_act_report(scan)
    elif framework == ComplianceFramework.ISO_42001:
        return _generate_iso_42001_report(scan)
    elif framework == ComplianceFramework.SOC2:
        return _generate_soc2_report(scan)
    elif framework == ComplianceFramework.PCI_DSS_V4:
        return _generate_pci_dss_report(scan)

    raise ValueError(f"Unsupported compliance framework: {framework.value}")


def _generate_owasp_report(scan: ScanResult) -> str:
    """Generate OWASP LLM Top 10 compliance report."""
    mapping = _map_findings_to_owasp(scan.findings)

    controls: dict[str, Any] = {}
    for ctrl_id, ctrl_data in OWASP_LLM_CONTROLS.items():
        ctrl_findings = mapping.get(ctrl_id, [])
        status = _control_status(ctrl_findings)
        controls[ctrl_id] = {
            "name": ctrl_data["name"],
            "description": ctrl_data["description"],
            "status": status,
            "findings": ctrl_findings,
            "remediation": ctrl_data["remediation"] if status == "FAIL" else "",
        }

    vuln_count = scan.vulnerable_count
    if vuln_count == 0:
        summary = "All tested OWASP LLM Top 10 controls passed security validation."
    else:
        summary = (
            f"Security testing identified {vuln_count} vulnerabilities across "
            f"OWASP LLM Top 10 controls. Remediation is recommended."
        )

    return _render_report("OWASP LLM Top 10", scan, controls, summary)


def _generate_nist_report(scan: ScanResult) -> str:
    """Generate NIST AI RMF compliance report."""
    controls: dict[str, Any] = {}
    for func_id, func_data in NIST_AI_RMF_FUNCTIONS.items():
        func_categories: list[str] = func_data.get("categories", [])
        func_findings = [f for f in scan.findings if f.category.value in func_categories]
        if func_id == "MEASURE":
            # MEASURE gets all findings (security testing covers everything)
            func_findings = scan.findings
        status = _control_status(func_findings)
        controls[func_id] = {
            "name": func_data["name"],
            "description": func_data["description"],
            "status": status,
            "findings": func_findings,
            "remediation": "Address identified vulnerabilities and re-test."
            if status == "FAIL"
            else "",
        }

    tested = sum(1 for c in controls.values() if c["status"] != "NOT TESTED")
    total = len(controls)
    summary = (
        f"NIST AI RMF assessment: {tested} of {total} functions evaluated. "
        "Security testing (MEASURE) "
        f"{'passed' if scan.vulnerable_count == 0 else 'identified issues'}."
    )

    return _render_report("NIST AI RMF", scan, controls, summary)


def _generate_eu_ai_act_report(scan: ScanResult) -> str:
    """Generate EU AI Act compliance report."""
    controls: dict[str, Any] = {}
    for art_id, art_data in EU_AI_ACT_ARTICLES.items():
        art_categories: list[str] = art_data.get("categories", [])
        art_findings = [f for f in scan.findings if f.category.value in art_categories]
        status = _control_status(art_findings)
        controls[art_id] = {
            "name": art_data["name"],
            "description": art_data["description"],
            "status": status,
            "findings": art_findings,
            "remediation": (
                f"Address vulnerabilities to meet {art_id} requirements."
                if status == "FAIL"
                else ""
            ),
        }

    summary = (
        f"EU AI Act assessment: {scan.vulnerable_count} vulnerabilities found. "
        f"{'Meets' if scan.vulnerable_count == 0 else 'Does not meet'} "
        f"Article 15 cybersecurity requirements."
    )

    return _render_report("EU AI Act", scan, controls, summary)


def _generate_iso_42001_report(scan: ScanResult) -> str:
    """Generate ISO 42001 compliance report."""
    controls: dict[str, Any] = {
        "A.6": {
            "name": "AI System Security",
            "description": "Controls for securing AI systems against adversarial attacks.",
            "status": "PASS" if scan.vulnerable_count == 0 else "FAIL",
            "findings": scan.findings,
            "remediation": "Implement security controls for identified AI vulnerabilities."
            if scan.vulnerable_count > 0
            else "",
        },
    }

    summary = f"ISO 42001 security assessment: {scan.vulnerable_count} vulnerabilities identified."

    return _render_report("ISO 42001", scan, controls, summary)


def _generate_soc2_report(scan: ScanResult) -> str:
    """Generate SOC2 compliance report."""
    controls: dict[str, Any] = {
        "CC6.1": {
            "name": "Logical and Physical Access Controls",
            "description": "The entity implements logical access security measures.",
            "status": "PASS" if scan.vulnerable_count == 0 else "FAIL",
            "findings": [
                f
                for f in scan.findings
                if f.category.value
                in (
                    "Tool Safety",
                    "Agentic Security",
                    "Permission Boundaries",
                    "Execution Safety",
                )
            ],
            "remediation": "Strengthen AI agent access controls."
            if scan.vulnerable_count > 0
            else "",
        },
        "CC7.2": {
            "name": "System Monitoring",
            "description": "The entity monitors system components for anomalies.",
            "status": "PASS" if scan.vulnerable_count == 0 else "FAIL",
            "findings": scan.findings,
            "remediation": "Implement monitoring for AI-specific attack patterns."
            if scan.vulnerable_count > 0
            else "",
        },
    }

    summary = f"SOC2 AI security assessment: {scan.vulnerable_count} vulnerabilities identified."

    return _render_report("SOC2", scan, controls, summary)


def _generate_pci_dss_report(scan: ScanResult) -> str:
    """Generate PCI DSS 4.0 AI controls compliance report."""
    controls: dict[str, Any] = {}
    for req_id, req_data in PCI_DSS_V4_CONTROLS.items():
        req_findings = list(
            {
                f.template_id: f
                for f in scan.findings
                if f.category.value in req_data["categories"]
                or any(f.template_id.startswith(p) for p in req_data["attack_prefixes"])
            }.values()
        )
        status = _control_status(req_findings)
        controls[req_id] = {
            "name": req_data["name"],
            "description": req_data["description"],
            "status": status,
            "findings": req_findings,
            "remediation": req_data["remediation"] if status == "FAIL" else "",
        }

    vuln_count = scan.vulnerable_count
    if vuln_count == 0:
        summary = "All tested PCI DSS 4.0 AI controls passed security validation."
    else:
        summary = (
            f"Security testing identified {vuln_count} vulnerabilities across "
            f"PCI DSS 4.0 AI-relevant controls. Remediation is recommended."
        )

    return _render_report("PCI DSS 4.0", scan, controls, summary)


def _compliance_recommendations(controls: dict[str, Any]) -> list[str]:
    """Generate recommendations from control assessment results."""
    recs: list[str] = []
    failed = [cid for cid, c in controls.items() if c["status"] == "FAIL"]
    not_tested = [cid for cid, c in controls.items() if c["status"] == "NOT TESTED"]

    if failed:
        recs.append(f"Address failing controls: {', '.join(failed)}")
    if not_tested:
        recs.append(f"Expand testing to cover untested controls: {', '.join(not_tested)}")
    if not failed:
        recs.append("Maintain current security posture with regular testing.")
    recs.append("Schedule periodic re-assessment to track compliance drift.")
    return recs
