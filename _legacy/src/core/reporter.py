"""Report generation — markdown reports matching existing format."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Template

from keelson.core.models import (
    CampaignResult,
    Category,
    Finding,
    ScanDiff,
    ScanResult,
    Verdict,
)

REPORT_TEMPLATE = Template("""\
# Keelson Security Scan Report

**Target**: {{ target.url }}
**Model**: {{ target.model }}
**Date**: {{ date }}
**Scan ID**: {{ scan.scan_id }}
**Probes Run**: {{ scan.findings | length }} | \
**Vulnerable**: {{ scan.vulnerable_count }} | \
**Safe**: {{ scan.safe_count }} | \
**Inconclusive**: {{ scan.inconclusive_count }}

## Summary

{{ summary }}

{% if critical_findings %}
## Critical Findings
{% for f in critical_findings %}
- **{{ f.template_id }}**: {{ f.template_name }} — {{ f.reasoning }}
{% endfor %}
{% endif %}

{% if infra_findings %}
## Infrastructure Findings

{% for inf in infra_findings %}
### {{ inf.title }} — {{ inf.severity.value }}

{{ inf.description }}

**Evidence**: {{ inf.evidence[:300] }}{% if inf.evidence | length > 300 %}…{% endif %}

**Remediation**: {{ inf.remediation }}

{% endfor %}
{% endif %}
## Detailed Results

### Goal Adherence (GA)
{% for f in ga_findings %}
#### {{ f.template_id }}: {{ f.template_name }} — {{ f.verdict.value }}

**Severity**: {{ f.severity.value }}
**OWASP**: {{ f.owasp }}

{% for e in f.evidence %}
**Prompt**: {{ e.prompt[:200] }}{% if e.prompt | length > 200 %}...{% endif %}

**Response** ({{ e.response_time_ms }}ms):\
 {{ e.response[:300] }}{% if e.response | length > 300 %}…{% endif %}

{% endfor %}
**Reasoning**: {{ f.reasoning }}

{% endfor %}
### Tool Safety (TS)
{% for f in ts_findings %}
#### {{ f.template_id }}: {{ f.template_name }} — {{ f.verdict.value }}

**Severity**: {{ f.severity.value }}
**OWASP**: {{ f.owasp }}

{% for e in f.evidence %}
**Prompt**: {{ e.prompt[:200] }}{% if e.prompt | length > 200 %}...{% endif %}

**Response** ({{ e.response_time_ms }}ms):\
 {{ e.response[:300] }}{% if e.response | length > 300 %}…{% endif %}

{% endfor %}
**Reasoning**: {{ f.reasoning }}

{% endfor %}
### Memory Integrity (MI)
{% for f in mi_findings %}
#### {{ f.template_id }}: {{ f.template_name }} — {{ f.verdict.value }}

**Severity**: {{ f.severity.value }}
**OWASP**: {{ f.owasp }}

{% for e in f.evidence %}
**Prompt**: {{ e.prompt[:200] }}{% if e.prompt | length > 200 %}...{% endif %}

**Response** ({{ e.response_time_ms }}ms):\
 {{ e.response[:300] }}{% if e.response | length > 300 %}…{% endif %}

{% endfor %}
**Reasoning**: {{ f.reasoning }}

{% endfor %}
### Content Safety (CS)
{% for f in cs_findings %}
#### {{ f.template_id }}: {{ f.template_name }} — {{ f.verdict.value }}

**Severity**: {{ f.severity.value }}
**OWASP**: {{ f.owasp }}

{% for e in f.evidence %}
**Prompt**: {{ e.prompt[:200] }}{% if e.prompt | length > 200 %}...{% endif %}

**Response** ({{ e.response_time_ms }}ms):\
 {{ e.response[:300] }}{% if e.response | length > 300 %}…{% endif %}

{% endfor %}
**Reasoning**: {{ f.reasoning }}

{% endfor %}
### Agentic Security (AS)
{% for f in as_findings %}
#### {{ f.template_id }}: {{ f.template_name }} — {{ f.verdict.value }}

**Severity**: {{ f.severity.value }}
**OWASP**: {{ f.owasp }}

{% for e in f.evidence %}
**Prompt**: {{ e.prompt[:200] }}{% if e.prompt | length > 200 %}...{% endif %}

**Response** ({{ e.response_time_ms }}ms):\
 {{ e.response[:300] }}{% if e.response | length > 300 %}…{% endif %}

{% endfor %}
**Reasoning**: {{ f.reasoning }}

{% endfor %}
### Permission Boundaries (PB)
{% for f in pb_findings %}
#### {{ f.template_id }}: {{ f.template_name }} — {{ f.verdict.value }}

**Severity**: {{ f.severity.value }}
**OWASP**: {{ f.owasp }}

{% for e in f.evidence %}
**Prompt**: {{ e.prompt[:200] }}{% if e.prompt | length > 200 %}...{% endif %}

**Response** ({{ e.response_time_ms }}ms):\
 {{ e.response[:300] }}{% if e.response | length > 300 %}…{% endif %}

{% endfor %}
**Reasoning**: {{ f.reasoning }}

{% endfor %}
### Delegation Integrity (DI)
{% for f in di_findings %}
#### {{ f.template_id }}: {{ f.template_name }} — {{ f.verdict.value }}

**Severity**: {{ f.severity.value }}
**OWASP**: {{ f.owasp }}

{% for e in f.evidence %}
**Prompt**: {{ e.prompt[:200] }}{% if e.prompt | length > 200 %}...{% endif %}

**Response** ({{ e.response_time_ms }}ms):\
 {{ e.response[:300] }}{% if e.response | length > 300 %}…{% endif %}

{% endfor %}
**Reasoning**: {{ f.reasoning }}

{% endfor %}
### Execution Safety (ES)
{% for f in es_findings %}
#### {{ f.template_id }}: {{ f.template_name }} — {{ f.verdict.value }}

**Severity**: {{ f.severity.value }}
**OWASP**: {{ f.owasp }}

{% for e in f.evidence %}
**Prompt**: {{ e.prompt[:200] }}{% if e.prompt | length > 200 %}...{% endif %}

**Response** ({{ e.response_time_ms }}ms):\
 {{ e.response[:300] }}{% if e.response | length > 300 %}…{% endif %}

{% endfor %}
**Reasoning**: {{ f.reasoning }}

{% endfor %}
### Session Isolation (SI)
{% for f in si_findings %}
#### {{ f.template_id }}: {{ f.template_name }} — {{ f.verdict.value }}

**Severity**: {{ f.severity.value }}
**OWASP**: {{ f.owasp }}

{% for e in f.evidence %}
**Prompt**: {{ e.prompt[:200] }}{% if e.prompt | length > 200 %}...{% endif %}

**Response** ({{ e.response_time_ms }}ms):\
 {{ e.response[:300] }}{% if e.response | length > 300 %}…{% endif %}

{% endfor %}
**Reasoning**: {{ f.reasoning }}

{% endfor %}
## Recommendations

{% for rec in recommendations %}
{{ loop.index }}. {{ rec }}
{% endfor %}
""")


def _by_category(findings: list[Finding], cat: Category, *, debug: bool = False) -> list[Finding]:
    return [f for f in findings if f.category == cat and (debug or f.verdict != Verdict.SAFE)]


def _generate_summary(scan: ScanResult) -> str:
    total = len(scan.findings)
    infra_count = len(scan.infra_findings)
    infra_note = ""
    if infra_count > 0:
        infra_note = (
            f" Additionally, {infra_count} infrastructure-level"
            f" {'issue was' if infra_count == 1 else 'issues were'}"
            f" detected during recon."
        )
    if total == 0:
        if infra_count > 0:
            return f"No probes were executed.{infra_note}"
        return "No probes were executed."
    vuln_pct = (scan.vulnerable_count / total) * 100
    if vuln_pct == 0:
        return f"Target passed all security tests. No vulnerabilities detected.{infra_note}"
    elif vuln_pct < 15:
        return (
            f"Target shows minor security concerns with "
            f"{scan.vulnerable_count} vulnerabilities found "
            f"across {total} tests ({vuln_pct:.0f}%).{infra_note}"
        )
    elif vuln_pct < 40:
        return (
            f"Target has moderate security issues with "
            f"{scan.vulnerable_count} vulnerabilities found "
            f"across {total} tests ({vuln_pct:.0f}%). "
            f"Remediation recommended.{infra_note}"
        )
    else:
        return (
            f"Target has significant security weaknesses with "
            f"{scan.vulnerable_count} vulnerabilities found "
            f"across {total} tests ({vuln_pct:.0f}%). "
            f"Immediate remediation required.{infra_note}"
        )


def _generate_recommendations(scan: ScanResult) -> list[str]:
    recs: list[str] = []

    # Infrastructure-level recommendations
    if scan.infra_findings:
        infra_titles = [inf.title for inf in scan.infra_findings]
        recs.append(
            "Address infrastructure-level findings from recon phase: "
            + ", ".join(infra_titles)
            + "."
        )

    categories_hit = {f.category for f in scan.findings if f.verdict == Verdict.VULNERABLE}
    if Category.GOAL_ADHERENCE in categories_hit:
        recs.append("Strengthen system prompt boundaries and instruction-following safeguards.")
    if Category.TOOL_SAFETY in categories_hit:
        recs.append("Implement stricter tool execution controls and input validation.")
    if Category.MEMORY_INTEGRITY in categories_hit:
        recs.append("Add conversation history integrity checks and context validation.")
    if Category.CONTENT_SAFETY in categories_hit:
        recs.append("Implement content filtering for bias, toxicity, and PII leakage prevention.")
    if Category.AGENTIC_SECURITY in categories_hit:
        recs.append("Enforce object-level and function-level authorization in agentic workflows.")
    if Category.PERMISSION_BOUNDARIES in categories_hit:
        recs.append("Enforce strict role-based access controls and permission scoping for agents.")
    if Category.DELEGATION_INTEGRITY in categories_hit:
        recs.append("Validate sub-agent delegation chains and enforce trust boundaries.")
    if Category.EXECUTION_SAFETY in categories_hit:
        recs.append("Implement execution sandboxing, resource limits, and audit logging.")
    if Category.SESSION_ISOLATION in categories_hit:
        recs.append("Enforce session isolation boundaries and prevent cross-tenant data leakage.")
    if any(
        f.verdict == Verdict.VULNERABLE and f.severity.value == "Critical" for f in scan.findings
    ):
        recs.append(
            "Address critical vulnerabilities as highest priority before production deployment."
        )
    if not recs:
        recs.append("Continue regular security testing to maintain security posture.")
    return recs


def generate_report(scan: ScanResult, *, debug: bool = False) -> str:
    """Generate a markdown report from scan results.

    By default only VULNERABLE and INCONCLUSIVE findings are shown.
    Pass debug=True to include SAFE findings as well.
    """
    critical = [
        f
        for f in scan.findings
        if f.verdict == Verdict.VULNERABLE and f.severity.value == "Critical"
    ]
    return REPORT_TEMPLATE.render(
        scan=scan,
        target=scan.target,
        date=scan.started_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        summary=_generate_summary(scan),
        critical_findings=critical,
        infra_findings=scan.infra_findings,
        ga_findings=_by_category(scan.findings, Category.GOAL_ADHERENCE, debug=debug),
        ts_findings=_by_category(scan.findings, Category.TOOL_SAFETY, debug=debug),
        mi_findings=_by_category(scan.findings, Category.MEMORY_INTEGRITY, debug=debug),
        cs_findings=_by_category(scan.findings, Category.CONTENT_SAFETY, debug=debug),
        as_findings=_by_category(scan.findings, Category.AGENTIC_SECURITY, debug=debug),
        pb_findings=_by_category(scan.findings, Category.PERMISSION_BOUNDARIES, debug=debug),
        di_findings=_by_category(scan.findings, Category.DELEGATION_INTEGRITY, debug=debug),
        es_findings=_by_category(scan.findings, Category.EXECUTION_SAFETY, debug=debug),
        si_findings=_by_category(scan.findings, Category.SESSION_ISOLATION, debug=debug),
        recommendations=_generate_recommendations(scan),
    )


def save_report(scan: ScanResult, reports_dir: Path | None = None, *, debug: bool = False) -> Path:
    """Generate and save a report to disk."""
    report_text = generate_report(scan, debug=debug)
    out_dir = reports_dir or Path("reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    filename = f"scan-{scan.started_at.strftime('%Y-%m-%d-%H%M%S')}.md"
    path = out_dir / filename
    path.write_text(report_text)
    return path


# --- Phase 2: Campaign report ---

CAMPAIGN_TEMPLATE = Template("""\
# Keelson Campaign Report

**Target**: {{ target.url }}
**Model**: {{ target.model }}
**Date**: {{ date }}
**Campaign ID**: {{ campaign.campaign_id }}
**Config**: {{ campaign.config.name }} ({{ campaign.config.trials_per_probe }} trials/probe, \
{{ "%.0f"|format(campaign.config.confidence_level * 100) }}% CI)
**Probes Tested**: {{ campaign.findings | length }} | \
**Vulnerable**: {{ campaign.vulnerable_probes }} | \
**Total Trials**: {{ campaign.total_trials }}

## Summary

{{ summary }}

## Statistical Results

| Probe | Severity | Success Rate | 95% CI | Verdict |
|--------|----------|-------------|--------|---------|
{% for f in campaign.findings %}\
| {{ f.template_id }}: {{ f.template_name[:30] }} | {{ f.severity.value }} | \
{{ "%.1f"|format(f.success_rate * 100) }}% | \
[{{ "%.1f"|format(f.ci_lower * 100) }}%, {{ "%.1f"|format(f.ci_upper * 100) }}%] | \
{{ f.verdict.value }} |
{% endfor %}

## Recommendations

{% for rec in recommendations %}
{{ loop.index }}. {{ rec }}
{% endfor %}
""")


def generate_campaign_report(campaign: CampaignResult) -> str:
    """Generate a markdown report from campaign results."""
    return CAMPAIGN_TEMPLATE.render(
        campaign=campaign,
        target=campaign.target,
        date=campaign.started_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        summary=_generate_campaign_summary(campaign),
        recommendations=_generate_campaign_recommendations(campaign),
    )


def _generate_campaign_summary(campaign: CampaignResult) -> str:
    total = len(campaign.findings)
    if total == 0:
        return "No probes were tested."
    vuln_pct = (campaign.vulnerable_probes / total) * 100
    if vuln_pct == 0:
        return (
            f"Target passed all {total} statistical security tests across "
            f"{campaign.total_trials} total trials."
        )
    return (
        f"Statistical analysis across {campaign.total_trials} trials found "
        f"{campaign.vulnerable_probes} of {total} probes with statistically "
        f"significant vulnerability rates ({vuln_pct:.0f}%)."
    )


def _generate_campaign_recommendations(campaign: CampaignResult) -> list[str]:
    recs: list[str] = []
    high_rate = [f for f in campaign.findings if f.success_rate > 0.5]
    if high_rate:
        ids = ", ".join(f.template_id for f in high_rate[:5])
        recs.append(f"Prioritize fixing high-rate vulnerabilities: {ids}")
    if campaign.vulnerable_probes > 0:
        recs.append("Run follow-up campaign after remediations to verify fixes.")
    if not recs:
        recs.append("Continue regular campaign testing to maintain security posture.")
    return recs


def generate_diff_section(diff: ScanDiff) -> str:
    """Generate a markdown section for a scan diff."""
    from keelson.diff.comparator import format_diff_report

    return format_diff_report(diff)


# --- Phase 3: Compliance report ---


def generate_compliance_report(
    scan: ScanResult,
    framework: str = "owasp-llm-top10",
) -> str:
    """Generate a compliance report for the given framework.

    Entry point that delegates to core.compliance module.
    """
    from keelson.core.compliance import ComplianceFramework
    from keelson.core.compliance import generate_compliance_report as _generate

    fw = ComplianceFramework(framework)
    return _generate(scan, framework=fw)
