"""Report generation — markdown reports matching existing format."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Template

from pentis.core.models import CampaignResult, Category, Finding, ScanDiff, ScanResult, Verdict

REPORT_TEMPLATE = Template("""\
# Pentis Security Scan Report

**Target**: {{ target.url }}
**Model**: {{ target.model }}
**Date**: {{ date }}
**Scan ID**: {{ scan.scan_id }}
**Attacks Run**: {{ scan.findings | length }} | \
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

## Detailed Results

### Goal Adherence (GA)
{% for f in ga_findings %}
#### {{ f.template_id }}: {{ f.template_name }} — {{ f.verdict.value }}

**Severity**: {{ f.severity.value }}
**OWASP**: {{ f.owasp }}

{% for e in f.evidence %}
**Prompt**: {{ e.prompt[:200] }}{% if e.prompt | length > 200 %}...{% endif %}

**Response** ({{ e.response_time_ms }}ms): {{ e.response[:300] }}{% if e.response | length > 300 %}...{% endif %}

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

**Response** ({{ e.response_time_ms }}ms): {{ e.response[:300] }}{% if e.response | length > 300 %}...{% endif %}

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

**Response** ({{ e.response_time_ms }}ms): {{ e.response[:300] }}{% if e.response | length > 300 %}...{% endif %}

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

**Response** ({{ e.response_time_ms }}ms): {{ e.response[:300] }}{% if e.response | length > 300 %}...{% endif %}

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

**Response** ({{ e.response_time_ms }}ms): {{ e.response[:300] }}{% if e.response | length > 300 %}...{% endif %}

{% endfor %}
**Reasoning**: {{ f.reasoning }}

{% endfor %}
## Recommendations

{% for rec in recommendations %}
{{ loop.index }}. {{ rec }}
{% endfor %}
""")


def _by_category(findings: list[Finding], cat: Category) -> list[Finding]:
    return [f for f in findings if f.category == cat]


def _generate_summary(scan: ScanResult) -> str:
    total = len(scan.findings)
    if total == 0:
        return "No attacks were executed."
    vuln_pct = (scan.vulnerable_count / total) * 100
    if vuln_pct == 0:
        return "Target passed all security tests. No vulnerabilities detected."
    elif vuln_pct < 15:
        return f"Target shows minor security concerns with {scan.vulnerable_count} vulnerabilities found across {total} tests ({vuln_pct:.0f}%)."
    elif vuln_pct < 40:
        return f"Target has moderate security issues with {scan.vulnerable_count} vulnerabilities found across {total} tests ({vuln_pct:.0f}%). Remediation recommended."
    else:
        return f"Target has significant security weaknesses with {scan.vulnerable_count} vulnerabilities found across {total} tests ({vuln_pct:.0f}%). Immediate remediation required."


def _generate_recommendations(scan: ScanResult) -> list[str]:
    recs: list[str] = []
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
    if any(f.verdict == Verdict.VULNERABLE and f.severity.value == "Critical" for f in scan.findings):
        recs.append("Address critical vulnerabilities as highest priority before production deployment.")
    if not recs:
        recs.append("Continue regular security testing to maintain security posture.")
    return recs


def generate_report(scan: ScanResult) -> str:
    """Generate a markdown report from scan results."""
    critical = [f for f in scan.findings if f.verdict == Verdict.VULNERABLE and f.severity.value == "Critical"]
    return REPORT_TEMPLATE.render(
        scan=scan,
        target=scan.target,
        date=scan.started_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        summary=_generate_summary(scan),
        critical_findings=critical,
        ga_findings=_by_category(scan.findings, Category.GOAL_ADHERENCE),
        ts_findings=_by_category(scan.findings, Category.TOOL_SAFETY),
        mi_findings=_by_category(scan.findings, Category.MEMORY_INTEGRITY),
        cs_findings=_by_category(scan.findings, Category.CONTENT_SAFETY),
        as_findings=_by_category(scan.findings, Category.AGENTIC_SECURITY),
        recommendations=_generate_recommendations(scan),
    )


def save_report(scan: ScanResult, reports_dir: Path | None = None) -> Path:
    """Generate and save a report to disk."""
    report_text = generate_report(scan)
    out_dir = reports_dir or Path("reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    filename = f"scan-{scan.started_at.strftime('%Y-%m-%d-%H%M%S')}.md"
    path = out_dir / filename
    path.write_text(report_text)
    return path


# --- Phase 2: Campaign report ---

CAMPAIGN_TEMPLATE = Template("""\
# Pentis Campaign Report

**Target**: {{ target.url }}
**Model**: {{ target.model }}
**Date**: {{ date }}
**Campaign ID**: {{ campaign.campaign_id }}
**Config**: {{ campaign.config.name }} ({{ campaign.config.trials_per_attack }} trials/attack, \
{{ "%.0f"|format(campaign.config.confidence_level * 100) }}% CI)
**Attacks Tested**: {{ campaign.findings | length }} | \
**Vulnerable**: {{ campaign.vulnerable_attacks }} | \
**Total Trials**: {{ campaign.total_trials }}

## Summary

{{ summary }}

## Statistical Results

| Attack | Severity | Success Rate | 95% CI | Verdict |
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
        return "No attacks were tested."
    vuln_pct = (campaign.vulnerable_attacks / total) * 100
    if vuln_pct == 0:
        return (
            f"Target passed all {total} statistical security tests across "
            f"{campaign.total_trials} total trials."
        )
    return (
        f"Statistical analysis across {campaign.total_trials} trials found "
        f"{campaign.vulnerable_attacks} of {total} attacks with statistically "
        f"significant vulnerability rates ({vuln_pct:.0f}%)."
    )


def _generate_campaign_recommendations(campaign: CampaignResult) -> list[str]:
    recs: list[str] = []
    high_rate = [f for f in campaign.findings if f.success_rate > 0.5]
    if high_rate:
        ids = ", ".join(f.template_id for f in high_rate[:5])
        recs.append(f"Prioritize fixing high-rate vulnerabilities: {ids}")
    if campaign.vulnerable_attacks > 0:
        recs.append("Run follow-up campaign after remediations to verify fixes.")
    if not recs:
        recs.append("Continue regular campaign testing to maintain security posture.")
    return recs


def generate_diff_section(diff: ScanDiff) -> str:
    """Generate a markdown section for a scan diff."""
    from pentis.diff.comparator import format_diff_report
    return format_diff_report(diff)


# --- Phase 3: Compliance report ---


def generate_compliance_report(
    scan: ScanResult,
    framework: str = "owasp-llm-top10",
) -> str:
    """Generate a compliance report for the given framework.

    Entry point that delegates to core.compliance module.
    """
    from pentis.core.compliance import ComplianceFramework
    from pentis.core.compliance import generate_compliance_report as _generate

    fw = ComplianceFramework(framework)
    return _generate(scan, framework=fw)
