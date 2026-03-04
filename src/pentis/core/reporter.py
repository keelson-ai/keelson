"""Report generation — markdown reports matching existing format."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Template

from pentis.core.models import Category, Finding, ScanResult, Verdict

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
