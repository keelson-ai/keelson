"""Executive report generator with PoC sections."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime

from jinja2 import Template

from keelson.core.models import Category, Finding, ScanResult, Severity, Verdict

# ---------------------------------------------------------------------------
# Severity ordering for sorting (most severe first)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

# ---------------------------------------------------------------------------
# Category-level recommendation mapping
# ---------------------------------------------------------------------------

_CATEGORY_RECOMMENDATIONS: dict[Category, str] = {
    Category.GOAL_ADHERENCE: (
        "Harden system prompt boundaries with layered instruction-following "
        "safeguards. Consider prompt armoring techniques such as XML delimiters, "
        "instruction repetition, and canary tokens."
    ),
    Category.TOOL_SAFETY: (
        "Enforce strict input validation and allowlisting on all tool invocations. "
        "Implement a tool-call audit log and require explicit user confirmation "
        "for destructive operations."
    ),
    Category.MEMORY_INTEGRITY: (
        "Add conversation-history integrity checks. Validate that injected context "
        "cannot override prior instructions. Consider cryptographic hashing of "
        "critical memory entries."
    ),
    Category.CONTENT_SAFETY: (
        "Deploy content filtering for bias, toxicity, and PII leakage. Implement "
        "output classifiers to catch harmful content before delivery to end users."
    ),
    Category.AGENTIC_SECURITY: (
        "Enforce object-level and function-level authorization across agentic "
        "workflows. Audit inter-agent message buses for privilege escalation paths."
    ),
    Category.PERMISSION_BOUNDARIES: (
        "Implement role-based access controls with least-privilege scoping. "
        "Validate permission claims at every delegation boundary."
    ),
    Category.DELEGATION_INTEGRITY: (
        "Validate sub-agent delegation chains end-to-end. Enforce trust boundaries "
        "and prevent transitive authority escalation."
    ),
    Category.EXECUTION_SAFETY: (
        "Sandbox all code execution environments. Enforce resource limits (CPU, "
        "memory, network) and maintain comprehensive audit logging."
    ),
    Category.SESSION_ISOLATION: (
        "Enforce strict session isolation boundaries. Prevent cross-tenant data "
        "leakage through shared caches, embeddings, or conversation state."
    ),
}

# ---------------------------------------------------------------------------
# Data containers for template context
# ---------------------------------------------------------------------------


@dataclass
class SeverityRow:
    """A row in the severity breakdown table."""

    severity: str
    count: int
    bar: str


@dataclass
class CategoryRow:
    """A row in the risk-matrix / coverage table."""

    category: str
    vuln_count: int
    highest_severity: str
    owasp: str
    tested: int = 0
    safe: int = 0
    inconclusive: int = 0


@dataclass
class RecommendationItem:
    """A prioritized recommendation."""

    priority: int
    severity: str
    text: str


# ---------------------------------------------------------------------------
# Jinja2 executive report template
# ---------------------------------------------------------------------------

EXECUTIVE_REPORT_TEMPLATE = Template(
    """\
# AI Agent Security Assessment Report

---

## Executive Summary

| Field | Value |
|-------|-------|
| **Target** | {{ target_url }} |
| **Model** | {{ target_model }} |
| **Scan ID** | {{ scan_id }} |
| **Date** | {{ scan_date }} |
| **Duration** | {{ duration }} |
| **Probes Executed** | {{ total_probes }} |

{{ risk_assessment }}

### Severity Breakdown

| Severity | Count | |
|----------|------:|---|
{% for row in severity_rows %}\
| **{{ row.severity }}** | {{ row.count }} | {{ row.bar }} |
{% endfor %}\
| **Total Vulnerable** | **{{ total_vulnerable }}** | |

---

## Risk Matrix

| Category | Vulnerabilities | Highest Severity | OWASP Mapping |
|----------|:-:|:-:|---|
{% for row in risk_matrix %}\
| {{ row.category }} | {{ row.vuln_count }} | {{ row.highest_severity }} | {{ row.owasp }} |
{% endfor %}

---

## Confirmed Vulnerabilities
{% if vulnerable_findings %}
{% for f in vulnerable_findings %}

### {{ f.template_id }}: {{ f.template_name }}

| | |
|---|---|
| **Severity** | {{ f.severity.value }} |
| **Category** | {{ f.category.value }} |
| **OWASP** | {{ f.owasp }} |

**Analysis**: {{ f.reasoning }}
{% if f.evidence %}

**Proof of Concept**:

{% for e in f.evidence %}
*Step {{ e.step_index }}* -- Prompt:

```
{{ e.prompt }}
```

Agent Response{% if e.response_time_ms %} ({{ e.response_time_ms }}ms){% endif %}:

```
{{ e.response[:500] }}{% if e.response|length > 500 %}...{% endif %}
```
{% endfor %}
{% endif %}
{% if f.leakage_signals %}

**Leakage Signals Detected**:
{% for sig in f.leakage_signals %}
- [{{ sig.severity | upper }}] {{ sig.signal_type }}: {{ sig.description }}\
{% if sig.confidence %} (confidence: {{ "%.0f"|format(sig.confidence * 100) }}%){% endif %}
{% endfor %}
{% endif %}

---
{% endfor %}
{% else %}
No confirmed vulnerabilities were found during this assessment.

---
{% endif %}

## Inconclusive Findings
{% if inconclusive_findings %}

| ID | Name | Severity | Category | OWASP |
|----|------|----------|----------|-------|
{% for f in inconclusive_findings %}\
| {{ f.template_id }} | {{ f.template_name }} | {{ f.severity.value }} \
| {{ f.category.value }} | {{ f.owasp }} |
{% endfor %}

> Inconclusive findings could not be definitively classified as vulnerable or safe. \
Manual review is recommended, particularly for high-severity items.
{% else %}
No inconclusive findings.
{% endif %}

---
{% if include_safe and safe_findings %}

## Safe Findings

| ID | Name | Severity | Category |
|----|------|----------|----------|
{% for f in safe_findings %}\
| {{ f.template_id }} | {{ f.template_name }} | {{ f.severity.value }} \
| {{ f.category.value }} |
{% endfor %}

---
{% endif %}

## Probe Coverage

| Category | Tested | Vulnerable | Safe | Inconclusive |
|----------|------:|----------:|-----:|-:|
{% for row in coverage_rows %}\
| {{ row.category }} | {{ row.tested }} | {{ row.vuln_count }} \
| {{ row.safe }} | {{ row.inconclusive }} |
{% endfor %}\
| **Total** | **{{ total_probes }}** | **{{ total_vulnerable }}** \
| **{{ total_safe }}** | **{{ total_inconclusive }}** |

---

## Recommendations

{% for rec in recommendations %}\
{{ rec.priority }}. **[{{ rec.severity }}]** {{ rec.text }}
{% endfor %}

---

*Report generated by Keelson AI Agent Security Scanner on {{ generated_at }}.*
""",
    keep_trailing_newline=True,
)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _severity_sort_key(finding: Finding) -> tuple[int, str]:
    """Sort key: severity descending, then template_id ascending."""
    return (_SEVERITY_ORDER.get(finding.severity, 99), finding.template_id)


def _compute_severity_rows(findings: list[Finding]) -> list[SeverityRow]:
    """Build the severity breakdown table rows."""
    vuln_findings = [f for f in findings if f.verdict == Verdict.VULNERABLE]
    counts = Counter(f.severity for f in vuln_findings)

    rows: list[SeverityRow] = []
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        count = counts.get(severity, 0)
        bar = "\u2588" * count if count > 0 else "-"
        rows.append(SeverityRow(severity=severity.value, count=count, bar=bar))
    return rows


def _compute_risk_matrix(findings: list[Finding]) -> list[CategoryRow]:
    """Build the risk matrix -- one row per category that has vulnerable findings."""
    category_findings: dict[Category, list[Finding]] = {}
    for f in findings:
        if f.verdict == Verdict.VULNERABLE:
            category_findings.setdefault(f.category, []).append(f)

    rows: list[CategoryRow] = []
    for cat in Category:
        cat_vulns = category_findings.get(cat, [])
        if not cat_vulns:
            continue
        highest = min(cat_vulns, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
        owasp_ids = sorted({f.owasp for f in cat_vulns})
        rows.append(
            CategoryRow(
                category=cat.value,
                vuln_count=len(cat_vulns),
                highest_severity=highest.severity.value,
                owasp=", ".join(owasp_ids),
            )
        )
    return rows


def _compute_coverage_rows(findings: list[Finding]) -> list[CategoryRow]:
    """Build the probe coverage table -- one row per category with any findings."""
    by_cat: dict[Category, list[Finding]] = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)

    rows: list[CategoryRow] = []
    for cat in Category:
        cat_findings = by_cat.get(cat, [])
        if not cat_findings:
            continue
        rows.append(
            CategoryRow(
                category=cat.value,
                vuln_count=sum(1 for f in cat_findings if f.verdict == Verdict.VULNERABLE),
                highest_severity="",
                owasp="",
                tested=len(cat_findings),
                safe=sum(1 for f in cat_findings if f.verdict == Verdict.SAFE),
                inconclusive=sum(1 for f in cat_findings if f.verdict == Verdict.INCONCLUSIVE),
            )
        )
    return rows


def _generate_risk_assessment(scan: ScanResult) -> str:
    """Produce a 2-3 sentence executive risk assessment."""
    total = len(scan.findings)
    if total == 0:
        return "No probe templates were executed during this assessment."

    vuln = scan.vulnerable_count
    if vuln == 0:
        return (
            "The target agent demonstrated robust security controls across all "
            f"{total} probe scenarios tested. No vulnerabilities were confirmed. "
            "Continued periodic assessment is recommended to maintain this posture."
        )

    vuln_pct = (vuln / total) * 100
    critical_count = sum(
        1
        for f in scan.findings
        if f.verdict == Verdict.VULNERABLE and f.severity == Severity.CRITICAL
    )
    high_count = sum(
        1 for f in scan.findings if f.verdict == Verdict.VULNERABLE and f.severity == Severity.HIGH
    )

    if critical_count > 0:
        risk_level = "CRITICAL"
        urgency = (
            f"Immediate remediation is required. {critical_count} critical-severity "
            f"{'vulnerability was' if critical_count == 1 else 'vulnerabilities were'} "
            "confirmed, indicating that core security controls can be bypassed."
        )
    elif high_count > 0:
        risk_level = "HIGH"
        urgency = (
            f"Prompt remediation is strongly recommended. {high_count} high-severity "
            f"{'vulnerability was' if high_count == 1 else 'vulnerabilities were'} "
            "confirmed, representing significant risk to production deployment."
        )
    elif vuln_pct > 30:
        risk_level = "ELEVATED"
        urgency = (
            "A substantial proportion of probe scenarios succeeded. "
            "Systematic hardening of the agent's defensive controls is recommended "
            "before production exposure."
        )
    else:
        risk_level = "MODERATE"
        urgency = (
            "A limited number of probe scenarios succeeded. Targeted remediation "
            "of the identified weaknesses is recommended."
        )

    return (
        f"**Overall Risk Level: {risk_level}** -- "
        f"Out of {total} probe scenarios executed, {vuln} "
        f"({vuln_pct:.0f}%) resulted in confirmed vulnerabilities. "
        f"{urgency}"
    )


def _format_duration(scan: ScanResult) -> str:
    """Human-readable scan duration."""
    if scan.finished_at is None:
        return "in progress"
    delta = scan.finished_at - scan.started_at
    total_seconds = int(delta.total_seconds())
    if total_seconds < 60:
        return f"{total_seconds}s"
    minutes, seconds = divmod(total_seconds, 60)
    if minutes < 60:
        return f"{minutes}m {seconds}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m {seconds}s"


def _build_recommendations(findings: list[Finding]) -> list[RecommendationItem]:
    """Build a prioritized recommendation list based on confirmed vulnerabilities."""
    vuln_by_cat: dict[Category, list[Finding]] = {}
    for f in findings:
        if f.verdict == Verdict.VULNERABLE:
            vuln_by_cat.setdefault(f.category, []).append(f)

    if not vuln_by_cat:
        return [
            RecommendationItem(
                priority=1,
                severity="INFO",
                text=(
                    "No vulnerabilities were confirmed. Continue regular security "
                    "assessments to maintain this posture."
                ),
            )
        ]

    # Sort categories by worst severity found, then by vulnerability count
    def _cat_sort_key(item: tuple[Category, list[Finding]]) -> tuple[int, int]:
        _cat, cat_findings = item
        worst = min(_SEVERITY_ORDER.get(f.severity, 99) for f in cat_findings)
        return (worst, -len(cat_findings))

    sorted_cats = sorted(vuln_by_cat.items(), key=_cat_sort_key)

    recs: list[RecommendationItem] = []
    priority = 1

    # Per-category recommendations
    for cat, cat_findings in sorted_cats:
        worst_finding = min(cat_findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
        rec_text = _CATEGORY_RECOMMENDATIONS.get(cat, f"Review {cat.value} controls.")
        ids = ", ".join(sorted({f.template_id for f in cat_findings}))
        full_text = f"{rec_text} (Affected: {ids})"
        recs.append(
            RecommendationItem(
                priority=priority,
                severity=worst_finding.severity.value,
                text=full_text,
            )
        )
        priority += 1

    # Critical-severity meta-recommendation
    critical_vulns = [
        f for f in findings if f.verdict == Verdict.VULNERABLE and f.severity == Severity.CRITICAL
    ]
    if critical_vulns:
        recs.append(
            RecommendationItem(
                priority=priority,
                severity="Critical",
                text=(
                    "Address all critical-severity findings before any production "
                    "deployment. These represent fundamental control failures that "
                    "can be exploited with minimal prober sophistication."
                ),
            )
        )
        priority += 1

    # Inconclusive meta-recommendation
    inconclusive = [f for f in findings if f.verdict == Verdict.INCONCLUSIVE]
    if inconclusive:
        recs.append(
            RecommendationItem(
                priority=priority,
                severity="Info",
                text=(
                    f"Manually review {len(inconclusive)} inconclusive "
                    f"{'finding' if len(inconclusive) == 1 else 'findings'} "
                    "to determine whether additional controls are needed."
                ),
            )
        )

    return recs


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_executive_report(
    scan: ScanResult,
    *,
    include_safe: bool = False,
) -> str:
    """Generate an executive security assessment report.

    Produces a pentest-grade markdown report with:
    - Executive summary with severity breakdown
    - Risk matrix by category
    - Full PoC reproduction sections (exact prompts and responses)
    - Probe coverage matrix
    - Prioritized remediation recommendations

    Args:
        scan: Completed scan result containing findings.
        include_safe: If True, include a table of safe findings in the report.

    Returns:
        Rendered markdown report as a string.
    """
    vulnerable = sorted(
        [f for f in scan.findings if f.verdict == Verdict.VULNERABLE],
        key=_severity_sort_key,
    )
    inconclusive = sorted(
        [f for f in scan.findings if f.verdict == Verdict.INCONCLUSIVE],
        key=_severity_sort_key,
    )
    safe = sorted(
        [f for f in scan.findings if f.verdict == Verdict.SAFE],
        key=_severity_sort_key,
    )

    return EXECUTIVE_REPORT_TEMPLATE.render(
        # Executive summary fields
        target_url=scan.target.url,
        target_model=scan.target.model,
        scan_id=scan.scan_id,
        scan_date=scan.started_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        duration=_format_duration(scan),
        total_probes=len(scan.findings),
        risk_assessment=_generate_risk_assessment(scan),
        # Severity breakdown
        severity_rows=_compute_severity_rows(scan.findings),
        total_vulnerable=scan.vulnerable_count,
        total_safe=scan.safe_count,
        total_inconclusive=scan.inconclusive_count,
        # Risk matrix
        risk_matrix=_compute_risk_matrix(scan.findings),
        # Findings
        vulnerable_findings=vulnerable,
        inconclusive_findings=inconclusive,
        safe_findings=safe,
        include_safe=include_safe,
        # Coverage
        coverage_rows=_compute_coverage_rows(scan.findings),
        # Recommendations
        recommendations=_build_recommendations(scan.findings),
        # Footer
        generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
