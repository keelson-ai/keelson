"""Terminal and markdown report generators."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Template
from rich.console import Console
from rich.table import Table

from pentis.core.models import Finding, FindingStatus, ScanResult

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}

STATUS_ICONS = {
    FindingStatus.VULNERABLE: "[red]VULN[/red]",
    FindingStatus.SAFE: "[green]SAFE[/green]",
    FindingStatus.INCONCLUSIVE: "[yellow]INCO[/yellow]",
    FindingStatus.ERROR: "[dim]ERR [/dim]",
}


class TerminalReporter:
    """Real-time terminal output using Rich."""

    def print_finding(self, finding: Finding) -> None:
        """Print a single finding as it's discovered."""
        status_icon = STATUS_ICONS.get(finding.status, "????")
        severity_style = SEVERITY_COLORS.get(finding.severity, "white")

        console.print(
            f"  {status_icon} [{severity_style}]{finding.severity.upper():8s}[/{severity_style}] "
            f"[cyan]{finding.template_id}[/cyan] {finding.template_name}"
        )

    def print_summary(self, result: ScanResult) -> None:
        """Print the final scan summary table."""
        console.print()
        console.print("[bold]Scan Summary[/bold]")
        console.print(f"  Target: {result.target.url}")
        console.print(f"  Model: {result.target.model}")
        console.print(f"  Duration: {result.duration_seconds:.1f}s")
        console.print(f"  Templates: {result.templates_run}/{result.templates_total}")
        console.print()

        # Summary counts
        table = Table(title="Results", show_lines=False)
        table.add_column("Status", style="white")
        table.add_column("Count", justify="right")

        table.add_row("[red]Vulnerable[/red]", str(result.vulnerable_count))
        table.add_row("[green]Safe[/green]", str(result.safe_count))
        table.add_row("[yellow]Inconclusive[/yellow]", str(result.inconclusive_count))
        table.add_row("[dim]Error[/dim]", str(result.error_count))
        table.add_row("[bold]Total[/bold]", str(len(result.findings)))

        console.print(table)

        # Findings by severity
        if result.vulnerable_count > 0:
            console.print()
            vuln_table = Table(title="Vulnerabilities Found", show_lines=True)
            vuln_table.add_column("ID", style="cyan", no_wrap=True)
            vuln_table.add_column("Name", style="white")
            vuln_table.add_column("Severity", style="red")
            vuln_table.add_column("Behavior", style="magenta")
            vuln_table.add_column("OWASP", style="yellow")
            vuln_table.add_column("Confidence", justify="right")

            for f in result.findings:
                if f.is_vulnerable:
                    sev_style = SEVERITY_COLORS.get(f.severity, "white")
                    vuln_table.add_row(
                        f.template_id,
                        f.template_name,
                        f"[{sev_style}]{f.severity.upper()}[/{sev_style}]",
                        f.behavior,
                        f.owasp_id or "—",
                        f"{f.confidence:.0%}",
                    )

            console.print(vuln_table)


REPORT_TEMPLATE = """\
# Pentis Security Scan Report

**Date**: {{ scan_date }}
**Target**: {{ target_url }}
**Model**: {{ model }}
**Duration**: {{ duration }}s

---

## Executive Summary

Pentis scanned **{{ templates_total }}** attack templates across **{{ behavior_count }}** behavior categories.

| Metric | Value |
|--------|-------|
| Vulnerable | {{ vulnerable_count }} |
| Safe | {{ safe_count }} |
| Inconclusive | {{ inconclusive_count }} |
| Error | {{ error_count }} |
| **Total** | **{{ total }}** |

{% if vulnerable_count > 0 -%}
**{{ vulnerable_count }} vulnerabilities detected.** Review findings below and remediate before deployment.
{% else -%}
**No vulnerabilities detected.** The agent appears resilient to the tested attack patterns.
{% endif %}

---

## OWASP Mapping

| OWASP ID | Name | Findings |
|----------|------|----------|
{% for owasp_id, items in owasp_map.items() -%}
| {{ owasp_id }} | {{ items[0].owasp_name or '—' }} | {{ items | length }} |
{% endfor %}

---

## Findings by Behavior

{% for behavior, findings in by_behavior.items() %}
### {{ behavior | replace('_', ' ') | title }}

{% for f in findings %}
#### {{ f.template_id }}: {{ f.template_name }}

| Field | Value |
|-------|-------|
| Status | **{{ f.status.value | upper }}** |
| Severity | {{ f.severity | upper }} |
| OWASP | {{ f.owasp_id or '—' }} — {{ f.owasp_name or '—' }} |
| Confidence | {{ "%.0f" | format(f.confidence * 100) }}% |

{{ f.description }}

{% if f.evidence -%}
<details>
<summary>Evidence ({{ f.evidence | length }} steps)</summary>

{% for e in f.evidence %}
**Step {{ e.step_index + 1 }}**

*Prompt:*
```
{{ e.prompt[:500] }}
```

*Response:*
```
{{ e.response[:500] }}
```

{% if e.indicators_matched -%}
*Indicators matched:* {{ e.indicators_matched | join(', ') }}
{% endif -%}
{% if e.refusal_detected -%}
*Refusal detected: Yes*
{% endif %}
{% endfor %}
</details>
{%- endif %}

---

{% endfor %}
{% endfor %}

## Scan Configuration

- **Target URL**: {{ target_url }}
- **Model**: {{ model }}
- **Templates executed**: {{ templates_run }}/{{ templates_total }}
- **Scan duration**: {{ duration }}s

{% if system_prompt_leaked -%}
## System Prompt Leak Detected

The agent's system prompt was partially extracted during discovery:

```
{{ system_prompt_leaked[:500] }}
```
{% endif %}

---

*Generated by [Pentis](https://github.com/pentis-ai/pentis) v{{ version }}*
"""


class MarkdownReporter:
    """Generate a markdown report from scan results."""

    def generate(self, result: ScanResult, output_path: Path) -> None:
        """Generate and write a markdown report."""
        from pentis import __version__

        # Group findings
        by_behavior: dict[str, list[Finding]] = {}
        owasp_map: dict[str, list[Finding]] = {}
        for f in result.findings:
            by_behavior.setdefault(f.behavior, []).append(f)
            if f.owasp_id:
                owasp_map.setdefault(f.owasp_id, []).append(f)

        template = Template(REPORT_TEMPLATE)
        content = template.render(
            scan_date=result.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            target_url=result.target.url,
            model=result.target.model,
            duration=f"{result.duration_seconds:.1f}",
            templates_total=result.templates_total,
            templates_run=result.templates_run,
            behavior_count=len(by_behavior),
            vulnerable_count=result.vulnerable_count,
            safe_count=result.safe_count,
            inconclusive_count=result.inconclusive_count,
            error_count=result.error_count,
            total=len(result.findings),
            by_behavior=by_behavior,
            owasp_map=owasp_map,
            system_prompt_leaked=result.target.system_prompt_leaked,
            version=__version__,
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content)
