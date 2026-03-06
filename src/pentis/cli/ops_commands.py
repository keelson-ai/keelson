"""Operations commands: list, report, history, diff, discover, baseline, compliance."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.table import Table

from pentis.cli import (
    SEVERITY_COLORS,
    app,
    console,
    make_adapter,
    run_with_adapter,
)
from pentis.core.reporter import save_report
from pentis.core.templates import load_all_templates
from pentis.state.store import Store


@app.command(name="list")
def list_attacks(
    category: str | None = typer.Option(None, "--category", "-c", help="Filter by category"),
) -> None:
    """List all available attack templates."""
    templates = load_all_templates(category=category)
    table = Table(title="Attack Templates")
    table.add_column("ID", style="bold")
    table.add_column("Name")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("OWASP")
    table.add_column("Steps", justify="right")

    for t in templates:
        table.add_row(
            t.id,
            t.name,
            f"[{SEVERITY_COLORS.get(t.severity.value, 'white')}]{t.severity.value}[/]",
            t.category.value,
            t.owasp,
            str(len(t.steps)),
        )
    console.print(table)


@app.command()
def report(
    scan_id: str = typer.Argument(help="Scan ID to generate report for"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output directory"),
    debug: bool = typer.Option(False, "--debug", help="Include SAFE findings in report"),
) -> None:
    """Generate a report from a saved scan."""
    with Store() as store:
        result = store.get_scan(scan_id)
    if not result:
        console.print(f"[red]Scan {scan_id} not found[/]")
        raise typer.Exit(1)
    path = save_report(result, reports_dir=output, debug=debug)
    console.print(f"Report saved: {path}")


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of scans to show"),
) -> None:
    """Show scan history."""
    with Store() as store:
        scans = store.list_scans(limit=limit)
    if not scans:
        console.print("No scans recorded yet.")
        return
    table = Table(title="Scan History")
    table.add_column("Scan ID", style="bold")
    table.add_column("Target")
    table.add_column("Date")
    table.add_column("Total", justify="right")
    table.add_column("Vuln", justify="right", style="red")
    table.add_column("Safe", justify="right", style="green")
    for s in scans:
        table.add_row(
            s["scan_id"],
            s["target_url"][:40],
            s["started_at"][:19],
            str(s["total"]),
            str(s["vulnerable"]),
            str(s["safe"]),
        )
    console.print(table)


@app.command()
def discover(
    url: str = typer.Argument(help="Target endpoint URL"),
    api_key: str = typer.Option("", "--api-key", "-k"),
    model: str = typer.Option("default", "--model", "-m"),
    no_save: bool = typer.Option(False, "--no-save", help="Skip saving to database"),
    adapter: str = typer.Option(
        "openai", "--adapter", "-a", help="Adapter type: openai, anthropic, langgraph, mcp, or a2a"
    ),
    assistant_id: str = typer.Option("agent", "--assistant-id", help="LangGraph assistant ID"),
    tool_name: str = typer.Option("chat", "--tool-name", help="MCP tool name to call"),
) -> None:
    """Fingerprint agent capabilities."""
    from pentis.attacker.discovery import discover_capabilities

    target_adapter = make_adapter(
        url, api_key, adapter, assistant_id=assistant_id, tool_name=tool_name
    )

    console.print("\n[bold]Pentis Agent Discovery[/bold]")
    console.print(f"Target: {url}")
    console.print()

    profile = run_with_adapter(
        lambda: discover_capabilities(target_adapter, model=model, target_url=url),
        target_adapter,
    )

    if not no_save:
        with Store() as store:
            store.save_agent_profile(profile)

    table = Table(title="Agent Capabilities")
    table.add_column("Capability", style="bold")
    table.add_column("Detected")
    table.add_column("Confidence", justify="right")
    for cap in profile.capabilities:
        detected_str = "[green]Yes[/]" if cap.detected else "[dim]No[/]"
        table.add_row(cap.name, detected_str, f"{cap.confidence:.0%}")
    console.print(table)
    console.print(f"\nProfile ID: {profile.profile_id}")
    console.print(f"Detected: {len(profile.detected_capabilities)} of {len(profile.capabilities)}")


@app.command()
def diff(
    scan_a: str = typer.Argument(help="First scan ID (before)"),
    scan_b: str = typer.Argument(help="Second scan ID (after)"),
    enhanced: bool = typer.Option(
        False, "--enhanced", "-e", help="Show severity-classified alerts"
    ),
) -> None:
    """Compare two scans and show regressions/improvements."""
    from pentis.diff.comparator import diff_scans, enhanced_diff_scans, format_diff_report

    with Store() as store:
        result_a = store.get_scan(scan_a)
        result_b = store.get_scan(scan_b)

        if not result_a:
            console.print(f"[red]Scan {scan_a} not found[/]")
            raise typer.Exit(1)
        if not result_b:
            console.print(f"[red]Scan {scan_b} not found[/]")
            raise typer.Exit(1)

        if enhanced:
            scan_diff, alerts = enhanced_diff_scans(result_a, result_b)
            report_text = format_diff_report(scan_diff)
            console.print(report_text)

            if alerts:
                console.print("\n[bold]Regression Alerts[/bold]")
                alert_table = Table()
                alert_table.add_column("Severity", style="bold")
                alert_table.add_column("Attack")
                alert_table.add_column("Change")
                alert_table.add_column("Description")

                alert_sev_colors = {
                    "critical": "red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "dim",
                }
                for alert in alerts:
                    table_color = alert_sev_colors.get(alert.alert_severity, "white")
                    alert_table.add_row(
                        f"[{table_color}]{alert.alert_severity.upper()}[/]",
                        alert.template_id,
                        alert.change_type,
                        alert.description,
                    )
                console.print(alert_table)

                store.save_regression_alerts(scan_a, scan_b, alerts)
        else:
            scan_diff = diff_scans(result_a, result_b)
            report_text = format_diff_report(scan_diff)
            console.print(report_text)

            if scan_diff.regressions:
                console.print(
                    f"\n[red bold]WARNING: {len(scan_diff.regressions)} regressions detected![/]"
                )


@app.command()
def baseline(
    scan_id: str = typer.Argument(help="Scan ID to set as baseline"),
    label: str = typer.Option("", "--label", "-l", help="Label for this baseline"),
) -> None:
    """Set a scan as a regression baseline."""
    with Store() as store:
        result = store.get_scan(scan_id)
        if not result:
            console.print(f"[red]Scan {scan_id} not found[/]")
            raise typer.Exit(1)
        store.save_baseline(scan_id, label=label)
    label_str = f' (label: "{label}")' if label else ""
    console.print(f"Baseline set: {scan_id}{label_str}")


@app.command(name="compliance")
def compliance_report(
    scan_id: str = typer.Argument(help="Scan ID to generate compliance report for"),
    framework: str = typer.Option(
        "owasp-llm-top10",
        "--framework",
        "-f",
        help="Compliance framework: owasp-llm-top10, nist-ai-rmf, eu-ai-act, iso-42001, soc2",
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output directory"),
) -> None:
    """Generate a compliance report for a scan against a security framework."""
    from pentis.core.reporter import generate_compliance_report

    with Store() as store:
        result = store.get_scan(scan_id)
    if not result:
        console.print(f"[red]Scan {scan_id} not found[/]")
        raise typer.Exit(1)

    report_text = generate_compliance_report(result, framework=framework)
    out_dir = output or Path("reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = (
        out_dir / f"compliance-{framework}-{result.started_at.strftime('%Y-%m-%d-%H%M%S')}.md"
    )
    report_path.write_text(report_text)

    console.print(f"[bold]Compliance Report: {framework}[/bold]")
    console.print(f"Scan: {scan_id}")
    console.print(f"Report saved: {report_path}")
