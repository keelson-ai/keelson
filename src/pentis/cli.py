"""Pentis CLI — AI agent security scanner."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from pentis.adapters.openai import OpenAIAdapter
from pentis.core.models import Target
from pentis.core.reporter import save_report
from pentis.core.scanner import run_scan
from pentis.core.templates import load_all_templates
from pentis.state.store import Store

app = typer.Typer(name="pentis", help="AI agent security scanner — Living Red Team")
console = Console()


@app.command()
def scan(
    url: str = typer.Argument(help="Target endpoint URL (OpenAI-compatible chat completions)"),
    api_key: str = typer.Option("", "--api-key", "-k", help="API key for authentication"),
    model: str = typer.Option("default", "--model", "-m", help="Model name for requests"),
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filter by category"),
    delay: float = typer.Option(1.5, "--delay", "-d", help="Seconds between requests"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Report output directory"),
    no_save: bool = typer.Option(False, "--no-save", help="Skip saving to database"),
) -> None:
    """Run a full security scan against an AI agent endpoint."""
    target = Target(url=url, api_key=api_key, model=model)
    adapter = OpenAIAdapter(url=url, api_key=api_key)

    def on_finding(finding, current, total):
        icon = {"VULNERABLE": "[red]VULN[/]", "SAFE": "[green]SAFE[/]", "INCONCLUSIVE": "[yellow]????[/]"}
        console.print(
            f"  [{current}/{total}] {finding.template_id}: {finding.template_name} — "
            f"{icon.get(finding.verdict.value, finding.verdict.value)}"
        )

    console.print(f"\n[bold]Pentis Security Scan[/bold]")
    console.print(f"Target: {url}")
    console.print(f"Model: {model}")
    if category:
        console.print(f"Category: {category}")
    console.print()

    result = asyncio.run(
        run_scan(
            target=target,
            adapter=adapter,
            category=category,
            delay=delay,
            on_finding=on_finding,
        )
    )
    asyncio.run(adapter.close())

    # Save to database
    if not no_save:
        store = Store()
        store.save_scan(result)
        store.close()

    # Generate report
    report_path = save_report(result, reports_dir=output)
    console.print(f"\n[bold]Results[/bold]")
    console.print(f"  Vulnerable: [red]{result.vulnerable_count}[/]")
    console.print(f"  Safe: [green]{result.safe_count}[/]")
    console.print(f"  Inconclusive: [yellow]{result.inconclusive_count}[/]")
    console.print(f"\nReport saved: {report_path}")


@app.command()
def attack(
    url: str = typer.Argument(help="Target endpoint URL"),
    attack_id: str = typer.Argument(help="Attack template ID (e.g., GA-001)"),
    api_key: str = typer.Option("", "--api-key", "-k"),
    model: str = typer.Option("default", "--model", "-m"),
) -> None:
    """Run a single attack against a target."""
    from pentis.core.engine import execute_attack
    from pentis.core.templates import load_all_templates

    templates = load_all_templates()
    template = next((t for t in templates if t.id == attack_id), None)
    if not template:
        console.print(f"[red]Attack {attack_id} not found[/]")
        raise typer.Exit(1)

    adapter = OpenAIAdapter(url=url, api_key=api_key)
    console.print(f"\n[bold]{template.id}: {template.name}[/bold]")
    console.print(f"Severity: {template.severity.value} | Category: {template.category.value}")
    console.print()

    finding = asyncio.run(execute_attack(template, adapter, model=model))
    asyncio.run(adapter.close())

    icon = {"VULNERABLE": "[red]VULNERABLE[/]", "SAFE": "[green]SAFE[/]", "INCONCLUSIVE": "[yellow]INCONCLUSIVE[/]"}
    console.print(f"Verdict: {icon.get(finding.verdict.value, finding.verdict.value)}")
    console.print(f"Reasoning: {finding.reasoning}")
    for ev in finding.evidence:
        console.print(f"\n  Step {ev.step_index}:")
        console.print(f"  Prompt: {ev.prompt[:150]}...")
        console.print(f"  Response ({ev.response_time_ms}ms): {ev.response[:200]}...")


@app.command(name="list")
def list_attacks(
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filter by category"),
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
        sev_color = {"Critical": "red", "High": "red", "Medium": "yellow", "Low": "green"}
        table.add_row(
            t.id,
            t.name,
            f"[{sev_color.get(t.severity.value, 'white')}]{t.severity.value}[/]",
            t.category.value,
            t.owasp,
            str(len(t.steps)),
        )
    console.print(table)


@app.command()
def report(
    scan_id: str = typer.Argument(help="Scan ID to generate report for"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory"),
) -> None:
    """Generate a report from a saved scan."""
    store = Store()
    result = store.get_scan(scan_id)
    store.close()
    if not result:
        console.print(f"[red]Scan {scan_id} not found[/]")
        raise typer.Exit(1)
    path = save_report(result, reports_dir=output)
    console.print(f"Report saved: {path}")


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of scans to show"),
) -> None:
    """Show scan history."""
    store = Store()
    scans = store.list_scans(limit=limit)
    store.close()
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


if __name__ == "__main__":
    app()
