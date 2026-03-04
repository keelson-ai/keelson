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


# --- Phase 2 Commands ---


@app.command()
def campaign(
    config_path: str = typer.Argument(help="Path to TOML campaign configuration file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Report output directory"),
    no_save: bool = typer.Option(False, "--no-save", help="Skip saving to database"),
) -> None:
    """Run a statistical campaign (N trials per attack)."""
    from pentis.campaign.config import parse_campaign_config
    from pentis.campaign.runner import run_campaign
    from pentis.core.models import CampaignConfig
    from pentis.core.reporter import generate_campaign_report

    config = parse_campaign_config(config_path)
    target = Target(url=config.target_url, api_key=config.api_key, model=config.model)
    adapter = OpenAIAdapter(url=config.target_url, api_key=config.api_key)

    def on_finding(sf, current, total):
        icon = {"VULNERABLE": "[red]VULN[/]", "SAFE": "[green]SAFE[/]", "INCONCLUSIVE": "[yellow]????[/]"}
        console.print(
            f"  [{current}/{total}] {sf.template_id}: {sf.template_name} — "
            f"{icon.get(sf.verdict.value, sf.verdict.value)} "
            f"({sf.success_rate:.0%} rate, {sf.num_trials} trials)"
        )

    console.print(f"\n[bold]Pentis Statistical Campaign[/bold]")
    console.print(f"Config: {config.name}")
    console.print(f"Target: {config.target_url}")
    console.print(f"Trials/attack: {config.trials_per_attack}")
    console.print()

    result = asyncio.run(
        run_campaign(target=target, adapter=adapter, config=config, on_finding=on_finding)
    )
    asyncio.run(adapter.close())

    if not no_save:
        store = Store()
        store.save_campaign(result)
        store.close()

    # Generate campaign report
    report_text = generate_campaign_report(result)
    out_dir = output or Path("reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / f"campaign-{result.started_at.strftime('%Y-%m-%d-%H%M%S')}.md"
    report_path.write_text(report_text)

    console.print(f"\n[bold]Campaign Results[/bold]")
    console.print(f"  Attacks tested: {len(result.findings)}")
    console.print(f"  Vulnerable: [red]{result.vulnerable_attacks}[/]")
    console.print(f"  Total trials: {result.total_trials}")
    console.print(f"\nReport saved: {report_path}")


@app.command()
def discover(
    url: str = typer.Argument(help="Target endpoint URL"),
    api_key: str = typer.Option("", "--api-key", "-k"),
    model: str = typer.Option("default", "--model", "-m"),
    no_save: bool = typer.Option(False, "--no-save", help="Skip saving to database"),
) -> None:
    """Fingerprint agent capabilities."""
    from pentis.attacker.discovery import discover_capabilities

    adapter = OpenAIAdapter(url=url, api_key=api_key)

    console.print(f"\n[bold]Pentis Agent Discovery[/bold]")
    console.print(f"Target: {url}")
    console.print()

    profile = asyncio.run(discover_capabilities(adapter, model=model, target_url=url))
    asyncio.run(adapter.close())

    if not no_save:
        store = Store()
        store.save_agent_profile(profile)
        store.close()

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
) -> None:
    """Compare two scans and show regressions/improvements."""
    from pentis.diff.comparator import diff_scans, format_diff_report

    store = Store()
    result_a = store.get_scan(scan_a)
    result_b = store.get_scan(scan_b)
    store.close()

    if not result_a:
        console.print(f"[red]Scan {scan_a} not found[/]")
        raise typer.Exit(1)
    if not result_b:
        console.print(f"[red]Scan {scan_b} not found[/]")
        raise typer.Exit(1)

    scan_diff = diff_scans(result_a, result_b)
    report = format_diff_report(scan_diff)
    console.print(report)

    if scan_diff.regressions:
        console.print(f"\n[red bold]WARNING: {len(scan_diff.regressions)} regressions detected![/]")


@app.command()
def evolve(
    url: str = typer.Argument(help="Target endpoint URL"),
    attack_id: str = typer.Argument(help="Attack template ID to mutate"),
    api_key: str = typer.Option("", "--api-key", "-k"),
    model: str = typer.Option("default", "--model", "-m"),
    attacker_url: Optional[str] = typer.Option(None, "--attacker-url", help="Attacker LLM endpoint"),
    attacker_key: str = typer.Option("", "--attacker-key", help="Attacker LLM API key"),
    mutations: int = typer.Option(5, "--mutations", "-n", help="Number of mutations to try"),
) -> None:
    """Mutate an attack to find bypasses (evolve mode)."""
    from pentis.adaptive.mutations import (
        PROGRAMMATIC_MUTATIONS,
        apply_llm_mutation,
        apply_programmatic_mutation,
    )
    from pentis.adaptive.strategies import round_robin, LLM_TYPES, PROGRAMMATIC_TYPES
    from pentis.core.engine import execute_attack
    from pentis.core.models import AttackStep, MutationType

    templates = load_all_templates()
    template = next((t for t in templates if t.id == attack_id), None)
    if not template:
        console.print(f"[red]Attack {attack_id} not found[/]")
        raise typer.Exit(1)

    target_adapter = OpenAIAdapter(url=url, api_key=api_key)
    attacker_adapter = None
    if attacker_url:
        from pentis.adapters.attacker import AttackerAdapter
        raw_attacker = OpenAIAdapter(url=attacker_url, api_key=attacker_key)
        attacker_adapter = AttackerAdapter(raw_attacker)

    console.print(f"\n[bold]Pentis Evolve: {attack_id}[/bold]")
    console.print(f"Target: {url}")
    console.print(f"Mutations: {mutations}")
    console.print()

    original_prompt = template.steps[0].prompt
    history: list[MutationType] = []
    available = PROGRAMMATIC_TYPES + (LLM_TYPES if attacker_adapter else [])

    async def _run():
        results = []
        for i in range(mutations):
            mt = round_robin(history, available=available)
            history.append(mt)

            if mt in PROGRAMMATIC_MUTATIONS:
                mutated = apply_programmatic_mutation(original_prompt, mt, attack_id)
            elif attacker_adapter:
                mutated = await apply_llm_mutation(
                    original_prompt, mt, attacker_adapter, model=model, original_id=attack_id
                )
            else:
                continue

            # Create a variant template with the mutated prompt
            variant = AttackTemplate(
                id=f"{attack_id}-mut{i+1}",
                name=f"{template.name} ({mt.value})",
                severity=template.severity,
                category=template.category,
                owasp=template.owasp,
                objective=template.objective,
                steps=[AttackStep(index=1, prompt=mutated.mutated_prompt)],
                eval_criteria=template.eval_criteria,
            )
            finding = await execute_attack(variant, target_adapter, model=model, delay=0.5)
            results.append((mutated, finding))

            icon = {"VULNERABLE": "[red]VULN[/]", "SAFE": "[green]SAFE[/]", "INCONCLUSIVE": "[yellow]????[/]"}
            console.print(
                f"  [{i+1}/{mutations}] {mt.value}: "
                f"{icon.get(finding.verdict.value, finding.verdict.value)}"
            )
        return results

    results = asyncio.run(_run())
    asyncio.run(target_adapter.close())
    if attacker_adapter:
        asyncio.run(attacker_adapter.close())

    vuln_count = sum(1 for _, f in results if f.verdict.value == "VULNERABLE")
    console.print(f"\n[bold]Evolve Results[/bold]")
    console.print(f"  Mutations tried: {len(results)}")
    console.print(f"  Bypasses found: [red]{vuln_count}[/]")


@app.command()
def baseline(
    scan_id: str = typer.Argument(help="Scan ID to set as baseline"),
    label: str = typer.Option("", "--label", "-l", help="Label for this baseline"),
) -> None:
    """Set a scan as a regression baseline."""
    store = Store()
    result = store.get_scan(scan_id)
    if not result:
        store.close()
        console.print(f"[red]Scan {scan_id} not found[/]")
        raise typer.Exit(1)
    store.save_baseline(scan_id, label=label)
    store.close()
    label_str = f' (label: "{label}")' if label else ""
    console.print(f"Baseline set: {scan_id}{label_str}")


if __name__ == "__main__":
    app()
