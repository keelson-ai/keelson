"""Scan commands: scan, pipeline-scan, smart-scan, attack."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import typer

from pentis.cli import (
    VERDICT_ICONS_FULL,
    app,
    check_fail_gates,
    console,
    make_adapter,
    make_finding_callback,
    make_stat_finding_callback,
    print_cache_stats,
    write_report,
)
from pentis.core.models import ScanTier, Target
from pentis.core.scanner import run_scan
from pentis.core.templates import load_all_templates
from pentis.state.store import Store


@app.command()
def scan(
    url: str = typer.Argument(help="Target endpoint URL (OpenAI-compatible chat completions)"),
    api_key: str = typer.Option("", "--api-key", "-k", help="API key for authentication"),
    model: str = typer.Option("default", "--model", "-m", help="Model name for requests"),
    category: str | None = typer.Option(None, "--category", "-c", help="Filter by category"),
    delay: float = typer.Option(1.5, "--delay", "-d", help="Seconds between requests"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Report output directory"),
    no_save: bool = typer.Option(False, "--no-save", help="Skip saving to database"),
    adapter: str = typer.Option(
        "openai", "--adapter", "-a", help="Adapter type: openai, anthropic, langgraph, mcp, or a2a"
    ),
    use_cache: bool = typer.Option(False, "--cache", help="Enable response caching"),
    tier: str | None = typer.Option(
        None, "--tier", "-t", help="Scan tier: fast, deep, or continuous"
    ),
    format: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Output format: markdown, executive, sarif, or junit",
    ),
    fail_on_vuln: bool = typer.Option(
        False, "--fail-on-vuln", help="Exit with code 1 if any vulnerabilities found"
    ),
    fail_threshold: float = typer.Option(
        0.0,
        "--fail-threshold",
        help="Vulnerability rate threshold (0.0-1.0) above which to fail (requires --fail-on-vuln)",
    ),
    assistant_id: str = typer.Option("agent", "--assistant-id", help="LangGraph assistant ID"),
    tool_name: str = typer.Option("chat", "--tool-name", help="MCP tool name to call"),
    debug: bool = typer.Option(False, "--debug", help="Include SAFE findings in report"),
) -> None:
    """Run a full security scan against an AI agent endpoint."""
    target = Target(url=url, api_key=api_key, model=model)

    if tier:
        from pentis.campaign.runner import run_campaign
        from pentis.campaign.tiers import get_tier_config

        scan_tier = ScanTier(tier)
        overrides: dict[str, Any] = {}
        if category:
            overrides["category"] = category
        config = get_tier_config(scan_tier, overrides)
        config.target_url = url
        config.api_key = api_key
        config.model = model

        target_adapter = make_adapter(url, api_key, adapter, use_cache, assistant_id, tool_name)
        on_finding_tier = make_stat_finding_callback()

        console.print(f"\n[bold]Pentis Security Scan (tier: {tier})[/bold]")
        console.print(f"Target: {url}")
        concurrency = config.concurrency.max_concurrent_trials
        console.print(f"Trials/attack: {config.trials_per_attack} | Concurrency: {concurrency}")
        console.print()

        async def _run_tier():
            try:
                return await run_campaign(
                    target=target, adapter=target_adapter, config=config, on_finding=on_finding_tier
                )
            finally:
                await target_adapter.close()

        result = asyncio.run(_run_tier())

        if not no_save:
            store = Store()
            store.save_campaign(result)
            store.close()

        report_path = write_report(result, format, output, f"scan-{tier}", debug=debug)

        print_cache_stats(target_adapter)

        console.print("\n[bold]Results[/bold]")
        console.print(f"  Attacks tested: {len(result.findings)}")
        console.print(f"  Vulnerable: [red]{result.vulnerable_attacks}[/]")
        console.print(f"  Total trials: {result.total_trials}")
        console.print(f"\nReport saved: {report_path}")

        check_fail_gates(
            result.vulnerable_attacks, len(result.findings), fail_on_vuln, fail_threshold
        )

        return

    # Standard single-pass scan
    target_adapter = make_adapter(url, api_key, adapter, use_cache, assistant_id, tool_name)
    on_finding = make_finding_callback()

    console.print("\n[bold]Pentis Security Scan[/bold]")
    console.print(f"Target: {url}")
    console.print(f"Model: {model}")
    if category:
        console.print(f"Category: {category}")
    console.print()

    async def _run():
        try:
            return await run_scan(
                target=target,
                adapter=target_adapter,
                category=category,
                delay=delay,
                on_finding=on_finding,
            )
        finally:
            await target_adapter.close()

    result = asyncio.run(_run())

    if not no_save:
        store = Store()
        store.save_scan(result)
        store.close()

    report_path = write_report(result, format, output, "scan", debug=debug)

    print_cache_stats(target_adapter)

    console.print("\n[bold]Results[/bold]")
    console.print(f"  Vulnerable: [red]{result.vulnerable_count}[/]")
    console.print(f"  Safe: [green]{result.safe_count}[/]")
    console.print(f"  Inconclusive: [yellow]{result.inconclusive_count}[/]")
    console.print(f"\nReport saved: {report_path}")

    check_fail_gates(result.vulnerable_count, len(result.findings), fail_on_vuln, fail_threshold)


@app.command(name="pipeline-scan")
def pipeline_scan(
    url: str = typer.Argument(help="Target endpoint URL (OpenAI-compatible chat completions)"),
    api_key: str = typer.Option("", "--api-key", "-k", help="API key for authentication"),
    model: str = typer.Option("default", "--model", "-m", help="Model name for requests"),
    category: str | None = typer.Option(None, "--category", "-c", help="Filter by category"),
    delay: float = typer.Option(1.5, "--delay", "-d", help="Seconds between requests"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Report output directory"),
    no_save: bool = typer.Option(False, "--no-save", help="Skip saving to database"),
    adapter: str = typer.Option(
        "openai",
        "--adapter",
        "-a",
        help="Adapter type: openai, anthropic, langgraph, mcp, or a2a",
    ),
    use_cache: bool = typer.Option(False, "--cache", help="Enable response caching"),
    concurrency: int = typer.Option(5, "--concurrency", help="Max concurrent attacks"),
    no_verify: bool = typer.Option(
        False, "--no-verify", help="Skip vulnerability verification phase"
    ),
    checkpoint_dir: Path | None = typer.Option(
        None, "--checkpoint-dir", help="Directory for checkpoint files (enables resume)"
    ),
    format: str = typer.Option(
        "executive",
        "--format",
        "-f",
        help="Output format: executive, markdown, sarif, or junit",
    ),
    fail_on_vuln: bool = typer.Option(
        False, "--fail-on-vuln", help="Exit with code 1 if any vulnerabilities found"
    ),
    fail_threshold: float = typer.Option(
        0.0, "--fail-threshold", help="Vulnerability rate threshold (0.0-1.0) to trigger failure"
    ),
    assistant_id: str = typer.Option("agent", "--assistant-id", help="LangGraph assistant ID"),
    tool_name: str = typer.Option("chat", "--tool-name", help="MCP tool name to call"),
    debug: bool = typer.Option(False, "--debug", help="Include SAFE findings in report"),
) -> None:
    """Run a parallel pipeline scan with checkpoint/resume and verification."""
    from pentis.core.pipeline import PipelineConfig, run_pipeline

    target = Target(url=url, api_key=api_key, model=model)
    target_adapter = make_adapter(url, api_key, adapter, use_cache, assistant_id, tool_name)
    on_finding = make_finding_callback()

    config = PipelineConfig(
        max_concurrent=concurrency,
        delay=delay,
        checkpoint_dir=checkpoint_dir,
        verify_vulnerabilities=not no_verify,
        on_finding=on_finding,
    )

    console.print("\n[bold]Pentis Pipeline Scan[/bold]")
    console.print(f"Target: {url}")
    console.print(f"Model: {model}")
    console.print(f"Concurrency: {concurrency}")
    console.print(f"Verification: {'enabled' if not no_verify else 'disabled'}")
    if checkpoint_dir:
        console.print(f"Checkpoints: {checkpoint_dir}")
    if category:
        console.print(f"Category: {category}")
    console.print()

    async def _run():
        try:
            return await run_pipeline(
                target=target,
                adapter=target_adapter,
                config=config,
                category=category,
            )
        finally:
            await target_adapter.close()

    result = asyncio.run(_run())

    if not no_save:
        store = Store()
        store.save_scan(result)
        store.close()

    report_path = write_report(result, format, output, "pipeline-scan", debug=debug)

    print_cache_stats(target_adapter)

    console.print("\n[bold]Pipeline Results[/bold]")
    console.print(f"  Vulnerable: [red]{result.vulnerable_count}[/]")
    console.print(f"  Safe: [green]{result.safe_count}[/]")
    console.print(f"  Inconclusive: [yellow]{result.inconclusive_count}[/]")
    console.print(f"\nReport saved: {report_path}")

    check_fail_gates(result.vulnerable_count, len(result.findings), fail_on_vuln, fail_threshold)


@app.command(name="smart-scan")
def smart_scan(
    url: str = typer.Argument(help="Target endpoint URL"),
    api_key: str = typer.Option("", "--api-key", "-k", help="API key for authentication"),
    model: str = typer.Option("default", "--model", "-m", help="Model name for requests"),
    delay: float = typer.Option(2.0, "--delay", "-d", help="Seconds between requests"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Report output directory"),
    no_save: bool = typer.Option(False, "--no-save", help="Skip saving to database"),
    adapter: str = typer.Option(
        "openai",
        "--adapter",
        "-a",
        help="Adapter type: openai, anthropic, langgraph, mcp, or a2a",
    ),
    use_cache: bool = typer.Option(False, "--cache", help="Enable response caching"),
    format: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Output format: markdown, executive, sarif, or junit",
    ),
    fail_on_vuln: bool = typer.Option(
        False, "--fail-on-vuln", help="Exit with code 1 if any vulnerabilities found"
    ),
    fail_threshold: float = typer.Option(0.0, "--fail-threshold", help="Vuln rate threshold"),
    assistant_id: str = typer.Option("agent", "--assistant-id", help="LangGraph assistant ID"),
    tool_name: str = typer.Option("chat", "--tool-name", help="MCP tool name to call"),
    debug: bool = typer.Option(False, "--debug", help="Include SAFE findings in report"),
    verify: bool = typer.Option(
        False, "--verify", help="Re-probe VULNERABLE findings to confirm them"
    ),
) -> None:
    """Adaptive smart scan: discover, classify, select relevant attacks, execute in sessions."""
    from pentis.core.smart_scan import run_smart_scan

    target = Target(url=url, api_key=api_key, model=model)
    target_adapter = make_adapter(url, api_key, adapter, use_cache, assistant_id, tool_name)
    on_finding = make_finding_callback()

    console.print("\n[bold]Pentis Smart Scan[/bold]")
    console.print(f"Target: {url}")
    console.print(f"Model: {model}")
    console.print()

    def on_phase(phase: str, detail: str) -> None:
        phase_icons = {
            "discovery": "[cyan]DISCOVER[/]",
            "classify": "[cyan]CLASSIFY[/]",
            "profile": "[cyan]PROFILE [/]",
            "plan": "[cyan]PLAN    [/]",
            "category": "[dim]        [/]",
            "execute": "[cyan]EXECUTE [/]",
            "session": "[dim]SESSION [/]",
            "adapt": "[yellow]ADAPT   [/]",
            "verify": "[cyan]VERIFY  [/]",
            "done": "[green]DONE    [/]",
        }
        icon = phase_icons.get(phase, f"[dim]{phase:8s}[/]")
        console.print(f"  {icon} {detail}")

    async def _run():
        try:
            return await run_smart_scan(
                target=target,
                adapter=target_adapter,
                delay=delay,
                on_finding=on_finding,
                on_phase=on_phase,
                verify=verify,
            )
        finally:
            await target_adapter.close()

    result = asyncio.run(_run())

    if not no_save:
        store = Store()
        store.save_scan(result)
        store.close()

    report_path = write_report(result, format, output, "smart-scan", debug=debug)

    console.print("\n[bold]Results[/bold]")
    console.print(f"  Vulnerable: [red]{result.vulnerable_count}[/]")
    console.print(f"  Safe: [green]{result.safe_count}[/]")
    console.print(f"  Inconclusive: [yellow]{result.inconclusive_count}[/]")
    console.print(f"\nReport saved: {report_path}")

    check_fail_gates(result.vulnerable_count, len(result.findings), fail_on_vuln, fail_threshold)


@app.command()
def attack(
    url: str = typer.Argument(help="Target endpoint URL"),
    attack_id: str = typer.Argument(help="Attack template ID (e.g., GA-001)"),
    api_key: str = typer.Option("", "--api-key", "-k"),
    model: str = typer.Option("default", "--model", "-m"),
    adapter: str = typer.Option(
        "openai", "--adapter", "-a", help="Adapter type: openai, anthropic, langgraph, mcp, or a2a"
    ),
    assistant_id: str = typer.Option("agent", "--assistant-id", help="LangGraph assistant ID"),
    tool_name: str = typer.Option("chat", "--tool-name", help="MCP tool name to call"),
) -> None:
    """Run a single attack against a target."""
    from pentis.core.engine import execute_attack

    templates = load_all_templates()
    template = next((t for t in templates if t.id == attack_id), None)
    if not template:
        console.print(f"[red]Attack {attack_id} not found[/]")
        raise typer.Exit(1)

    target_adapter = make_adapter(
        url, api_key, adapter, assistant_id=assistant_id, tool_name=tool_name
    )
    console.print(f"\n[bold]{template.id}: {template.name}[/bold]")
    console.print(f"Severity: {template.severity.value} | Category: {template.category.value}")
    console.print()

    async def _run():
        try:
            return await execute_attack(template, target_adapter, model=model)
        finally:
            await target_adapter.close()

    finding = asyncio.run(_run())

    console.print(
        f"Verdict: {VERDICT_ICONS_FULL.get(finding.verdict.value, finding.verdict.value)}"
    )
    console.print(f"Reasoning: {finding.reasoning}")
    for ev in finding.evidence:
        console.print(f"\n  Step {ev.step_index}:")
        console.print(f"  Prompt: {ev.prompt[:150]}...")
        console.print(f"  Response ({ev.response_time_ms}ms): {ev.response[:200]}...")
