"""Pentis CLI — AI agent security scanner."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, TypeVar

import typer
from rich.console import Console

from pentis.adapters.base import BaseAdapter
from pentis.adapters.openai import OpenAIAdapter
from pentis.core.models import (
    CampaignResult,
    Finding,
    ScanResult,
    StatisticalFinding,
)

_T = TypeVar("_T")

app = typer.Typer(name="pentis", help="AI agent security scanner — Living Red Team")
console = Console()

# --- Shared constants ---

VERDICT_ICONS: dict[str, str] = {
    "VULNERABLE": "[red]VULN[/]",
    "SAFE": "[green]SAFE[/]",
    "INCONCLUSIVE": "[yellow]????[/]",
}

VERDICT_ICONS_FULL: dict[str, str] = {
    "VULNERABLE": "[red]VULNERABLE[/]",
    "SAFE": "[green]SAFE[/]",
    "INCONCLUSIVE": "[yellow]INCONCLUSIVE[/]",
}

SEVERITY_COLORS: dict[str, str] = {
    "Critical": "red",
    "High": "red",
    "Medium": "yellow",
    "Low": "green",
}


def make_finding_callback():  # type: ignore[no-untyped-def]
    def _cb(finding: Finding, current: int, total: int) -> None:
        icon = VERDICT_ICONS.get(finding.verdict.value, finding.verdict.value)
        console.print(
            f"  [{current}/{total}] {finding.template_id}: {icon} — {finding.template_name}"
        )

    return _cb


def make_stat_finding_callback():  # type: ignore[no-untyped-def]
    def _cb(finding: StatisticalFinding, current: int, total: int) -> None:
        icon = VERDICT_ICONS.get(finding.verdict.value, finding.verdict.value)
        console.print(
            f"  [{current}/{total}] {finding.template_id}: {icon} "
            f"({finding.success_rate:.0%} in {finding.num_trials} trials)"
        )

    return _cb


def write_report(
    result: ScanResult | CampaignResult,
    fmt: str,
    output: Path | None,
    prefix: str,
    *,
    debug: bool = False,
) -> Path:
    """Write a report in the requested format and return the output path."""
    out_dir = output or Path("reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = result.started_at.strftime("%Y-%m-%d-%H%M%S")

    if fmt == "sarif":
        from pentis.core.sarif import to_sarif_json

        text = to_sarif_json(result)
        path = out_dir / f"{prefix}-{timestamp}.sarif.json"
    elif fmt == "junit":
        from pentis.core.junit import to_junit_xml

        text = to_junit_xml(result)
        path = out_dir / f"{prefix}-{timestamp}.junit.xml"
    elif fmt == "executive":
        from pentis.core.executive_report import generate_executive_report

        if isinstance(result, ScanResult):
            text = generate_executive_report(result, include_safe=debug)
        else:
            console.print(
                "[yellow]Warning: executive format not supported for campaign results, "
                "falling back to markdown[/]"
            )
            from pentis.core.reporter import generate_campaign_report

            text = generate_campaign_report(result)
        path = out_dir / f"{prefix}-{timestamp}.md"
    else:
        from pentis.core.reporter import generate_campaign_report, generate_report

        if isinstance(result, CampaignResult):
            text = generate_campaign_report(result)
        else:
            text = generate_report(result, debug=debug)
        path = out_dir / f"{prefix}-{timestamp}.md"

    path.write_text(text)
    return path


def check_fail_gates(vuln_count: int, total: int, fail_on_vuln: bool, threshold: float) -> None:
    """Check CI fail gates and exit with code 1 if triggered."""
    if fail_on_vuln and vuln_count > 0:
        console.print(
            f"\n[red bold]CI FAILURE: {vuln_count} "
            f"{'vulnerability' if vuln_count == 1 else 'vulnerabilities'} found[/]"
        )
        raise typer.Exit(1)
    if threshold > 0.0 and total > 0:
        rate = vuln_count / total
        if rate > threshold:
            console.print(
                f"\n[red bold]CI FAILURE: vulnerability rate {rate:.0%} "
                f"exceeds threshold {threshold:.0%}[/]"
            )
            raise typer.Exit(1)


def run_with_adapter(
    coro_fn: Callable[[], Awaitable[_T]],
    *adapters: BaseAdapter,
) -> _T:
    """Run an async function and close adapters on completion.

    Replaces the repeated pattern of::

        async def _run():
            try:
                return await some_coroutine(...)
            finally:
                await adapter.close()
        result = asyncio.run(_run())
    """

    async def _run() -> _T:
        try:
            return await coro_fn()
        finally:
            for adapter in adapters:
                await adapter.close()

    return asyncio.run(_run())


def print_scan_summary(result: ScanResult, report_path: Path) -> None:
    """Print the standard scan result summary block."""
    console.print("\n[bold]Results[/bold]")
    console.print(f"  Vulnerable: [red]{result.vulnerable_count}[/]")
    console.print(f"  Safe: [green]{result.safe_count}[/]")
    console.print(f"  Inconclusive: [yellow]{result.inconclusive_count}[/]")
    console.print(f"\nReport saved: {report_path}")


def make_adapter(
    url: str,
    api_key: str,
    adapter_type: str = "openai",
    cache: bool = False,
    assistant_id: str = "agent",
    tool_name: str = "chat",
):
    """Create the appropriate adapter stack based on CLI flags."""
    base: BaseAdapter
    if adapter_type == "anthropic":
        from pentis.adapters.anthropic import AnthropicAdapter

        base = AnthropicAdapter(api_key=api_key, url=url)
    elif adapter_type == "langgraph":
        from pentis.adapters.langgraph import LangGraphAdapter

        base = LangGraphAdapter(url=url, api_key=api_key, assistant_id=assistant_id)
    elif adapter_type == "mcp":
        from pentis.adapters.mcp import MCPAdapter

        base = MCPAdapter(url=url, api_key=api_key, tool_name=tool_name)
    elif adapter_type == "a2a":
        from pentis.adapters.a2a import A2AAdapter

        base = A2AAdapter(url=url, api_key=api_key)
    else:
        base = OpenAIAdapter(url=url, api_key=api_key)

    if cache:
        from pentis.adapters.cache import CachingAdapter

        base = CachingAdapter(base)

    return base


def print_cache_stats(adapter: Any) -> None:
    """Print cache stats if the adapter is a CachingAdapter."""
    from pentis.adapters.cache import CachingAdapter

    current: Any = adapter
    while current:
        if isinstance(current, CachingAdapter):
            stats = current.stats
            console.print(
                f"\n[dim]Cache: {stats.hits} hits, {stats.misses} misses, "
                f"{stats.evictions} evictions, {stats.size} cached[/]"
            )
            return
        current = getattr(current, "_adapter", None)


# Register command modules — import triggers @app.command() registration
from pentis.cli import commands as commands  # noqa: E402
