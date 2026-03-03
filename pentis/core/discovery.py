"""Discovery phase — probe the target agent for capabilities."""

from __future__ import annotations

from rich.console import Console

from pentis.adapters.http import HTTPAdapter
from pentis.core.models import TargetInfo

console = Console()


async def discover_target(adapter: HTTPAdapter) -> TargetInfo:
    """Run discovery probes against the target endpoint.

    Returns a TargetInfo with detected capabilities.
    """
    console.print("[dim]Running discovery probes...[/dim]")

    try:
        info = await adapter.discover()
    except Exception as e:
        console.print(f"[red]Discovery failed: {e}[/red]")
        return TargetInfo(url=adapter.url)

    # Report findings
    console.print(f"  Model: [cyan]{info.model}[/cyan]")

    if info.system_prompt_leaked:
        console.print("  [yellow]System prompt leaked![/yellow]")

    if info.supports_tools:
        console.print(f"  Tools detected: [green]{len(info.tools_detected)}[/green]")
        for tool in info.tools_detected[:10]:
            console.print(f"    - {tool}")
    else:
        console.print("  [dim]No tool calls detected[/dim]")

    console.print()
    return info
