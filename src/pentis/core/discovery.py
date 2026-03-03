"""Discovery phase — probe the target agent for capabilities."""

from __future__ import annotations

from rich.console import Console

from pentis.adapters.http import HTTPAdapter
from pentis.core.graph import build_tool_chain_graph, detect_dangerous_tool_combos
from pentis.core.discovery_schema import target_info_to_dict, validate_discovery_payload
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
        graph = build_tool_chain_graph(info.tools_detected)
        info.tool_chain_nodes = sorted(str(node) for node in graph.nodes)
        info.tool_chain_edges = sorted((str(src), str(dst)) for src, dst in graph.edges)
        info.dangerous_combos = detect_dangerous_tool_combos(info.tools_detected)
        if info.dangerous_combos:
            console.print(f"  [red]Dangerous combos:[/red] {', '.join(info.dangerous_combos)}")
    else:
        console.print("  [dim]No tool calls detected[/dim]")

    validation_errors = validate_discovery_payload(target_info_to_dict(info))
    if validation_errors:
        console.print("[yellow]Discovery output contract warnings:[/yellow]")
        for err in validation_errors[:3]:
            console.print(f"  - {err}")

    console.print()
    return info
