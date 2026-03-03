"""Pentis CLI — scan, list, and init commands."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from pentis import __version__

app = typer.Typer(
    name="pentis",
    help="AI Agent Security Scanner — black-box vulnerability testing for LLM-powered agents.",
    no_args_is_help=True,
)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"pentis {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", help="Show version.", callback=version_callback, is_eager=True
    ),
) -> None:
    """Pentis — AI Agent Security Scanner."""


@app.command()
def scan(
    url: str = typer.Option(..., "--url", "-u", help="Target endpoint URL (OpenAI-compatible)."),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="API key for the target endpoint."),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name to use."),
    behaviors: Optional[str] = typer.Option(
        None, "--behaviors", "-b", help="Comma-separated behavior categories to test (default: all)."
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output report file path."),
    timeout: float = typer.Option(30.0, "--timeout", "-t", help="Request timeout in seconds."),
    rate_limit: float = typer.Option(1.0, "--rate-limit", help="Minimum seconds between requests."),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress the ASCII banner."),
) -> None:
    """Scan an AI agent endpoint for security vulnerabilities."""
    from pentis.core.banner import print_banner
    from pentis.core.scanner import Scanner

    if not no_banner:
        print_banner()

    behavior_list = None
    if behaviors:
        behavior_list = [b.strip() for b in behaviors.split(",")]

    scanner = Scanner(
        url=url,
        api_key=api_key,
        model=model,
        behaviors=behavior_list,
        output=output,
        timeout=timeout,
        rate_limit=rate_limit,
    )
    asyncio.run(scanner.run())


@app.command(name="list")
def list_templates(
    behavior: Optional[str] = typer.Option(None, "--behavior", "-b", help="Filter by behavior category."),
) -> None:
    """List available attack templates."""
    from pentis.core.banner import print_banner
    from pentis.core.templates import TemplateLoader

    print_banner()

    loader = TemplateLoader()
    templates = loader.load_all()

    if behavior:
        templates = [t for t in templates if t.behavior == behavior]

    if not templates:
        console.print("[yellow]No templates found.[/yellow]")
        raise typer.Exit()

    from rich.table import Table

    table = Table(title="Attack Templates", show_lines=False)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Behavior", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("OWASP", style="yellow")

    current_behavior = None
    for t in sorted(templates, key=lambda x: (x.behavior, x.id)):
        if current_behavior and t.behavior != current_behavior:
            table.add_row("", "", "", "", "")
        current_behavior = t.behavior
        table.add_row(t.id, t.name, t.behavior, t.severity, t.owasp_id or "—")

    console.print(table)
    console.print(f"\n[dim]{len(templates)} templates loaded[/dim]")


@app.command()
def init(
    path: Path = typer.Argument(Path("."), help="Directory to initialize."),
) -> None:
    """Initialize a pentis configuration file."""
    from pentis.core.banner import print_banner

    print_banner()

    config_path = path / "pentis.yaml"
    if config_path.exists():
        console.print(f"[yellow]Config already exists: {config_path}[/yellow]")
        raise typer.Exit(1)

    config_content = """\
# Pentis Configuration
# See: https://github.com/pentis-ai/pentis

target:
  url: "http://localhost:11434/v1/chat/completions"
  # api_key: "sk-..."
  # model: "llama3"

scan:
  behaviors:
    - goal_adherence
    - tool_safety
    - memory_integrity
  timeout: 30
  rate_limit: 1.0

report:
  format: markdown
  # output: "pentis-report.md"
"""
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(config_content)
    console.print(f"[green]Created config:[/green] {config_path}")
    console.print("[dim]Edit the file, then run: pentis scan --url <endpoint>[/dim]")
