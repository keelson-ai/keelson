"""Pentis CLI — scan, list, discover, and quality-gate commands."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console

from pentis import __version__

app = typer.Typer(
    name="pentis",
    help="AI Agent Security Scanner — black-box vulnerability testing for LLM-powered agents.",
    no_args_is_help=True,
)
console = Console()
DEFAULT_CONFIG_PATH = Path(".pentis.yaml")


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
    url: Optional[str] = typer.Option(None, "--url", "-u", help="Target endpoint URL (OpenAI-compatible)."),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="API key for the target endpoint."),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name to use."),
    config: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", "-c", help="Path to config file."),
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

    cfg = _load_config(config)
    target = cfg.get("target", {})
    scan_cfg = cfg.get("scan", {})

    url = url or target.get("url")
    if not url:
        raise typer.BadParameter("Provide --url or set target.url in .pentis.yaml")

    api_key = api_key or target.get("api_key")
    model = model or target.get("model")
    timeout = float(scan_cfg.get("timeout", timeout))
    rate_limit = float(scan_cfg.get("rate_limit", rate_limit))

    behavior_list = None
    if behaviors:
        behavior_list = [b.strip() for b in behaviors.split(",")]
    elif isinstance(scan_cfg.get("behaviors"), list):
        behavior_list = [str(b).strip() for b in scan_cfg["behaviors"]]

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

    config_path = path / DEFAULT_CONFIG_PATH.name
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


@app.command()
def discover(
    url: str = typer.Option(..., "--url", "-u", help="Target endpoint URL (OpenAI-compatible)."),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="API key for the target endpoint."),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name to use."),
    timeout: float = typer.Option(30.0, "--timeout", "-t", help="Request timeout in seconds."),
    output: str = typer.Option("table", "--output", help="Output format: table or json."),
    graph_output: Optional[Path] = typer.Option(
        None, "--graph-output", help="Optional path to write tool-chain graph JSON."
    ),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress the ASCII banner."),
) -> None:
    """Discover agent capabilities without running attack templates."""
    from pentis.adapters.http import HTTPAdapter
    from pentis.core.banner import print_banner
    from pentis.core.discovery import discover_target
    from pentis.core.discovery_schema import target_info_to_dict, validate_discovery_payload

    if not no_banner:
        print_banner()

    async def _run() -> None:
        adapter = HTTPAdapter(url=url, api_key=api_key, model=model, timeout=timeout)
        try:
            info = await discover_target(adapter)
        finally:
            await adapter.close()

        payload = target_info_to_dict(info)
        validation_errors = validate_discovery_payload(payload)
        if validation_errors:
            console.print(f"[red]Discovery output failed schema validation:[/red] {validation_errors[0]}")
            raise typer.Exit(1)

        if output == "json":
            console.print_json(json.dumps(payload))
        if graph_output:
            graph_output.parent.mkdir(parents=True, exist_ok=True)
            graph_output.write_text(
                json.dumps(
                    {
                        "nodes": info.tool_chain_nodes,
                        "edges": info.tool_chain_edges,
                        "dangerous_combos": info.dangerous_combos,
                    },
                    indent=2,
                )
            )
            console.print(f"[green]Graph written:[/green] {graph_output}")

    asyncio.run(_run())


@app.command()
def audit(
    path: Path = typer.Option(..., "--path", help="Path to codebase for static checks."),
    output: str = typer.Option("table", "--output", help="Output format: table or json."),
) -> None:
    """Run static audit checks against source code without executing the agent."""
    findings = []
    for py_file in path.rglob("*.py"):
        text = py_file.read_text(errors="ignore")
        if "eval(" in text or "os.system(" in text:
            findings.append({"file": str(py_file), "issue": "Potential unsafe execution primitive"})

    if output == "json":
        console.print_json(json.dumps({"path": str(path), "findings": findings}))
        return

    if not findings:
        console.print("[green]No obvious static issues detected.[/green]")
        return

    console.print(f"[yellow]{len(findings)} potential issue(s) found:[/yellow]")
    for finding in findings:
        console.print(f" - {finding['file']}: {finding['issue']}")


@app.command()
def report(
    input_path: Path = typer.Option(..., "--input", help="Input scan report path."),
    output_path: Optional[Path] = typer.Option(None, "--output", help="Optional output path."),
    format: str = typer.Option("markdown", "--format", help="Output format (markdown|json)."),
) -> None:
    """Generate or reformat a report artifact."""
    if not input_path.exists():
        raise typer.BadParameter(f"Input file does not exist: {input_path}")

    content = input_path.read_text()
    out = output_path or input_path
    if format == "json":
        out.write_text(json.dumps({"source": str(input_path), "content": content}, indent=2))
    else:
        out.write_text(content)
    console.print(f"[green]Report written:[/green] {out}")


@app.command()
def ci(
    url: str = typer.Option(..., "--url", "-u", help="Target endpoint URL (OpenAI-compatible)."),
    fail_on: str = typer.Option("high", "--fail-on", help="Severity threshold: critical|high|medium|low|info"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress the ASCII banner."),
) -> None:
    """CI quality gate wrapper around scan."""
    from pentis.core.banner import print_banner
    from pentis.core.scanner import Scanner

    if not no_banner:
        print_banner()

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    threshold = severity_rank.get(fail_on.lower())
    if threshold is None:
        raise typer.BadParameter("fail-on must be one of: critical|high|medium|low|info")

    result = asyncio.run(Scanner(url=url).run())
    max_found = max((severity_rank.get(f.severity, 0) for f in result.findings if f.is_vulnerable), default=0)
    if max_found >= threshold:
        console.print("[red]CI gate failed: findings at or above threshold detected.[/red]")
        raise typer.Exit(1)
    console.print("[green]CI gate passed.[/green]")


@app.command()
def validate(
    template: Path = typer.Option(..., "--template", "-t", help="Path to YAML template."),
) -> None:
    """Validate a custom YAML attack template."""
    from pentis.core.template_schema import validate_template

    if not template.exists():
        raise typer.BadParameter(f"Template not found: {template}")

    data = yaml.safe_load(template.read_text())
    errors = validate_template(data)
    if errors:
        for err in errors:
            console.print(f"[red]- {err}[/red]")
        raise typer.Exit(1)

    console.print(f"[green]Template valid:[/green] {template}")


def _load_config(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise typer.BadParameter(f"Invalid YAML in {path}: {exc}") from exc
