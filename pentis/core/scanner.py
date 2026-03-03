"""Scanner — main orchestrator for the scan pipeline."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from pentis.adapters.http import HTTPAdapter
from pentis.core.discovery import discover_target
from pentis.core.engine import AttackEngine
from pentis.core.models import Finding, FindingStatus, ScanResult
from pentis.core.reporter import MarkdownReporter, TerminalReporter
from pentis.core.templates import TemplateLoader
from pentis.strategies.fixed import FixedStrategy

console = Console()


class Scanner:
    """Main scan orchestrator: discover → attack → detect → report."""

    def __init__(
        self,
        url: str,
        api_key: str | None = None,
        model: str | None = None,
        behaviors: list[str] | None = None,
        output: Path | None = None,
        timeout: float = 30.0,
        rate_limit: float = 1.0,
    ) -> None:
        self.url = url
        self.api_key = api_key
        self.model = model
        self.behaviors = behaviors
        self.output = output
        self.timeout = timeout
        self.rate_limit = rate_limit

    async def run(self) -> ScanResult:
        """Execute the full scan pipeline."""
        start_time = datetime.now()

        # 1. Setup adapter
        adapter = HTTPAdapter(
            url=self.url,
            api_key=self.api_key,
            model=self.model,
            timeout=self.timeout,
        )

        try:
            # 2. Discovery phase
            target_info = await discover_target(adapter)

            # 3. Load templates
            loader = TemplateLoader()
            templates = loader.load_all()

            if self.behaviors:
                templates = [t for t in templates if t.behavior in self.behaviors]

            if not templates:
                console.print("[yellow]No templates to execute.[/yellow]")
                return ScanResult(target=target_info, start_time=start_time)

            # 4. Order templates
            strategy = FixedStrategy()
            templates = strategy.order(templates)

            # 5. Execute attacks
            engine = AttackEngine(adapter=adapter, rate_limit=self.rate_limit)
            terminal_reporter = TerminalReporter()

            result = ScanResult(
                target=target_info,
                start_time=start_time,
                templates_total=len(templates),
            )

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Scanning...", total=len(templates))

                def on_finding(finding: Finding) -> None:
                    result.findings.append(finding)
                    result.templates_run += 1
                    progress.update(task, advance=1, description=f"[{finding.template_id}] {finding.template_name[:40]}")
                    terminal_reporter.print_finding(finding)

                await engine.execute_all(templates, on_finding=on_finding)

            result.end_time = datetime.now()

            # 6. Print summary
            terminal_reporter.print_summary(result)

            # 7. Generate report
            report_path = self.output or Path(f"pentis-report-{start_time.strftime('%Y%m%d-%H%M%S')}.md")
            md_reporter = MarkdownReporter()
            md_reporter.generate(result, report_path)
            console.print(f"\n[green]Report saved to:[/green] {report_path}")

            return result

        finally:
            await adapter.close()
