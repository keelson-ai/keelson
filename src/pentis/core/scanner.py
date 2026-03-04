"""Scanner pipeline — discover, load, execute, detect, report."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from pentis.adapters.base import BaseAdapter
from pentis.core.engine import execute_attack
from pentis.core.models import AttackTemplate, Finding, ScanResult, Target
from pentis.core.templates import load_all_templates


async def run_scan(
    target: Target,
    adapter: BaseAdapter,
    attacks_dir: Path | None = None,
    category: str | None = None,
    delay: float = 1.5,
    on_finding: Callable[[Finding, int, int], None] | None = None,
) -> ScanResult:
    """Run a full scan: load templates, execute attacks, collect findings.

    Args:
        target: The target to scan.
        adapter: Adapter for communicating with the target.
        attacks_dir: Override directory for attack playbooks.
        category: Filter to a specific category subdirectory.
        delay: Seconds to wait between attacks.
        on_finding: Optional callback(finding, current_index, total) for progress.
    """
    templates = load_all_templates(attacks_dir=attacks_dir, category=category)
    result = ScanResult(target=target)
    total = len(templates)

    for i, template in enumerate(templates):
        finding = await execute_attack(template, adapter, model=target.model, delay=delay)
        result.findings.append(finding)
        if on_finding:
            on_finding(finding, i + 1, total)
        # Rate-limit between attacks
        if i < total - 1:
            await asyncio.sleep(delay)

    result.finished_at = datetime.now(timezone.utc)
    return result
