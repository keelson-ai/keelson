"""Simple campaign scheduler — foreground asyncio loop with cron-like timing."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from pathlib import Path

from keelson.adapters.base import BaseAdapter
from keelson.campaign.runner import run_campaign
from keelson.core.models import CampaignConfig, CampaignResult, Target


def parse_interval(interval: str) -> int:
    """Parse a human-readable interval string into seconds.

    Supports: "30s", "5m", "1h", "2h30m", "1d"
    """
    total = 0
    pattern = re.compile(r"(\d+)([smhd])")
    matches = pattern.findall(interval.lower())
    if not matches:
        raise ValueError(f"Invalid interval format: {interval}. Use e.g. '30s', '5m', '1h', '1d'")
    for value, unit in matches:
        n = int(value)
        if unit == "s":
            total += n
        elif unit == "m":
            total += n * 60
        elif unit == "h":
            total += n * 3600
        elif unit == "d":
            total += n * 86400
    return total


async def run_scheduled(
    target: Target,
    adapter: BaseAdapter,
    config: CampaignConfig,
    interval_seconds: int,
    max_runs: int | None = None,
    attacks_dir: Path | None = None,
    on_campaign: Callable[[CampaignResult, int], None] | None = None,
) -> list[CampaignResult]:
    """Run campaigns on a schedule.

    Args:
        target: Target to scan.
        adapter: Target adapter.
        config: Campaign configuration.
        interval_seconds: Seconds between campaign runs.
        max_runs: Maximum number of runs (None = run forever).
        attacks_dir: Override probes directory.
        on_campaign: Callback(result, run_number) after each campaign.

    Returns:
        List of all campaign results.
    """
    results: list[CampaignResult] = []
    run_number = 0

    while max_runs is None or run_number < max_runs:
        run_number += 1
        result = await run_campaign(target, adapter, config, attacks_dir=attacks_dir)
        results.append(result)

        if on_campaign:
            on_campaign(result, run_number)

        if max_runs is not None and run_number >= max_runs:
            break

        await asyncio.sleep(interval_seconds)

    return results
