"""Scanner pipeline — discover, load, execute, detect, report."""

from __future__ import annotations

import asyncio
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from pentis.adapters.base import BaseAdapter
from pentis.adaptive.branching import execute_branching_attack, find_vulnerable_paths
from pentis.core.engine import execute_attack
from pentis.core.models import (
    AttackTemplate,
    EvidenceItem,
    Finding,
    ScanResult,
    Target,
    Verdict,
)
from pentis.core.templates import load_all_templates

# Reorder remaining attacks every N findings
_REORDER_INTERVAL = 10

# Maximum branching depth for deep probes
_PROBE_MAX_DEPTH = 2


def _prioritize_templates(
    remaining: list[AttackTemplate],
    vuln_categories: Counter[str],
) -> list[AttackTemplate]:
    """Sort remaining templates: categories with known vulnerabilities first."""
    if not vuln_categories:
        return remaining

    def sort_key(t: AttackTemplate) -> tuple[int, str]:
        # Higher vuln count → lower sort value (run first)
        count = vuln_categories.get(t.category, 0)
        return (-count, t.id)

    return sorted(remaining, key=sort_key)


async def _deep_probe(
    template: AttackTemplate,
    adapter: BaseAdapter,
    model: str,
    delay: float,
) -> list[Finding]:
    """Probe a confirmed vulnerability deeper using conversation branching.

    When an attack succeeds, we explore follow-up conversation paths to discover
    additional vulnerable behaviors stemming from the same weakness.
    """
    root = await execute_branching_attack(
        template=template,
        adapter=adapter,
        model=model,
        max_depth=_PROBE_MAX_DEPTH,
        delay=delay,
    )

    probe_findings: list[Finding] = []
    vuln_paths = find_vulnerable_paths(root)

    for path in vuln_paths:
        # Skip the root path (depth=0) — that's the original finding
        deep_nodes = [n for n in path if n.depth > 0 and n.verdict == Verdict.VULNERABLE]
        for node in deep_nodes:
            evidence = [
                EvidenceItem(
                    step_index=node.depth,
                    prompt=node.prompt,
                    response=node.response,
                )
            ]
            probe_findings.append(
                Finding(
                    template_id=f"{template.id}-probe-d{node.depth}",
                    template_name=f"{template.name} (deep probe depth {node.depth})",
                    verdict=Verdict.VULNERABLE,
                    severity=template.severity,
                    category=template.category,
                    owasp=template.owasp,
                    evidence=evidence,
                    reasoning=f"Deep probe from {template.id}: follow-up at depth {node.depth} "
                    f"also yielded vulnerability via {node.response_class.value} path",
                    probe_source=template.id,
                )
            )

    return probe_findings


async def run_scan(
    target: Target,
    adapter: BaseAdapter,
    attacks_dir: Path | None = None,
    category: str | None = None,
    delay: float = 1.5,
    on_finding: Callable[[Finding, int, int], None] | None = None,
    reorder: bool = True,
    deep_probe: bool = False,
) -> ScanResult:
    """Run a full scan: load templates, execute attacks, collect findings.

    Args:
        target: The target to scan.
        adapter: Adapter for communicating with the target.
        attacks_dir: Override directory for attack playbooks.
        category: Filter to a specific category subdirectory.
        delay: Seconds to wait between attacks.
        on_finding: Optional callback(finding, current_index, total) for progress.
        reorder: Dynamically reorder remaining attacks based on findings.
        deep_probe: When a vulnerability is found, probe deeper with branching.
    """
    templates = load_all_templates(attacks_dir=attacks_dir, category=category)
    result = ScanResult(target=target)
    total = len(templates)

    remaining = list(templates)
    executed = 0
    vuln_categories: Counter[str] = Counter()

    while remaining:
        template = remaining.pop(0)
        finding = await execute_attack(template, adapter, model=target.model, delay=delay)
        result.findings.append(finding)
        executed += 1

        if finding.verdict == Verdict.VULNERABLE:
            vuln_categories[finding.category] += 1

            # Deep probe: explore the vulnerability further
            if deep_probe:
                await asyncio.sleep(delay)
                probe_findings = await _deep_probe(template, adapter, target.model, delay)
                result.findings.extend(probe_findings)

        if on_finding:
            on_finding(finding, executed, total)

        # Reorder remaining attacks periodically
        if reorder and remaining and executed % _REORDER_INTERVAL == 0:
            remaining = _prioritize_templates(remaining, vuln_categories)

        # Rate-limit between attacks
        if remaining:
            await asyncio.sleep(delay)

    result.finished_at = datetime.now(UTC)
    return result
