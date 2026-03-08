"""Scanner pipeline — discover, load, execute, detect, report."""

from __future__ import annotations

import asyncio
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from keelson.adapters.base import BaseAdapter
from keelson.adaptive.branching import execute_branching_attack, find_vulnerable_paths
from keelson.core.engine import execute_probe
from keelson.core.models import (
    EvidenceItem,
    Finding,
    ProbeTemplate,
    ScanResult,
    Target,
    Verdict,
)
from keelson.core.templates import load_all_templates
from keelson.core.yaml_templates import update_effectiveness_scores

# Reorder remaining probes every N findings
_REORDER_INTERVAL = 10

# Maximum branching depth for deep probes
_PROBE_MAX_DEPTH = 2


def _prioritize_templates(
    remaining: list[ProbeTemplate],
    vuln_categories: Counter[str],
) -> list[ProbeTemplate]:
    """Sort remaining templates: categories with known vulnerabilities first."""
    if not vuln_categories:
        return remaining

    def sort_key(t: ProbeTemplate) -> tuple[int, str]:
        # Higher vuln count → lower sort value (run first)
        count = vuln_categories.get(t.category, 0)
        return (-count, t.id)

    return sorted(remaining, key=sort_key)


async def _deep_probe(
    template: ProbeTemplate,
    adapter: BaseAdapter,
    model: str,
    delay: float,
) -> list[Finding]:
    """Probe a confirmed vulnerability deeper using conversation branching.

    When a probe succeeds, we explore follow-up conversation paths to discover
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

    # Deduplicate: a node can appear in multiple paths (intermediate + leaf).
    # Track seen node_ids to emit each vulnerable node only once.
    seen_node_ids: set[str] = set()

    for path in vuln_paths:
        # Skip the root (depth=0) — that's the original finding
        deep_nodes = [n for n in path if n.depth > 0 and n.verdict == Verdict.VULNERABLE]
        for node in deep_nodes:
            if node.node_id in seen_node_ids:
                continue
            seen_node_ids.add(node.node_id)

            evidence = [
                EvidenceItem(
                    step_index=node.depth,
                    prompt=node.prompt,
                    response=node.response,
                )
            ]
            # Use node_id for uniqueness so downstream dict-keyed consumers don't collide
            probe_findings.append(
                Finding(
                    template_id=f"{template.id}-probe-{node.node_id}",
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
    reorder: bool = False,
    deep_probe: bool = False,
    max_response_tokens: int | None = 512,
) -> ScanResult:
    """Run a full scan: load templates, execute probes, collect findings.

    Args:
        target: The target to scan.
        adapter: Adapter for communicating with the target.
        attacks_dir: Override directory for probe playbooks.
        category: Filter to a specific category subdirectory.
        delay: Seconds to wait between probes.
        on_finding: Optional callback(finding, current_index, total) for progress.
        reorder: Dynamically reorder remaining probes based on findings.
        deep_probe: When a vulnerability is found, probe deeper with branching.
        max_response_tokens: Limit target response length to save tokens (default 512).
            Set to None to allow unlimited responses.
    """
    templates = load_all_templates(attacks_dir=attacks_dir, category=category)
    result = ScanResult(target=target)
    total = len(templates)

    remaining = list(templates)
    executed = 0
    vuln_categories: Counter[str] = Counter()

    while remaining:
        template = remaining.pop(0)
        finding = await execute_probe(
            template,
            adapter,
            model=target.model,
            delay=delay,
            max_response_tokens=max_response_tokens,
        )
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

        # Reorder remaining probes periodically
        if reorder and remaining and executed % _REORDER_INTERVAL == 0:
            remaining = _prioritize_templates(remaining, vuln_categories)

        # Rate-limit between probes
        if remaining:
            await asyncio.sleep(delay)

    result.finished_at = datetime.now(UTC)
    update_effectiveness_scores(result.findings, templates)
    return result
