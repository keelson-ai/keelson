"""Attack execution engine — loads template, sends steps, produces findings."""

from __future__ import annotations

import asyncio

from pentis.adapters.base import BaseAdapter
from pentis.core.detection import detect
from pentis.core.models import AttackTemplate, EvidenceItem, Finding
from pentis.core.observer import StreamingObserver


async def execute_attack(
    template: AttackTemplate,
    adapter: BaseAdapter,
    model: str = "default",
    delay: float = 1.0,
    observer: StreamingObserver | None = None,
) -> Finding:
    """Execute an attack template against a target via the adapter.

    Sends each step, accumulates messages for multi-turn, runs detection.
    Optionally runs a StreamingObserver for per-step leakage analysis.
    """
    messages: list[dict[str, str]] = []
    evidence: list[EvidenceItem] = []

    for step in template.steps:
        messages.append({"role": "user", "content": step.prompt})
        response_text, response_time_ms = await adapter.send_messages(messages, model=model)
        messages.append({"role": "assistant", "content": response_text})
        evidence.append(
            EvidenceItem(
                step_index=step.index,
                prompt=step.prompt,
                response=response_text,
                response_time_ms=response_time_ms,
            )
        )
        # Rate-limit between steps
        if step != template.steps[-1]:
            await asyncio.sleep(delay)

    verdict, reasoning = detect(template, evidence)

    leakage_signals = []
    if observer is not None:
        leakage_signals = observer.observe(evidence)

    return Finding(
        template_id=template.id,
        template_name=template.name,
        verdict=verdict,
        severity=template.severity,
        category=template.category,
        owasp=template.owasp,
        evidence=evidence,
        reasoning=reasoning,
        leakage_signals=leakage_signals,
    )
