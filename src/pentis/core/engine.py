"""Attack execution engine — loads template, sends steps, produces findings."""

from __future__ import annotations

import asyncio

from pentis.adapters.base import BaseAdapter
from pentis.core.detection import REFUSAL_PHRASES, detect
from pentis.core.models import AttackTemplate, EvidenceItem, Finding
from pentis.core.observer import StreamingObserver

# Minimum refusal phrase matches to trigger early termination.
_EARLY_TERM_REFUSAL_THRESHOLD = 3

# Responses shorter than this with enough refusal phrases trigger early termination.
# Longer responses may contain partial information worth probing further.
_EARLY_TERM_MAX_RESPONSE_LEN = 200


def _is_hard_refusal(response: str) -> bool:
    """Check if a response is a terse, unambiguous refusal.

    Both conditions must hold:
    - Multiple refusal phrases present (>= threshold)
    - Response is short (< max length), indicating a terse rejection
      with no useful content to build on

    This avoids terminating multi-turn attacks where step 1 is a polite
    refusal that erosion attacks are designed to overcome.
    """
    if len(response) > _EARLY_TERM_MAX_RESPONSE_LEN:
        return False
    lower = response.lower()
    matches = sum(1 for p in REFUSAL_PHRASES if p in lower)
    return matches >= _EARLY_TERM_REFUSAL_THRESHOLD


async def execute_attack(
    template: AttackTemplate,
    adapter: BaseAdapter,
    model: str = "default",
    delay: float = 1.0,
    observer: StreamingObserver | None = None,
    max_response_tokens: int | None = None,
) -> Finding:
    """Execute an attack template against a target via the adapter.

    Sends each step, accumulates messages for multi-turn, runs detection.
    Optionally runs a StreamingObserver for per-step leakage analysis.

    Steps with role "assistant" are injected into the conversation history
    without sending to the adapter, enabling conversation history poisoning
    attacks (e.g., SI-014).

    Early termination: for multi-turn attacks, if the first user turn gets a
    hard refusal (2+ refusal phrases), remaining turns are skipped to save tokens.
    """
    messages: list[dict[str, str]] = []
    evidence: list[EvidenceItem] = []
    user_turn_count = 0

    for step_idx, step in enumerate(template.steps):
        if step.new_session:
            messages = []

        if step.role != "user":
            # Inject non-user turns (e.g., fabricated assistant context) into
            # the conversation history without sending to the adapter.
            messages.append({"role": step.role, "content": step.prompt})
            continue

        messages.append({"role": "user", "content": step.prompt})
        response_text, response_time_ms = await adapter.send_messages(
            messages, model=model, max_response_tokens=max_response_tokens
        )
        messages.append({"role": "assistant", "content": response_text})
        evidence.append(
            EvidenceItem(
                step_index=step.index,
                prompt=step.prompt,
                response=response_text,
                response_time_ms=response_time_ms,
            )
        )
        user_turn_count += 1

        # Early termination: if the first user turn gets a hard refusal in a
        # multi-turn attack with 3+ remaining user turns, skip them to save tokens.
        # Attacks with only 1-2 remaining turns are cheap enough to run fully,
        # and multi-turn erosion attacks often overcome initial refusals.
        remaining_user_steps = sum(1 for s in template.steps[step_idx + 1 :] if s.role == "user")
        if user_turn_count == 1 and remaining_user_steps >= 2 and _is_hard_refusal(response_text):
            break

        # Rate-limit between steps
        if step != template.steps[-1]:
            await asyncio.sleep(delay)

    # Always run observer for leakage detection; use caller's if provided
    effective_observer = observer if observer is not None else StreamingObserver()
    leakage_signals = effective_observer.observe(evidence)

    verdict, reasoning = detect(template, evidence, leakage_signals=leakage_signals)

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
