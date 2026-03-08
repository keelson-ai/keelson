"""Smart scan — discover, classify, select, execute adaptively in conversational sessions."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from keelson.adapters.base import BaseAdapter
from keelson.core.execution import apply_verified_findings, execute_sequential, verify_findings
from keelson.core.memo import MemoTable, infer_techniques_from_template, score_probe_by_memo
from keelson.core.models import (
    AgentCapability,
    AgentProfile,
    Category,
    Finding,
    ProbeTemplate,
    ScanResult,
    Target,
    Verdict,
)
from keelson.core.strategist import (
    ReconResponse,
    adapt_plan,
    classify_target,
    select_probes,
)
from keelson.core.templates import load_all_templates
from keelson.core.yaml_templates import update_effectiveness_scores
from keelson.prober.discovery import CAPABILITY_PROBES, score_capability

logger = logging.getLogger(__name__)

# Maximum probes per conversational session before resetting thread
_SESSION_MAX_TURNS = 6


async def _run_discovery(
    adapter: BaseAdapter,
    model: str,
    delay: float,
) -> tuple[AgentProfile, list[ReconResponse]]:
    """Phase 1: Discover target capabilities and collect recon responses."""
    capabilities: list[AgentCapability] = []
    recon_responses: list[ReconResponse] = []

    for i, probe in enumerate(CAPABILITY_PROBES):
        messages = [{"role": "user", "content": probe["prompt"]}]
        response_text, _ = await adapter.send_messages(messages, model=model)

        detected, confidence = score_capability(response_text, probe)
        capabilities.append(
            AgentCapability(
                name=probe["name"],
                detected=detected,
                probe_prompt=probe["prompt"],
                response_excerpt=response_text[:300],
                confidence=confidence,
            )
        )
        recon_responses.append(
            ReconResponse(
                probe_type=probe["name"],
                prompt=probe["prompt"],
                response=response_text,
            )
        )

        if i < len(CAPABILITY_PROBES) - 1:
            await asyncio.sleep(delay)

    profile = AgentProfile(target_url="", capabilities=capabilities)
    return profile, recon_responses


def _group_into_sessions(
    probe_ids: list[str],
    templates_by_id: dict[str, ProbeTemplate],
    memo: MemoTable | None = None,
) -> list[list[ProbeTemplate]]:
    """Group probes into conversational sessions.

    Groups probes by category, with up to _SESSION_MAX_TURNS per session.
    This creates natural conversation flow where related probes build on each other.

    When a memo table is provided, probes within each category are reordered
    so that probes using historically effective techniques run first,
    and probes using dead-end techniques are pushed to the back.
    """
    # Group by category
    by_category: dict[Category, list[ProbeTemplate]] = {}
    for aid in probe_ids:
        t = templates_by_id.get(aid)
        if t:
            by_category.setdefault(t.category, []).append(t)

    sessions: list[list[ProbeTemplate]] = []
    for category, templates in by_category.items():
        if memo and memo.entries:
            templates = _reorder_by_memo(templates, memo, category)
        else:
            # No memo yet — sort by success rate (higher = first)
            templates = sorted(templates, key=_effectiveness_score, reverse=True)

        # Split into chunks of _SESSION_MAX_TURNS
        for i in range(0, len(templates), _SESSION_MAX_TURNS):
            sessions.append(templates[i : i + _SESSION_MAX_TURNS])

    return sessions


def _effectiveness_score(t: ProbeTemplate) -> float:
    """Score a probe by its field-tested success rate, weighted by confidence.

    Untested probes (times_tested=0) score 0.0 (neutral).
    Tested probes scale from -1.0 (proven failure) to +1.0 (always works):
      - 0% rate after 10+ tests → -1.0 (strong deprioritization)
      - 0% rate after 1 test → -0.1 (mild penalty, could still work)
      - 50% rate after 10 tests → +0.5
    """
    if t.times_tested == 0:
        return 0.0
    confidence = min(t.times_tested / 10.0, 1.0)
    if t.success_rate == 0.0:
        return -1.0 * confidence
    return t.success_rate * confidence


def _reorder_by_memo(
    templates: list[ProbeTemplate],
    memo: MemoTable,
    category: Category,
) -> list[ProbeTemplate]:
    """Reorder templates so effective techniques come first, dead ends last.

    Combines field-tested success rates with memo-informed scoring.
    """

    def _score(t: ProbeTemplate) -> float:
        techniques = infer_techniques_from_template(t)
        memo_score = score_probe_by_memo(techniques, memo, category)
        return memo_score + _effectiveness_score(t)

    return sorted(templates, key=_score, reverse=True)


async def _execute_session(
    session: list[ProbeTemplate],
    adapter: BaseAdapter,
    model: str,
    delay: float,
    on_finding: Callable[[Finding, int, int], None] | None,
    current_offset: int,
    total: int,
    memo: MemoTable | None = None,
    max_response_tokens: int | None = 512,
) -> list[Finding]:
    """Execute a group of probes within a single conversational session.

    Uses a shared message history within the session so social manipulation
    builds naturally. Resets the session at the start.

    When a memo table is provided, each finding is recorded into it so
    subsequent sessions within the same scan benefit from accumulated knowledge.
    """
    adapter.reset_session()

    on_each = memo.record if memo is not None else None

    return await execute_sequential(
        templates=session,
        adapter=adapter,
        model=model,
        delay=delay,
        on_finding=on_finding,
        on_each=on_each,
        offset=current_offset,
        total=total,
        max_response_tokens=max_response_tokens,
    )


async def run_smart_scan(
    target: Target,
    adapter: BaseAdapter,
    attacks_dir: Path | None = None,
    delay: float = 2.0,
    on_finding: Callable[[Finding, int, int], None] | None = None,
    on_phase: Callable[[str, str], None] | None = None,
    verify: bool = False,
    max_response_tokens: int | None = 512,
) -> ScanResult:
    """Run an adaptive smart scan: discover -> classify -> select -> execute.

    Unlike run_scan which blindly runs all probes, smart_scan:
    1. Discovers target capabilities (8 probes)
    2. Classifies target type (codebase agent, RAG, customer service, etc.)
    3. Selects only relevant probes based on profile
    4. Groups probes into conversational sessions for natural social manipulation
    5. Adapts the plan based on findings (escalate/de-escalate)
    6. Optionally verifies VULNERABLE findings with confirmation probes

    Args:
        target: The target to scan.
        adapter: Adapter for communicating with the target.
        attacks_dir: Override directory for probe playbooks.
        delay: Seconds to wait between requests.
        on_finding: Optional callback(finding, current_index, total) for progress.
        on_phase: Optional callback(phase_name, detail) for phase transitions.
        verify: When True, re-probe VULNERABLE findings to confirm them.
        max_response_tokens: Limit target response length to save tokens.
    """
    result = ScanResult(target=target)

    # --- Phase 1: Discovery ---
    if on_phase:
        on_phase("discovery", "Fingerprinting target capabilities (8 probes)")

    discovered_profile, recon_responses = await _run_discovery(adapter, target.model, delay)

    detected_caps = [c.name for c in discovered_profile.capabilities if c.detected]
    if on_phase:
        on_phase("discovery", f"Detected capabilities: {', '.join(detected_caps) or 'none'}")

    # Reset thread after discovery
    adapter.reset_session()

    # --- Phase 2: Classification ---
    if on_phase:
        on_phase("classify", "Classifying target agent type")

    target_profile = classify_target(recon_responses)

    if on_phase:
        types_str = ", ".join(t.value for t in target_profile.agent_types)
        tools_str = ", ".join(target_profile.detected_tools[:5]) or "none detected"
        on_phase(
            "profile",
            f"Type: {types_str} | Tools: {tools_str} | "
            f"Memory: {target_profile.has_memory} | Refusal: {target_profile.refusal_style}",
        )

    # --- Phase 3: Probe Selection ---
    all_templates = load_all_templates(attacks_dir=attacks_dir)
    plan = select_probes(target_profile, all_templates)

    if on_phase:
        on_phase(
            "plan",
            f"Selected {plan.total_probes} probes (from {len(all_templates)} available)",
        )
        for cp in plan.categories:
            if cp.probe_ids:
                on_phase(
                    "category",
                    f"  {cp.category.value}: {len(cp.probe_ids)} probes "
                    f"({cp.priority.value}) — {cp.rationale}",
                )

    # Build lookup
    templates_by_id = {t.id: t for t in all_templates}

    # Collect all probe IDs from the plan
    all_probe_ids = [aid for cp in plan.categories for aid in cp.probe_ids]

    if not all_probe_ids:
        if on_phase:
            on_phase("done", "No probes selected for this target profile")
        result.finished_at = datetime.now(UTC)
        return result

    # --- Phase 4: Grouped Execution with Memoization ---
    memo = MemoTable()
    sessions = _group_into_sessions(all_probe_ids, templates_by_id, memo=memo)

    if on_phase:
        on_phase("execute", f"Running {len(all_probe_ids)} probes in {len(sessions)} sessions")

    total = len(all_probe_ids)
    current_offset = 0
    all_findings: list[Finding] = []

    for session_idx, session in enumerate(sessions):
        if on_phase:
            cat = session[0].category.value if session else "unknown"
            on_phase("session", f"Session {session_idx + 1}/{len(sessions)} ({cat})")

        # Log memo insights before each session (after the first)
        if memo.entries and on_phase:
            effective = memo.effective_techniques(session[0].category if session else None)
            dead_ends = memo.dead_end_techniques(session[0].category if session else None)
            leaked = memo.all_leaked_info()
            if effective:
                techs = ", ".join(f"{t.value}({n})" for t, n in list(effective.items())[:3])
                on_phase("memo", f"  Effective techniques: {techs}")
            if dead_ends:
                techs = ", ".join(f"{t.value}({n})" for t, n in list(dead_ends.items())[:3])
                on_phase("memo", f"  Dead-end techniques: {techs}")
            if leaked:
                on_phase("memo", f"  Leaked info: {len(leaked)} items")

        session_findings = await _execute_session(
            session,
            adapter,
            target.model,
            delay,
            on_finding,
            current_offset,
            total,
            memo=memo,
            max_response_tokens=max_response_tokens,
        )
        all_findings.extend(session_findings)
        current_offset += len(session)

        # --- Phase 5: Mid-scan Adaptation ---
        updated_plan = adapt_plan(plan, all_findings)

        # Check if any category was escalated or de-escalated
        for old_cp, new_cp in zip(plan.categories, updated_plan.categories):
            if old_cp.priority != new_cp.priority and on_phase:
                on_phase(
                    "adapt",
                    f"  {new_cp.category.value}: {old_cp.priority.value} -> "
                    f"{new_cp.priority.value} ({new_cp.rationale})",
                )

        plan = updated_plan

        # Re-group remaining sessions with updated memo knowledge.
        # Recompute from adapted plan so de-escalated categories are excluded.
        adapted_probe_ids = [aid for cp in plan.categories for aid in cp.probe_ids]
        executed_ids = {f.template_id for f in all_findings}
        remaining_ids = [aid for aid in adapted_probe_ids if aid not in executed_ids]
        if remaining_ids:
            remaining_sessions = _group_into_sessions(remaining_ids, templates_by_id, memo=memo)
            sessions[session_idx + 1 :] = remaining_sessions

    # --- Phase 6: Verification (optional) ---
    if verify:
        vulnerable = [f for f in all_findings if f.verdict == Verdict.VULNERABLE]
        if vulnerable:
            if on_phase:
                on_phase("verify", f"Re-probing {len(vulnerable)} vulnerable findings")
            verified = await verify_findings(
                vulnerable,
                adapter,
                model=target.model,
                delay=delay,
            )
            all_findings = apply_verified_findings(all_findings, verified)

    # Log final memo summary
    if on_phase and memo.entries:
        summary = memo.summary()
        on_phase(
            "memo_summary",
            f"Memo: {summary['total_conversations']} paths recorded, "
            f"{summary['leaked_info_count']} leaked items",
        )

    result.findings = all_findings
    result.finished_at = datetime.now(UTC)
    update_effectiveness_scores(all_findings, all_templates)
    return result
