"""Smart scan — discover, classify, select, execute adaptively in conversational sessions."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from pentis.adapters.base import BaseAdapter
from pentis.attacker.discovery import CAPABILITY_PROBES, score_capability
from pentis.core.engine import execute_attack
from pentis.core.memo import MemoTable, infer_techniques_from_template, score_attack_by_memo
from pentis.core.models import (
    AgentCapability,
    AgentProfile,
    AttackTemplate,
    Category,
    Finding,
    ScanResult,
    Target,
)
from pentis.core.strategist import (
    ReconResponse,
    adapt_plan,
    classify_target,
    select_attacks,
)
from pentis.core.templates import load_all_templates

logger = logging.getLogger(__name__)

# Maximum attacks per conversational session before resetting thread
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
    attack_ids: list[str],
    templates_by_id: dict[str, AttackTemplate],
    memo: MemoTable | None = None,
) -> list[list[AttackTemplate]]:
    """Group attacks into conversational sessions.

    Groups attacks by category, with up to _SESSION_MAX_TURNS per session.
    This creates natural conversation flow where related attacks build on each other.

    When a memo table is provided, attacks within each category are reordered
    so that attacks using historically effective techniques run first,
    and attacks using dead-end techniques are pushed to the back.
    """
    # Group by category
    by_category: dict[Category, list[AttackTemplate]] = {}
    for aid in attack_ids:
        t = templates_by_id.get(aid)
        if t:
            by_category.setdefault(t.category, []).append(t)

    sessions: list[list[AttackTemplate]] = []
    for category, templates in by_category.items():
        # Reorder by memo insights if available
        if memo and memo.entries:
            templates = _reorder_by_memo(templates, memo, category)

        # Split into chunks of _SESSION_MAX_TURNS
        for i in range(0, len(templates), _SESSION_MAX_TURNS):
            sessions.append(templates[i : i + _SESSION_MAX_TURNS])

    return sessions


def _reorder_by_memo(
    templates: list[AttackTemplate],
    memo: MemoTable,
    category: Category,
) -> list[AttackTemplate]:
    """Reorder templates so effective techniques come first, dead ends last."""

    def _score(t: AttackTemplate) -> float:
        techniques = infer_techniques_from_template(t)
        return score_attack_by_memo(techniques, memo, category)

    return sorted(templates, key=_score, reverse=True)


async def _execute_session(
    session: list[AttackTemplate],
    adapter: BaseAdapter,
    model: str,
    delay: float,
    on_finding: Callable[[Finding, int, int], None] | None,
    current_offset: int,
    total: int,
    memo: MemoTable | None = None,
) -> list[Finding]:
    """Execute a group of attacks within a single conversational session.

    Uses a shared message history within the session so social manipulation
    builds naturally. Resets the thread/session at the start.

    When a memo table is provided, each finding is recorded into it so
    subsequent sessions within the same scan benefit from accumulated knowledge.
    """
    # Reset to a fresh session
    if hasattr(adapter, "reset_thread"):
        adapter.reset_thread()  # type: ignore[union-attr]

    findings: list[Finding] = []

    for i, template in enumerate(session):
        finding = await execute_attack(template, adapter, model=model, delay=delay)
        findings.append(finding)

        # Record into memo table immediately so later sessions benefit
        if memo is not None:
            memo.record(finding)

        if on_finding:
            on_finding(finding, current_offset + i + 1, total)
        if i < len(session) - 1:
            await asyncio.sleep(delay)

    return findings


async def run_smart_scan(
    target: Target,
    adapter: BaseAdapter,
    attacks_dir: Path | None = None,
    delay: float = 2.0,
    on_finding: Callable[[Finding, int, int], None] | None = None,
    on_phase: Callable[[str, str], None] | None = None,
) -> ScanResult:
    """Run an adaptive smart scan: discover → classify → select → execute.

    Unlike run_scan which blindly runs all attacks, smart_scan:
    1. Discovers target capabilities (8 probes)
    2. Classifies target type (codebase agent, RAG, customer service, etc.)
    3. Selects only relevant attacks based on profile
    4. Groups attacks into conversational sessions for natural social manipulation
    5. Adapts the plan based on findings (escalate/de-escalate)

    Args:
        target: The target to scan.
        adapter: Adapter for communicating with the target.
        attacks_dir: Override directory for attack playbooks.
        delay: Seconds to wait between requests.
        on_finding: Optional callback(finding, current_index, total) for progress.
        on_phase: Optional callback(phase_name, detail) for phase transitions.
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
    if hasattr(adapter, "reset_thread"):
        adapter.reset_thread()  # type: ignore[union-attr]

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

    # --- Phase 3: Attack Selection ---
    all_templates = load_all_templates(attacks_dir=attacks_dir)
    plan = select_attacks(target_profile, all_templates)

    if on_phase:
        on_phase(
            "plan",
            f"Selected {plan.total_attacks} attacks (from {len(all_templates)} available)",
        )
        for cp in plan.categories:
            if cp.attack_ids:
                on_phase(
                    "category",
                    f"  {cp.category.value}: {len(cp.attack_ids)} attacks "
                    f"({cp.priority.value}) — {cp.rationale}",
                )

    # Build lookup
    templates_by_id = {t.id: t for t in all_templates}

    # Collect all attack IDs from the plan
    all_attack_ids = [aid for cp in plan.categories for aid in cp.attack_ids]

    if not all_attack_ids:
        if on_phase:
            on_phase("done", "No attacks selected for this target profile")
        result.finished_at = datetime.now(UTC)
        return result

    # --- Phase 4: Grouped Execution with Memoization ---
    memo = MemoTable()
    sessions = _group_into_sessions(all_attack_ids, templates_by_id, memo=memo)

    if on_phase:
        on_phase("execute", f"Running {len(all_attack_ids)} attacks in {len(sessions)} sessions")

    total = len(all_attack_ids)
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
            session, adapter, target.model, delay, on_finding, current_offset, total, memo=memo
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
                    f"  {new_cp.category.value}: {old_cp.priority.value} → "
                    f"{new_cp.priority.value} ({new_cp.rationale})",
                )

        plan = updated_plan

        # Re-group remaining sessions with updated memo knowledge.
        # Find remaining attack IDs (not yet executed).
        executed_ids = {f.template_id for f in all_findings}
        remaining_ids = [aid for aid in all_attack_ids if aid not in executed_ids]
        if remaining_ids:
            remaining_sessions = _group_into_sessions(remaining_ids, templates_by_id, memo=memo)
            # Replace remaining sessions (skip already-processed ones)
            sessions_left = remaining_sessions
            # We'll re-iterate from the next index; break and restart loop
            # Actually, we need to restructure to iterate over a mutable list.
            # Instead, update sessions in place for the next iteration.
            sessions[session_idx + 1 :] = sessions_left

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
    return result
