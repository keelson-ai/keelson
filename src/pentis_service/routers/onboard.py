"""Onboard router — guided target setup with health check and fingerprinting."""

from __future__ import annotations

import logging

from fastapi import APIRouter

from pentis.adapters.factory import make_adapter
from pentis.attacker.chains import synthesize_chains
from pentis.attacker.discovery import discover_capabilities
from pentis.core.models import ScheduleConfig
from pentis.core.templates import load_all_templates
from pentis_service import deps
from pentis_service.schemas import (
    AttackPlanResponse,
    CapabilityResponse,
    OnboardRequest,
    OnboardResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/onboard", tags=["onboard"])


@router.post("")
async def onboard(req: OnboardRequest) -> OnboardResponse:
    """Onboard a new target: health check, fingerprint, and optionally schedule."""
    adapter = make_adapter(
        url=req.target_url,
        api_key=req.api_key,
        adapter_type=req.adapter_type,
    )

    # Health check
    import time

    start = time.monotonic()
    try:
        healthy = await adapter.health_check()
        response_time_ms = int((time.monotonic() - start) * 1000)
    except Exception as exc:
        await adapter.close()
        return OnboardResponse(
            healthy=False,
            response_time_ms=int((time.monotonic() - start) * 1000),
        )

    if not healthy:
        await adapter.close()
        return OnboardResponse(healthy=False, response_time_ms=response_time_ms)

    # Fingerprint capabilities
    profile = await discover_capabilities(
        adapter, target_url=req.target_url, delay=1.0
    )
    store = deps.get_store()
    store.save_agent_profile(profile)

    capabilities = [
        CapabilityResponse(
            name=c.name,
            detected=c.detected,
            confidence=c.confidence,
        )
        for c in profile.capabilities
    ]

    # Attack plan summary
    all_templates = load_all_templates()
    chains = synthesize_chains(profile)
    attack_plan = AttackPlanResponse(
        playbook_attacks=len(all_templates),
        capability_attacks=len(profile.detected_capabilities) * 2,
        chain_attacks=len(chains),
    )

    # Create schedule if continuous mode
    schedule_id: str | None = None
    if req.run_mode == "continuous":
        scheduler = deps.get_scheduler()
        schedule = ScheduleConfig(
            target_url=req.target_url,
            api_key=req.api_key,
            adapter_type=req.adapter_type,
            interval_seconds=req.interval_seconds,
            attacker_api_key=req.attacker_api_key,
            attacker_model=req.attacker_model,
        )
        scheduler.add_schedule(schedule)
        schedule_id = schedule.schedule_id

        # Trigger first cycle immediately
        await scheduler.trigger_now(schedule.schedule_id)

    await adapter.close()

    return OnboardResponse(
        healthy=True,
        response_time_ms=response_time_ms,
        capabilities=capabilities,
        attack_plan=attack_plan,
        schedule_id=schedule_id,
    )
