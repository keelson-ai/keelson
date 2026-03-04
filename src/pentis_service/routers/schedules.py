"""Schedule router — CRUD for recurring red team schedules."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from pentis.core.models import ScheduleConfig
from pentis_service import deps
from pentis_service.schemas import ScheduleRequest, ScheduleResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/schedules", tags=["schedules"])


@router.post("", status_code=201)
async def create_schedule(req: ScheduleRequest) -> ScheduleResponse:
    """Create a recurring red team schedule."""
    scheduler = deps.get_scheduler()
    schedule = ScheduleConfig(
        target_url=req.target_url,
        api_key=req.api_key,
        adapter_type=req.adapter_type,
        tier=req.tier,
        interval_seconds=req.interval_seconds,
        category=req.category,
        attacker_api_key=req.attacker_api_key,
        attacker_model=req.attacker_model,
    )
    scheduler.add_schedule(schedule)
    return ScheduleResponse(
        schedule_id=schedule.schedule_id,
        target_url=schedule.target_url,
        adapter_type=schedule.adapter_type,
        tier=schedule.tier,
        interval_seconds=schedule.interval_seconds,
        enabled=schedule.enabled,
        category=schedule.category,
        created_at=schedule.created_at.isoformat(),
    )


@router.get("")
async def list_schedules() -> list[ScheduleResponse]:
    """List all schedules."""
    store = deps.get_store()
    schedules = store.list_schedules()
    return [
        ScheduleResponse(
            schedule_id=str(s["schedule_id"]),
            target_url=str(s["target_url"]),
            adapter_type=str(s.get("adapter_type", "openai")),
            tier=str(s.get("tier", "deep")),
            interval_seconds=int(s.get("interval_seconds", 21600)),
            enabled=bool(s.get("enabled", True)),
            category=str(s["category"]) if s.get("category") else None,
            created_at=str(s["created_at"]),
        )
        for s in schedules
    ]


@router.delete("/{schedule_id}")
async def delete_schedule(schedule_id: str) -> dict[str, str]:
    """Remove a schedule."""
    scheduler = deps.get_scheduler()
    deleted = scheduler.remove_schedule(schedule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"status": "deleted", "schedule_id": schedule_id}


@router.post("/{schedule_id}/trigger")
async def trigger_schedule(schedule_id: str) -> dict[str, str | None]:
    """Trigger an immediate cycle for a schedule."""
    scheduler = deps.get_scheduler()
    scan_id = await scheduler.trigger_now(schedule_id)
    if scan_id is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"status": "triggered", "scan_id": scan_id}
