"""Scan router — submit, list, cancel, and stream scans."""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from pentis.core.models import ScanJob
from pentis_service import deps
from pentis_service.schemas import (
    EvidenceResponse,
    FindingResponse,
    ScanJobResponse,
    ScanRequest,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scans", tags=["scans"])


def _job_to_response(job_dict: dict[str, object]) -> ScanJobResponse:
    return ScanJobResponse(
        scan_id=str(job_dict["scan_id"]),
        schedule_id=str(job_dict["schedule_id"]) if job_dict.get("schedule_id") else None,
        target_url=str(job_dict["target_url"]),
        status=str(job_dict["status"]),
        progress=int(job_dict.get("progress", 0)),  # type: ignore[arg-type]
        total_attacks=int(job_dict.get("total_attacks", 0)),  # type: ignore[arg-type]
        vulnerable_count=int(job_dict.get("vulnerable_count", 0)),  # type: ignore[arg-type]
        error_message=str(job_dict.get("error_message", "")),
        created_at=str(job_dict["created_at"]),
        started_at=str(job_dict["started_at"]) if job_dict.get("started_at") else None,
        finished_at=str(job_dict["finished_at"]) if job_dict.get("finished_at") else None,
    )


@router.post("", status_code=202)
async def submit_scan(req: ScanRequest) -> ScanJobResponse:
    """Submit an ad-hoc scan for background execution."""
    executor = deps.get_executor()
    store = deps.get_store()
    job = ScanJob(target_url=req.target_url)
    await executor.submit_scan(
        job=job,
        api_key=req.api_key,
        model=req.model,
        adapter_type=req.adapter_type,
        category=req.category,
        tier=req.tier,
        delay=req.delay,
    )
    saved = store.get_scan_job(job.scan_id)
    if not saved:
        raise HTTPException(status_code=500, detail="Failed to create scan job")
    return _job_to_response(dict(
        scan_id=saved.scan_id,
        schedule_id=saved.schedule_id,
        target_url=saved.target_url,
        status=saved.status.value,
        progress=saved.progress,
        total_attacks=saved.total_attacks,
        vulnerable_count=saved.vulnerable_count,
        error_message=saved.error_message,
        created_at=saved.created_at.isoformat(),
        started_at=saved.started_at.isoformat() if saved.started_at else None,
        finished_at=saved.finished_at.isoformat() if saved.finished_at else None,
    ))


@router.get("")
async def list_scans(status: str | None = None, limit: int = 50) -> list[ScanJobResponse]:
    """List scan jobs with optional status filter."""
    store = deps.get_store()
    jobs = store.list_scan_jobs(status=status, limit=limit)
    return [_job_to_response(j) for j in jobs]


@router.get("/{scan_id}")
async def get_scan(scan_id: str) -> ScanJobResponse:
    """Get scan job detail."""
    store = deps.get_store()
    job = store.get_scan_job(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _job_to_response(dict(
        scan_id=job.scan_id,
        schedule_id=job.schedule_id,
        target_url=job.target_url,
        status=job.status.value,
        progress=job.progress,
        total_attacks=job.total_attacks,
        vulnerable_count=job.vulnerable_count,
        error_message=job.error_message,
        created_at=job.created_at.isoformat(),
        started_at=job.started_at.isoformat() if job.started_at else None,
        finished_at=job.finished_at.isoformat() if job.finished_at else None,
    ))


@router.delete("/{scan_id}")
async def cancel_scan(scan_id: str) -> dict[str, str]:
    """Cancel a running scan."""
    executor = deps.get_executor()
    cancelled = await executor.cancel_scan(scan_id)
    if not cancelled:
        raise HTTPException(status_code=404, detail="Scan not found or already completed")
    return {"status": "cancelled", "scan_id": scan_id}


@router.get("/{scan_id}/events")
async def scan_events(scan_id: str) -> StreamingResponse:
    """SSE stream of events for a specific scan."""
    event_bus = deps.get_event_bus()
    sub_id, queue = event_bus.subscribe()

    async def event_generator():  # type: ignore[no-untyped-def]
        try:
            while True:
                event = await asyncio.wait_for(queue.get(), timeout=300.0)
                event_data = event.get("data", {})
                if event_data.get("scan_id") != scan_id:
                    continue
                import json

                yield f"event: {event['event_type']}\ndata: {json.dumps(event)}\n\n"
                if event["event_type"] in ("scan_completed", "scan_failed", "scan_cancelled"):
                    break
        except asyncio.TimeoutError:
            yield "event: timeout\ndata: {}\n\n"
        finally:
            event_bus.unsubscribe(sub_id)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/{scan_id}/findings")
async def scan_findings(scan_id: str) -> list[FindingResponse]:
    """Get findings for a completed scan."""
    store = deps.get_store()
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return [
        FindingResponse(
            template_id=f.template_id,
            template_name=f.template_name,
            verdict=f.verdict.value,
            severity=f.severity.value,
            category=f.category.value,
            owasp=f.owasp,
            reasoning=f.reasoning,
            evidence=[
                EvidenceResponse(
                    step_index=e.step_index,
                    prompt=e.prompt,
                    response=e.response,
                    response_time_ms=e.response_time_ms,
                )
                for e in f.evidence
            ],
        )
        for f in scan.findings
    ]
