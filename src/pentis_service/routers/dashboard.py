"""Dashboard router — aggregate stats and overview."""

from __future__ import annotations

import logging
from collections import Counter

from fastapi import APIRouter

from pentis_service import deps
from pentis_service.schemas import (
    DashboardResponse,
    LearningSummaryResponse,
    ScanJobResponse,
    TargetHealthResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("")
async def dashboard() -> DashboardResponse:
    """Aggregate dashboard stats."""
    store = deps.get_store()

    # Scan stats
    scans = store.list_scans(limit=1000)
    total_scans = len(scans)
    total_vulns = sum(int(s.get("vulnerable", 0)) for s in scans)

    # Schedule stats
    schedules = store.list_schedules()
    active_schedules = sum(1 for s in schedules if s.get("enabled"))

    # Target health
    health_statuses = store.list_target_health()
    targets_monitored = len(health_statuses)
    health_responses = [
        TargetHealthResponse(
            target_url=h.target_url,
            healthy=h.healthy,
            consecutive_failures=h.consecutive_failures,
            last_check_at=h.last_check_at.isoformat() if h.last_check_at else None,
            last_response_time_ms=h.last_response_time_ms,
        )
        for h in health_statuses
    ]

    # Recent scan jobs
    recent_jobs = store.list_scan_jobs(limit=10)
    recent_scan_responses = [
        ScanJobResponse(
            scan_id=str(j["scan_id"]),
            schedule_id=str(j["schedule_id"]) if j.get("schedule_id") else None,
            target_url=str(j["target_url"]),
            status=str(j["status"]),
            progress=int(j.get("progress", 0)),
            total_attacks=int(j.get("total_attacks", 0)),
            vulnerable_count=int(j.get("vulnerable_count", 0)),
            error_message=str(j.get("error_message", "")),
            created_at=str(j["created_at"]),
            started_at=str(j["started_at"]) if j.get("started_at") else None,
            finished_at=str(j["finished_at"]) if j.get("finished_at") else None,
        )
        for j in recent_jobs
    ]

    # Learning summary
    records = store.list_learning_records(limit=100)
    learning_summary = None
    if records:
        all_defense_patterns: Counter[str] = Counter()
        all_mutations: Counter[str] = Counter()
        for r in records:
            for p in r.defense_patterns:
                all_defense_patterns[p] += 1
            for m in r.successful_mutations:
                all_mutations[m] += 1

        learning_summary = LearningSummaryResponse(
            total_cycles=len(records),
            total_attacks_run=sum(r.attacks_run for r in records),
            total_vulns_found=sum(r.vulns_found for r in records),
            top_defense_patterns=[p for p, _ in all_defense_patterns.most_common(5)],
            top_successful_mutations=[m for m, _ in all_mutations.most_common(5)],
        )

    return DashboardResponse(
        total_scans=total_scans,
        total_vulnerabilities=total_vulns,
        active_schedules=active_schedules,
        targets_monitored=targets_monitored,
        target_health=health_responses,
        recent_scans=recent_scan_responses,
        learning_summary=learning_summary,
    )
