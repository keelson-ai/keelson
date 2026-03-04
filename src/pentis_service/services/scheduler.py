"""Scheduler — manages recurring red team scan schedules."""

from __future__ import annotations

import asyncio
import logging

from pentis.core.models import ScanJob, ScheduleConfig
from pentis.state.store import Store
from pentis_service.services.event_bus import EventBus

logger = logging.getLogger(__name__)


class Scheduler:
    """Manages recurring scan schedules, each running as an asyncio.Task."""

    def __init__(
        self,
        store: Store,
        event_bus: EventBus,
    ) -> None:
        self._store = store
        self._event_bus = event_bus
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._trigger_callback: object | None = None

    def set_trigger_callback(self, callback: object) -> None:
        """Set the callback invoked for each scheduled cycle.

        Should be a callable(ScheduleConfig) -> Coroutine.
        """
        self._trigger_callback = callback

    async def start(self) -> None:
        """Load all enabled schedules and start their loops."""
        schedules = self._store.list_schedules()
        for sched_dict in schedules:
            if not sched_dict.get("enabled"):
                continue
            schedule = self._store.get_schedule(sched_dict["schedule_id"])
            if schedule:
                self._start_schedule(schedule)
        logger.info("Scheduler started with %d active schedules", len(self._tasks))

    async def stop(self) -> None:
        """Stop all schedule loops."""
        for task in self._tasks.values():
            task.cancel()
        for task in self._tasks.values():
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.clear()
        logger.info("Scheduler stopped")

    def add_schedule(self, schedule: ScheduleConfig) -> None:
        """Add and persist a new schedule."""
        self._store.save_schedule(schedule)
        if schedule.enabled:
            self._start_schedule(schedule)

    def remove_schedule(self, schedule_id: str) -> bool:
        """Remove a schedule and stop its loop."""
        task = self._tasks.pop(schedule_id, None)
        if task:
            task.cancel()
        return self._store.delete_schedule(schedule_id)

    async def trigger_now(self, schedule_id: str) -> str | None:
        """Trigger an immediate cycle for a schedule. Returns scan_id or None."""
        schedule = self._store.get_schedule(schedule_id)
        if not schedule:
            return None
        return await self._run_cycle(schedule)

    def _start_schedule(self, schedule: ScheduleConfig) -> None:
        """Start the recurring loop for a schedule."""
        if schedule.schedule_id in self._tasks:
            return
        task = asyncio.create_task(self._schedule_loop(schedule))
        self._tasks[schedule.schedule_id] = task

    async def _schedule_loop(self, schedule: ScheduleConfig) -> None:
        """Recurring loop: trigger cycle, sleep, repeat."""
        while True:
            try:
                await self._run_cycle(schedule)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Schedule cycle failed: %s", schedule.schedule_id)

            await asyncio.sleep(schedule.interval_seconds)

    async def _run_cycle(self, schedule: ScheduleConfig) -> str:
        """Execute one cycle for a schedule."""
        job = ScanJob(
            schedule_id=schedule.schedule_id,
            target_url=schedule.target_url,
        )

        if self._trigger_callback is not None:
            # The red team loop handles execution
            callback = self._trigger_callback
            assert callable(callback)
            await callback(schedule, job)
        else:
            # Fallback: just create the job for the executor to pick up
            from pentis_service import deps

            executor = deps.get_executor()
            await executor.submit_scan(
                job=job,
                api_key=schedule.api_key,
                adapter_type=schedule.adapter_type,
                category=schedule.category,
                tier=schedule.tier,
            )

        await self._event_bus.publish(
            "schedule_triggered",
            {"schedule_id": schedule.schedule_id, "scan_id": job.scan_id},
        )
        return job.scan_id
