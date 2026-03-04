"""Health monitor — periodic target health checks."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from pentis.adapters.factory import make_adapter
from pentis.core.models import TargetHealthStatus
from pentis.state.store import Store
from pentis_service.services.event_bus import EventBus

logger = logging.getLogger(__name__)

UNHEALTHY_THRESHOLD = 3


class HealthMonitor:
    """Periodically checks target health and emits alerts on failures."""

    def __init__(
        self,
        store: Store,
        event_bus: EventBus,
        check_interval: float = 300.0,  # 5 minutes
    ) -> None:
        self._store = store
        self._event_bus = event_bus
        self._check_interval = check_interval
        self._task: asyncio.Task[None] | None = None
        self._running = False

    async def start(self) -> None:
        """Start the health monitoring loop."""
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())
        logger.info("Health monitor started (interval=%0.fs)", self._check_interval)

    async def stop(self) -> None:
        """Stop the health monitoring loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Health monitor stopped")

    async def check_target(self, target_url: str, api_key: str = "", adapter_type: str = "openai") -> TargetHealthStatus:
        """Check a single target's health."""
        adapter = make_adapter(url=target_url, api_key=api_key, adapter_type=adapter_type)
        existing = self._store.get_target_health(target_url)
        status = existing or TargetHealthStatus(target_url=target_url)

        try:
            import time

            start = time.monotonic()
            healthy = await adapter.health_check()
            elapsed_ms = int((time.monotonic() - start) * 1000)

            if healthy:
                status.healthy = True
                status.consecutive_failures = 0
                status.last_response_time_ms = elapsed_ms
                status.last_error = ""
            else:
                status.consecutive_failures += 1
                status.last_error = "health_check returned False"
                status.healthy = status.consecutive_failures < UNHEALTHY_THRESHOLD
        except Exception as exc:
            status.consecutive_failures += 1
            status.last_error = str(exc)
            status.healthy = status.consecutive_failures < UNHEALTHY_THRESHOLD
        finally:
            await adapter.close()

        status.last_check_at = datetime.now(timezone.utc)
        self._store.save_target_health(status)

        if not status.healthy:
            await self._event_bus.publish(
                "target_unhealthy",
                {
                    "target_url": target_url,
                    "consecutive_failures": status.consecutive_failures,
                    "last_error": status.last_error,
                },
            )

        return status

    async def _monitor_loop(self) -> None:
        """Background loop that checks all scheduled targets."""
        while self._running:
            try:
                schedules = self._store.list_schedules()
                for sched in schedules:
                    if not sched.get("enabled"):
                        continue
                    await self.check_target(
                        sched["target_url"],
                        sched.get("api_key", ""),
                        sched.get("adapter_type", "openai"),
                    )
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Health monitor cycle failed")

            await asyncio.sleep(self._check_interval)
