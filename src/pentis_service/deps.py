"""Dependency injection — singleton holders for shared service instances."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pentis.state.store import Store
    from pentis_service.services.event_bus import EventBus
    from pentis_service.services.executor import ScanExecutor
    from pentis_service.services.health_monitor import HealthMonitor
    from pentis_service.services.red_team_loop import RedTeamLoop
    from pentis_service.services.scheduler import Scheduler

_store: Store | None = None
_event_bus: EventBus | None = None
_executor: ScanExecutor | None = None
_scheduler: Scheduler | None = None
_health_monitor: HealthMonitor | None = None
_red_team_loop: RedTeamLoop | None = None


def get_store() -> Store:
    """Get the singleton Store instance."""
    if _store is None:
        raise RuntimeError("Store not initialized — call set_store() during startup")
    return _store


def set_store(store: Store) -> None:
    global _store
    _store = store


def get_event_bus() -> EventBus:
    """Get the singleton EventBus instance."""
    if _event_bus is None:
        raise RuntimeError("EventBus not initialized — call set_event_bus() during startup")
    return _event_bus


def set_event_bus(bus: EventBus) -> None:
    global _event_bus
    _event_bus = bus


def get_executor() -> ScanExecutor:
    """Get the singleton ScanExecutor instance."""
    if _executor is None:
        raise RuntimeError("ScanExecutor not initialized — call set_executor() during startup")
    return _executor


def set_executor(executor: ScanExecutor) -> None:
    global _executor
    _executor = executor


def get_scheduler() -> Scheduler:
    """Get the singleton Scheduler instance."""
    if _scheduler is None:
        raise RuntimeError("Scheduler not initialized — call set_scheduler() during startup")
    return _scheduler


def set_scheduler(scheduler: Scheduler) -> None:
    global _scheduler
    _scheduler = scheduler


def get_health_monitor() -> HealthMonitor:
    """Get the singleton HealthMonitor instance."""
    if _health_monitor is None:
        raise RuntimeError(
            "HealthMonitor not initialized — call set_health_monitor() during startup"
        )
    return _health_monitor


def set_health_monitor(monitor: HealthMonitor) -> None:
    global _health_monitor
    _health_monitor = monitor


def get_red_team_loop() -> RedTeamLoop:
    """Get the singleton RedTeamLoop instance."""
    if _red_team_loop is None:
        raise RuntimeError(
            "RedTeamLoop not initialized — call set_red_team_loop() during startup"
        )
    return _red_team_loop


def set_red_team_loop(loop: RedTeamLoop) -> None:
    global _red_team_loop
    _red_team_loop = loop
