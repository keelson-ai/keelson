"""Tests for the scheduler service."""

from __future__ import annotations

from pathlib import Path

import pytest

from pentis.core.models import ScheduleConfig
from pentis.state.store import Store
from pentis_service.services.event_bus import EventBus
from pentis_service.services.scheduler import Scheduler


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(db_path=tmp_path / "test.db")


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


@pytest.fixture
def scheduler(store: Store, bus: EventBus) -> Scheduler:
    return Scheduler(store, bus)


async def test_add_schedule_persists(scheduler: Scheduler, store: Store) -> None:
    schedule = ScheduleConfig(
        target_url="http://example.com/v1/chat/completions",
        api_key="sk-test",
        interval_seconds=3600,
    )
    scheduler.add_schedule(schedule)
    saved = store.get_schedule(schedule.schedule_id)
    assert saved is not None
    assert saved.target_url == "http://example.com/v1/chat/completions"
    assert saved.interval_seconds == 3600
    # Clean up the background task
    await scheduler.stop()


async def test_remove_schedule(scheduler: Scheduler, store: Store) -> None:
    schedule = ScheduleConfig(target_url="http://example.com/api")
    scheduler.add_schedule(schedule)
    assert scheduler.remove_schedule(schedule.schedule_id)
    assert store.get_schedule(schedule.schedule_id) is None
    await scheduler.stop()


def test_remove_nonexistent_schedule(scheduler: Scheduler) -> None:
    assert not scheduler.remove_schedule("nonexistent")


async def test_trigger_nonexistent(scheduler: Scheduler) -> None:
    result = await scheduler.trigger_now("nonexistent")
    assert result is None


def test_add_disabled_schedule_does_not_start_task(
    scheduler: Scheduler, store: Store
) -> None:
    schedule = ScheduleConfig(
        target_url="http://example.com/api",
        enabled=False,
    )
    scheduler.add_schedule(schedule)
    assert schedule.schedule_id not in scheduler._tasks


async def test_start_loads_schedules(scheduler: Scheduler, store: Store) -> None:
    schedule = ScheduleConfig(
        target_url="http://example.com/api",
        interval_seconds=999999,  # Long interval to prevent actual execution
    )
    store.save_schedule(schedule)
    await scheduler.start()
    assert schedule.schedule_id in scheduler._tasks
    await scheduler.stop()
