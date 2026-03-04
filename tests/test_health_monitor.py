"""Tests for the health monitor service."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from pentis.state.store import Store
from pentis_service.services.event_bus import EventBus
from pentis_service.services.health_monitor import HealthMonitor


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(db_path=tmp_path / "test.db")


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


@pytest.fixture
def monitor(store: Store, bus: EventBus) -> HealthMonitor:
    return HealthMonitor(store, bus, check_interval=1.0)


async def test_check_healthy_target(monitor: HealthMonitor) -> None:
    with patch("pentis_service.services.health_monitor.make_adapter") as mock_adapter:
        mock = AsyncMock()
        mock.health_check.return_value = True
        mock.close = AsyncMock()
        mock_adapter.return_value = mock

        status = await monitor.check_target("http://example.com/api")

    assert status.healthy is True
    assert status.consecutive_failures == 0
    assert status.target_url == "http://example.com/api"


async def test_check_unhealthy_target(monitor: HealthMonitor, bus: EventBus) -> None:
    sub_id, queue = bus.subscribe()

    with patch("pentis_service.services.health_monitor.make_adapter") as mock_adapter:
        mock = AsyncMock()
        mock.health_check.side_effect = ConnectionError("refused")
        mock.close = AsyncMock()
        mock_adapter.return_value = mock

        # First 3 failures should trigger unhealthy event
        for _ in range(3):
            status = await monitor.check_target("http://down.example.com/api")

    assert status.healthy is False
    assert status.consecutive_failures == 3
    # Should have emitted target_unhealthy event
    events = []
    while not queue.empty():
        events.append(queue.get_nowait())
    unhealthy_events = [e for e in events if e["event_type"] == "target_unhealthy"]
    assert len(unhealthy_events) >= 1

    bus.unsubscribe(sub_id)


async def test_check_target_recovers(monitor: HealthMonitor) -> None:
    with patch("pentis_service.services.health_monitor.make_adapter") as mock_adapter:
        mock = AsyncMock()
        mock.close = AsyncMock()

        # Fail twice
        mock.health_check.side_effect = ConnectionError("refused")
        mock_adapter.return_value = mock
        await monitor.check_target("http://example.com/api")
        await monitor.check_target("http://example.com/api")

        # Then recover
        mock.health_check.side_effect = None
        mock.health_check.return_value = True
        status = await monitor.check_target("http://example.com/api")

    assert status.healthy is True
    assert status.consecutive_failures == 0


async def test_start_and_stop(monitor: HealthMonitor) -> None:
    await monitor.start()
    assert monitor._task is not None
    await monitor.stop()
    assert monitor._running is False
