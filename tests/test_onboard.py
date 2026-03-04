"""Tests for the onboard API router."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pentis.state.store import Store
from pentis_service import deps
from pentis_service.routers.onboard import router
from pentis_service.services.event_bus import EventBus
from pentis_service.services.scheduler import Scheduler


@pytest.fixture
def setup_deps(tmp_path: Path):
    store = Store(db_path=tmp_path / "test.db", check_same_thread=False)
    bus = EventBus()
    scheduler = Scheduler(store, bus)
    deps.set_store(store)
    deps.set_event_bus(bus)
    deps.set_scheduler(scheduler)
    return store, bus, scheduler


@pytest.fixture
def client(setup_deps) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_onboard_unhealthy_target(client: TestClient, setup_deps) -> None:
    with patch("pentis_service.routers.onboard.make_adapter") as mock_make:
        mock = AsyncMock()
        mock.health_check.side_effect = ConnectionError("refused")
        mock.close = AsyncMock()
        mock_make.return_value = mock

        resp = client.post(
            "/onboard",
            json={
                "target_url": "http://unreachable.example.com/api",
                "run_mode": "once",
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["healthy"] is False


def test_onboard_healthy_target(client: TestClient, setup_deps) -> None:
    with (
        patch("pentis_service.routers.onboard.make_adapter") as mock_make,
        patch("pentis_service.routers.onboard.discover_capabilities") as mock_discover,
    ):
        mock = AsyncMock()
        mock.health_check.return_value = True
        mock.close = AsyncMock()
        mock_make.return_value = mock

        from pentis.core.models import AgentCapability, AgentProfile

        mock_discover.return_value = AgentProfile(
            target_url="http://example.com/api",
            capabilities=[
                AgentCapability(
                    name="web_access",
                    detected=True,
                    probe_prompt="test",
                    confidence=0.85,
                ),
                AgentCapability(
                    name="tool_usage",
                    detected=True,
                    probe_prompt="test",
                    confidence=0.9,
                ),
                AgentCapability(
                    name="file_access",
                    detected=False,
                    probe_prompt="test",
                    confidence=0.1,
                ),
            ],
        )

        resp = client.post(
            "/onboard",
            json={
                "target_url": "http://example.com/api",
                "api_key": "sk-test",
                "run_mode": "once",
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["healthy"] is True
    assert len(data["capabilities"]) == 3
    detected = [c for c in data["capabilities"] if c["detected"]]
    assert len(detected) == 2
    assert data["attack_plan"]["playbook_attacks"] > 0


def test_onboard_continuous_creates_schedule(client: TestClient, setup_deps) -> None:
    store = setup_deps[0]
    scheduler = setup_deps[2]

    # Mock the trigger to avoid actual scan
    scheduler.set_trigger_callback(AsyncMock())

    with (
        patch("pentis_service.routers.onboard.make_adapter") as mock_make,
        patch("pentis_service.routers.onboard.discover_capabilities") as mock_discover,
    ):
        mock = AsyncMock()
        mock.health_check.return_value = True
        mock.close = AsyncMock()
        mock_make.return_value = mock

        from pentis.core.models import AgentProfile

        mock_discover.return_value = AgentProfile(
            target_url="http://example.com/api",
            capabilities=[],
        )

        resp = client.post(
            "/onboard",
            json={
                "target_url": "http://example.com/api",
                "run_mode": "continuous",
                "interval_seconds": 3600,
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["schedule_id"] is not None

    # Verify schedule was persisted
    schedules = store.list_schedules()
    assert len(schedules) == 1
