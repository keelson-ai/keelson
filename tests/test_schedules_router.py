"""Tests for the schedules API router."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pentis.state.store import Store
from pentis_service import deps
from pentis_service.routers.schedules import router
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


def test_create_schedule(client: TestClient, setup_deps) -> None:
    resp = client.post(
        "/schedules",
        json={
            "target_url": "http://example.com/v1/chat/completions",
            "api_key": "sk-test",
            "interval_seconds": 7200,
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["target_url"] == "http://example.com/v1/chat/completions"
    assert data["interval_seconds"] == 7200
    assert data["enabled"] is True


def test_list_schedules(client: TestClient, setup_deps) -> None:
    client.post(
        "/schedules",
        json={"target_url": "http://example.com/api", "interval_seconds": 3600},
    )
    resp = client.get("/schedules")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 1


def test_delete_schedule(client: TestClient, setup_deps) -> None:
    resp = client.post(
        "/schedules",
        json={"target_url": "http://example.com/api", "interval_seconds": 3600},
    )
    schedule_id = resp.json()["schedule_id"]
    del_resp = client.delete(f"/schedules/{schedule_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "deleted"


def test_delete_nonexistent_schedule(client: TestClient, setup_deps) -> None:
    resp = client.delete("/schedules/nonexistent")
    assert resp.status_code == 404


def test_create_schedule_minimum_interval(client: TestClient, setup_deps) -> None:
    """Interval must be at least 300 seconds."""
    resp = client.post(
        "/schedules",
        json={"target_url": "http://example.com/api", "interval_seconds": 100},
    )
    assert resp.status_code == 422
