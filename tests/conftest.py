from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pentis.state.store import Store
from pentis_service import deps
from pentis_service.main import create_app
from pentis_service.services.event_bus import EventBus
from pentis_service.services.executor import ScanExecutor
from pentis_service.services.health_monitor import HealthMonitor
from pentis_service.services.regression import RegressionService
from pentis_service.services.scheduler import Scheduler


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "test.db"


@pytest.fixture
def store(tmp_db: Path) -> Store:
    return Store(db_path=tmp_db)


@pytest.fixture
def event_bus() -> EventBus:
    return EventBus()


@pytest.fixture
def app() -> FastAPI:
    return create_app()


@pytest.fixture
def test_store(tmp_path: Path) -> Store:
    """Store that auto-injects into deps for router tests."""
    s = Store(db_path=tmp_path / "test.db")
    deps.set_store(s)
    return s


@pytest.fixture
def test_event_bus() -> EventBus:
    """EventBus that auto-injects into deps for router tests."""
    bus = EventBus()
    deps.set_event_bus(bus)
    return bus


@pytest.fixture
def test_executor(test_store: Store, test_event_bus: EventBus) -> ScanExecutor:
    executor = ScanExecutor(test_store, test_event_bus)
    deps.set_executor(executor)
    return executor


@pytest.fixture
def test_scheduler(test_store: Store, test_event_bus: EventBus) -> Scheduler:
    scheduler = Scheduler(test_store, test_event_bus)
    deps.set_scheduler(scheduler)
    return scheduler


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())
