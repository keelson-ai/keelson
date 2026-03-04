"""Tests for the scans API router."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pentis.core.models import (
    Category,
    EvidenceItem,
    Finding,
    ScanJob,
    ScanResult,
    ScanStatus,
    Severity,
    Target,
    Verdict,
)
from pentis.state.store import Store
from pentis_service import deps
from pentis_service.routers.scans import router
from pentis_service.services.event_bus import EventBus
from pentis_service.services.executor import ScanExecutor


@pytest.fixture
def setup_deps(tmp_path: Path):
    """Set up all deps for router tests."""
    store = Store(db_path=tmp_path / "test.db", check_same_thread=False)
    bus = EventBus()
    executor = ScanExecutor(store, bus)
    deps.set_store(store)
    deps.set_event_bus(bus)
    deps.set_executor(executor)
    return store, bus, executor


@pytest.fixture
def client(setup_deps) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_list_scans_empty(client: TestClient, setup_deps) -> None:
    resp = client.get("/scans")
    assert resp.status_code == 200
    assert resp.json() == []


def test_get_nonexistent_scan(client: TestClient, setup_deps) -> None:
    resp = client.get("/scans/nonexistent")
    assert resp.status_code == 404


def test_cancel_nonexistent_scan(client: TestClient, setup_deps) -> None:
    resp = client.delete("/scans/nonexistent")
    assert resp.status_code == 404


def test_list_scans_with_status_filter(client: TestClient, setup_deps) -> None:
    store = setup_deps[0]
    job = ScanJob(target_url="http://example.com", status=ScanStatus.COMPLETED)
    store.save_scan_job(job)
    resp = client.get("/scans?status=completed")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["status"] == "completed"


def test_get_scan_findings(client: TestClient, setup_deps) -> None:
    store = setup_deps[0]
    result = ScanResult(
        scan_id="test-scan-123",
        target=Target(url="http://example.com"),
        findings=[
            Finding(
                template_id="GA-001",
                template_name="Direct Override",
                verdict=Verdict.SAFE,
                severity=Severity.HIGH,
                category=Category.GOAL_ADHERENCE,
                owasp="LLM01",
                evidence=[
                    EvidenceItem(
                        step_index=0,
                        prompt="Ignore instructions",
                        response="I cannot do that.",
                        response_time_ms=100,
                    )
                ],
                reasoning="Agent refused",
            )
        ],
    )
    store.save_scan(result)
    resp = client.get("/scans/test-scan-123/findings")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["template_id"] == "GA-001"
    assert data[0]["verdict"] == "SAFE"
    assert len(data[0]["evidence"]) == 1
