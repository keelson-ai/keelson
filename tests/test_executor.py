"""Tests for the scan executor service."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from pentis.core.models import ScanJob, ScanStatus
from pentis.state.store import Store
from pentis_service.services.event_bus import EventBus
from pentis_service.services.executor import ScanExecutor


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(db_path=tmp_path / "test.db")


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


@pytest.fixture
def executor(store: Store, bus: EventBus) -> ScanExecutor:
    return ScanExecutor(store, bus, max_concurrent=2)


async def test_submit_scan_creates_job(executor: ScanExecutor, store: Store) -> None:
    job = ScanJob(target_url="http://example.com/v1/chat/completions")
    sub_id, queue = executor._event_bus.subscribe()

    with patch("pentis_service.services.executor.make_adapter") as mock_adapter:
        mock = AsyncMock()
        mock.health_check.return_value = True
        mock.send_messages.return_value = ("I cannot do that.", 100)
        mock.close = AsyncMock()
        mock_adapter.return_value = mock

        scan_id = await executor.submit_scan(
            job=job,
            api_key="test-key",
            adapter_type="openai",
            tier="fast",
        )

    assert scan_id == job.scan_id
    saved = store.get_scan_job(scan_id)
    assert saved is not None
    assert saved.target_url == "http://example.com/v1/chat/completions"


async def test_cancel_nonexistent_scan(executor: ScanExecutor) -> None:
    result = await executor.cancel_scan("nonexistent-id")
    assert result is False


def test_semaphore_concurrency_limit(store: Store, bus: EventBus) -> None:
    executor = ScanExecutor(store, bus, max_concurrent=1)
    assert executor._semaphore._value == 1
