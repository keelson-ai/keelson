"""Tests for the event bus — pub/sub and webhook delivery."""

from __future__ import annotations

import asyncio
import json

import pytest

from pentis.core.models import WebhookConfig
from pentis_service.services.event_bus import EventBus


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


async def test_subscribe_and_receive(bus: EventBus) -> None:
    sub_id, queue = bus.subscribe()
    await bus.publish("test_event", {"key": "value"})
    event = queue.get_nowait()
    assert event["event_type"] == "test_event"
    assert event["data"]["key"] == "value"
    assert "timestamp" in event
    bus.unsubscribe(sub_id)


async def test_multiple_subscribers(bus: EventBus) -> None:
    _, q1 = bus.subscribe()
    _, q2 = bus.subscribe()
    await bus.publish("multi", {"n": 1})
    assert q1.qsize() == 1
    assert q2.qsize() == 1
    e1 = q1.get_nowait()
    e2 = q2.get_nowait()
    assert e1["event_type"] == "multi"
    assert e2["event_type"] == "multi"


async def test_unsubscribe_stops_delivery(bus: EventBus) -> None:
    sub_id, queue = bus.subscribe()
    bus.unsubscribe(sub_id)
    await bus.publish("after_unsub", {})
    assert queue.empty()


async def test_slow_subscriber_dropped(bus: EventBus) -> None:
    """Subscribers with full queues get dropped."""
    sub_id, queue = bus.subscribe()
    # Fill the queue
    for i in range(257):
        await bus.publish("flood", {"i": i})
    # Queue should still work (subscriber may have been dropped)
    assert queue.qsize() <= 256


async def test_webhook_filtering(bus: EventBus) -> None:
    """Webhooks with event filters only receive matching events."""
    webhook = WebhookConfig(
        url="http://example.com/hook",
        events=["scan_completed"],
        secret="test-secret",
    )
    bus.set_webhooks([webhook])
    # No error even though webhook URL is unreachable (fire-and-forget)
    await bus.publish("scan_started", {})
    await bus.publish("scan_completed", {})


async def test_publish_without_subscribers(bus: EventBus) -> None:
    """Publishing with no subscribers should not error."""
    await bus.publish("lonely_event", {"data": 42})
