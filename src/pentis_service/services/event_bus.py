"""In-process event bus with SSE subscriber queues and webhook delivery."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from pentis.core.models import WebhookConfig

logger = logging.getLogger(__name__)


class EventBus:
    """Async pub/sub event bus for real-time event distribution.

    Supports:
    - SSE subscribers via per-subscriber asyncio.Queue
    - Webhook delivery with HMAC-SHA256 signing
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, asyncio.Queue[dict[str, Any]]] = {}
        self._webhooks: list[WebhookConfig] = []
        self._subscriber_counter = 0

    def set_webhooks(self, webhooks: list[WebhookConfig]) -> None:
        """Update the list of active webhooks."""
        self._webhooks = [w for w in webhooks if w.enabled]

    def subscribe(self) -> tuple[str, asyncio.Queue[dict[str, Any]]]:
        """Create a new SSE subscriber. Returns (subscriber_id, queue)."""
        self._subscriber_counter += 1
        sub_id = f"sub-{self._subscriber_counter}"
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=256)
        self._subscribers[sub_id] = queue
        logger.info("SSE subscriber added: %s", sub_id)
        return sub_id, queue

    def unsubscribe(self, subscriber_id: str) -> None:
        """Remove an SSE subscriber."""
        self._subscribers.pop(subscriber_id, None)
        logger.info("SSE subscriber removed: %s", subscriber_id)

    async def publish(self, event_type: str, data: dict[str, Any] | None = None) -> None:
        """Publish an event to all subscribers and webhooks."""
        event = {
            "event_type": event_type,
            "data": data or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info("Event published: %s", event_type)

        # Fan out to SSE subscribers
        dead: list[str] = []
        for sub_id, queue in self._subscribers.items():
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                dead.append(sub_id)
                logger.warning("Dropping slow subscriber: %s", sub_id)
        for sub_id in dead:
            self._subscribers.pop(sub_id, None)

        # Deliver to webhooks (fire-and-forget)
        for webhook in self._webhooks:
            if webhook.events and event_type not in webhook.events:
                continue
            asyncio.create_task(self._deliver_webhook(webhook, event))

    async def _deliver_webhook(
        self, webhook: WebhookConfig, event: dict[str, Any]
    ) -> None:
        """Deliver an event to a webhook endpoint with HMAC signing."""
        payload = json.dumps(event)
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if webhook.secret:
            sig = hmac.new(
                webhook.secret.encode(), payload.encode(), hashlib.sha256
            ).hexdigest()
            headers["X-Pentis-Signature"] = f"sha256={sig}"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(webhook.url, content=payload, headers=headers)
                if resp.status_code >= 400:
                    logger.warning(
                        "Webhook delivery failed: %s → %d", webhook.url, resp.status_code
                    )
        except Exception:
            logger.exception("Webhook delivery error: %s", webhook.url)
