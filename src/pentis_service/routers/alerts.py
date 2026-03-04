"""Alerts router — regression alerts and webhook management."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from pentis.core.models import WebhookConfig
from pentis_service import deps
from pentis_service.schemas import AlertResponse, WebhookRequest, WebhookResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("")
async def list_alerts(limit: int = 50) -> list[AlertResponse]:
    """List regression alerts."""
    store = deps.get_store()
    alerts = store.list_regression_alerts(limit=limit)
    return [
        AlertResponse(
            id=int(a["id"]),
            scan_a_id=str(a["scan_a_id"]) if a.get("scan_a_id") else None,
            scan_b_id=str(a["scan_b_id"]) if a.get("scan_b_id") else None,
            template_id=str(a["template_id"]),
            alert_severity=str(a["alert_severity"]),
            change_type=str(a["change_type"]),
            description=str(a.get("description", "")),
            created_at=str(a["created_at"]),
            acknowledged=bool(a.get("acknowledged", False)),
        )
        for a in alerts
    ]


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int) -> dict[str, str]:
    """Acknowledge a regression alert."""
    store = deps.get_store()
    store.acknowledge_alert(alert_id)
    return {"status": "acknowledged", "alert_id": str(alert_id)}


# --- Webhook management ---


@router.get("/webhooks")
async def list_webhooks() -> list[WebhookResponse]:
    """List all configured webhooks."""
    store = deps.get_store()
    webhooks = store.list_webhooks()
    return [
        WebhookResponse(
            webhook_id=w.webhook_id,
            url=w.url,
            events=w.events,
            enabled=w.enabled,
            created_at=w.created_at.isoformat(),
        )
        for w in webhooks
    ]


@router.post("/webhooks", status_code=201)
async def create_webhook(req: WebhookRequest) -> WebhookResponse:
    """Create a new webhook."""
    store = deps.get_store()
    event_bus = deps.get_event_bus()
    webhook = WebhookConfig(
        url=req.url,
        events=req.events,
        secret=req.secret,
    )
    store.save_webhook(webhook)
    event_bus.set_webhooks(store.list_webhooks())
    return WebhookResponse(
        webhook_id=webhook.webhook_id,
        url=webhook.url,
        events=webhook.events,
        enabled=webhook.enabled,
        created_at=webhook.created_at.isoformat(),
    )


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str) -> dict[str, str]:
    """Delete a webhook."""
    store = deps.get_store()
    event_bus = deps.get_event_bus()
    deleted = store.delete_webhook(webhook_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Webhook not found")
    event_bus.set_webhooks(store.list_webhooks())
    return {"status": "deleted", "webhook_id": webhook_id}
