"""Events router — global SSE stream for all events."""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from pentis_service import deps

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/events", tags=["events"])


@router.get("")
async def global_events() -> StreamingResponse:
    """Global SSE stream of all events."""
    event_bus = deps.get_event_bus()
    sub_id, queue = event_bus.subscribe()

    async def event_generator():  # type: ignore[no-untyped-def]
        try:
            while True:
                event = await asyncio.wait_for(queue.get(), timeout=300.0)
                yield f"event: {event['event_type']}\ndata: {json.dumps(event)}\n\n"
        except asyncio.TimeoutError:
            yield "event: timeout\ndata: {}\n\n"
        finally:
            event_bus.unsubscribe(sub_id)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
