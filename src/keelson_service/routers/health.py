from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi import APIRouter

from keelson_service import __version__

logger = logging.getLogger(__name__)

router = APIRouter()


@dataclass
class HealthResponse:
    status: str
    version: str


@router.get("/health")
async def health() -> dict[str, str]:
    logger.info("health check requested")
    response = HealthResponse(status="ok", version=__version__)
    return {"status": response.status, "version": response.version}
