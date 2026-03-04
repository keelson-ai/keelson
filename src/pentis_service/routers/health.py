from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from pentis_service import __version__

logger = logging.getLogger(__name__)

router = APIRouter()


@dataclass
class HealthResponse:
    status: str
    version: str


@router.get("/health", response_class=JSONResponse)
async def health() -> dict[str, str]:
    logger.info("health check requested")
    response = HealthResponse(status="ok", version=__version__)
    return {"status": response.status, "version": response.version}
