"""Reports router — on-demand report generation."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from pentis.core.reporter import generate_report
from pentis.core.sarif import to_sarif_json
from pentis_service import deps

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{scan_id}")
async def get_report(scan_id: str, format: str = "markdown") -> PlainTextResponse:
    """Generate a report for a completed scan.

    Supported formats: markdown, sarif, junit.
    """
    store = deps.get_store()
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if format == "sarif":
        content = to_sarif_json(scan)
        return PlainTextResponse(content, media_type="application/json")
    elif format == "junit":
        from pentis.core.junit import to_junit_xml

        content = to_junit_xml(scan)
        return PlainTextResponse(content, media_type="application/xml")
    else:
        content = generate_report(scan)
        return PlainTextResponse(content, media_type="text/markdown")
