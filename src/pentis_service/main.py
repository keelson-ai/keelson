from __future__ import annotations

import logging
import os

from fastapi import FastAPI

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Pentis Service",
    version="0.1.0",
    description="AI agent security scanner REST API",
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PENTIS_PORT", "8000"))
    uvicorn.run("pentis_service.main:app", host="0.0.0.0", port=port, reload=False)
