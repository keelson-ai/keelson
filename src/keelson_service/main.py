from __future__ import annotations

import logging
import logging.config
import os

from fastapi import FastAPI

from keelson_service import __version__
from keelson_service.routers import health

_LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

_LOGGING_CONFIG: dict[str, object] = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "logging.Formatter",
            "fmt": (
                '{"time":"%(asctime)s",'
                '"level":"%(levelname)s",'
                '"logger":"%(name)s",'
                '"message":"%(message)s"}'
            ),
            "datefmt": "%Y-%m-%dT%H:%M:%SZ",
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "stream": "ext://sys.stdout",
        }
    },
    "root": {
        "level": _LOG_LEVEL,
        "handlers": ["console"],
    },
}


def create_app() -> FastAPI:
    logging.config.dictConfig(_LOGGING_CONFIG)
    logger = logging.getLogger(__name__)
    logger.info("starting keelson_service", extra={"version": __version__})

    app = FastAPI(
        title="Keelson Service",
        version=__version__,
        description="AI agent security scanner REST API",
    )

    app.include_router(health.router)

    return app


app = create_app()


def serve() -> None:
    import uvicorn

    port = int(os.environ.get("KEELSON_PORT", "8000"))
    uvicorn.run("keelson_service.main:app", host="0.0.0.0", port=port, reload=False)


if __name__ == "__main__":
    serve()
