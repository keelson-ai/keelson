from __future__ import annotations

import logging
import logging.config
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from pentis_service import __version__, deps
from pentis_service.routers import health
from pentis_service.routers.alerts import router as alerts_router
from pentis_service.routers.dashboard import router as dashboard_router
from pentis_service.routers.events import router as events_router
from pentis_service.routers.onboard import router as onboard_router
from pentis_service.routers.reports import router as reports_router
from pentis_service.routers.scans import router as scans_router
from pentis_service.routers.schedules import router as schedules_router

_LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

_LOGGING_CONFIG: dict[str, object] = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "logging.Formatter",
            "fmt": '{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}',
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


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Boot and teardown all background services."""
    logger = logging.getLogger(__name__)

    # --- Boot ---
    from pentis.state.store import Store
    from pentis_service.services.event_bus import EventBus
    from pentis_service.services.executor import ScanExecutor
    from pentis_service.services.health_monitor import HealthMonitor
    from pentis_service.services.red_team_loop import RedTeamLoop
    from pentis_service.services.regression import RegressionService
    from pentis_service.services.scheduler import Scheduler

    store = Store()
    deps.set_store(store)

    event_bus = EventBus()
    event_bus.set_webhooks(store.list_webhooks())
    deps.set_event_bus(event_bus)

    max_concurrent = int(os.environ.get("PENTIS_MAX_CONCURRENT_SCANS", "3"))
    executor = ScanExecutor(store, event_bus, max_concurrent=max_concurrent)
    deps.set_executor(executor)

    regression_service = RegressionService(store, event_bus)
    red_team_loop = RedTeamLoop(store, event_bus, regression_service)
    deps.set_red_team_loop(red_team_loop)

    scheduler = Scheduler(store, event_bus)
    scheduler.set_trigger_callback(red_team_loop.run_cycle)
    deps.set_scheduler(scheduler)

    health_interval = float(os.environ.get("PENTIS_HEALTH_CHECK_INTERVAL", "300"))
    health_monitor = HealthMonitor(store, event_bus, check_interval=health_interval)
    deps.set_health_monitor(health_monitor)

    await scheduler.start()
    await health_monitor.start()
    logger.info("All services started")

    yield

    # --- Teardown ---
    await health_monitor.stop()
    await scheduler.stop()
    store.close()
    logger.info("All services stopped")


def create_app() -> FastAPI:
    logging.config.dictConfig(_LOGGING_CONFIG)
    logger = logging.getLogger(__name__)
    logger.info("starting pentis_service", extra={"version": __version__})

    app = FastAPI(
        title="Pentis Service",
        version=__version__,
        description="AI agent security scanner REST API — Always-Live Red Team",
        lifespan=lifespan,
    )

    app.include_router(health.router)
    app.include_router(scans_router)
    app.include_router(schedules_router)
    app.include_router(alerts_router)
    app.include_router(dashboard_router)
    app.include_router(events_router)
    app.include_router(reports_router)
    app.include_router(onboard_router)

    return app


app = create_app()


def serve() -> None:
    import uvicorn

    port = int(os.environ.get("PENTIS_PORT", "8000"))
    uvicorn.run("pentis_service.main:app", host="0.0.0.0", port=port, reload=False)


if __name__ == "__main__":
    serve()
