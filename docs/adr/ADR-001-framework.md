# ADR-001: Web Framework Selection — FastAPI

## Status

Accepted

## Context

The Keelson service needs an HTTP API layer to expose scan, probe, and report operations. The service is I/O-heavy (network calls to LLM targets, SQLite reads/writes) and will serve a mix of synchronous and long-running asynchronous operations. The team has chosen Python as the implementation language (see ADR-002 for dependency tooling).

Options considered:

1. **FastAPI** — async-first, ASGI, automatic OpenAPI generation, Pydantic validation
2. **Flask** — mature WSGI framework, large ecosystem, sync-by-default
3. **Starlette (bare)** — minimal ASGI toolkit; FastAPI builds on it

## Decision

We use **FastAPI** as the web framework.

Key factors:

- **Async by default** — matches the `httpx`-based async adapter pattern used throughout the engine; avoids the thread-pool overhead required to run async code under WSGI.
- **OpenAPI generation** — FastAPI auto-generates a spec from route signatures and Pydantic models, keeping `docs/openapi.yaml` and the implementation in sync.
- **Pydantic v2 integration** — request/response validation is handled declaratively; no hand-rolled schema code.
- **Starlette primitives** — background tasks, middleware, and streaming responses are available without additional dependencies.
- **Ecosystem maturity** — actively maintained, first-class `pytest` / `httpx` testing story via `ASGITransport`.

Flask was ruled out because it is WSGI-only; bridging async adapters through `asyncio.run()` in every route handler is fragile and adds latency. Bare Starlette was ruled out because FastAPI provides all of Starlette's capabilities plus validation and OpenAPI at near-zero cost.

## Consequences

**Positive:**
- Routes can `await` adapter calls directly without thread pools.
- `/docs` (Swagger UI) and `/redoc` are available out of the box during development.
- Tests use `httpx.AsyncClient(transport=ASGITransport(app))` — no server process required.
- Future streaming endpoints (e.g., streaming scan progress) are straightforward with `StreamingResponse`.

**Negative / trade-offs:**
- FastAPI's dependency injection system (the `Depends()` pattern) has a learning curve for contributors familiar with Flask.
- Pydantic v2 validation errors return 422 Unprocessable Entity by default; callers must handle this status code in addition to 400.
- ASGI deployment requires an ASGI server (uvicorn or hypercorn); the familiar `gunicorn` alone is insufficient.

**Neutral:**
- `uvicorn[standard]` is already pinned as the ASGI server in `pyproject.toml`.
- The `HealthResponse` dataclass in `routers/health.py` should be migrated to a Pydantic `BaseModel` in Phase 2 so FastAPI can generate an accurate JSON Schema for the `/health` response (current dataclass is not introspected by FastAPI's schema generator).
