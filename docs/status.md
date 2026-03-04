# Task Status

## YvHKkjLC — Create Dockerfile and docker-compose.yml

**Status**: Complete

### Files Created / Modified
| File | Action | Notes |
|------|--------|-------|
| `src/pentis_service/__init__.py` | Created | Skeleton package, `__version__ = "0.1.0"` |
| `src/pentis_service/main.py` | Created | FastAPI app with `GET /health` endpoint |
| `Dockerfile` | Created | Multi-stage production build (builder → runtime) |
| `Dockerfile.dev` | Created | Single-stage dev image with hot-reload |
| `docker-compose.yml` | Created | `api` service with port 8000, volume mount, env_file, healthcheck |
| `.env.example` | Created | All required variables documented |
| `pyproject.toml` | Modified | Added `fastapi>=0.111`, `uvicorn[standard]>=0.30`; added `pentis_service` to build targets |

### Usage
```bash
# Copy environment file
cp .env.example .env
# Edit .env with your values, then:
docker compose up
```
The API will be available at `http://localhost:8000` and the health endpoint at `http://localhost:8000/health`.

### QA Review Fixes (automated)
| File | Fix |
|------|-----|
| `Dockerfile.dev` | Changed `uv sync` → `uv sync --extra dev` so dev tools (pytest, ruff, pyright) are actually installed |
| `docker-compose.yml` | Added `extra_hosts: host.docker.internal:host-gateway` for Linux Docker compatibility with the default `PENTIS_TARGET_URL` |

### Notes
- `uv.lock` will need to be regenerated after adding `fastapi`/`uvicorn` to dependencies (`uv lock` locally)
- The healthcheck uses Python's stdlib `urllib` to avoid requiring `curl` in the minimal runtime image
- Hot-reload works because `./src` is bind-mounted into the container in development mode

---

## WGoV69RB — Implement skeleton FastAPI application with GET /health endpoint

**Status**: Complete

### Files Created / Modified
| File | Action | Notes |
|------|--------|-------|
| `src/pentis_service/routers/__init__.py` | Created | Empty router package marker |
| `src/pentis_service/routers/health.py` | Created | `HealthResponse` dataclass, `GET /health` route returning `{"status":"ok","version":"<version>"}` |
| `src/pentis_service/main.py` | Modified | `create_app()` factory, JSON structured logging via `logging.config.dictConfig`, `serve()` entrypoint |
| `pyproject.toml` | Modified | Added `pentis-service = "pentis_service.main:serve"` to `[project.scripts]` |

### Usage
```bash
# Run directly (after uv sync)
pentis-service

# Or via Python module
python -m pentis_service.main
```

### Notes
- `create_app()` factory makes the app importable and testable without starting the server
- JSON log format uses stdlib `logging.Formatter` (no extra dependencies)
- `LOG_LEVEL` env var controls log verbosity (default: `INFO`)
- `PENTIS_PORT` env var controls server port (default: `8000`)
