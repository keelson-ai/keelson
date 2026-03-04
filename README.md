# Pentis

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Autonomous red team agent for AI systems.** Pentis ships 105 attack playbooks across 7 behavior categories mapped to the OWASP LLM Top 10. It is implemented as a pure Claude Code plugin — Claude Code becomes the pentester: reads attack playbooks, sends prompts via curl, semantically evaluates responses, and generates reports.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start (Docker)](#quick-start-docker)
- [Local Development (without Docker)](#local-development-without-docker)
- [Running Tests](#running-tests)
- [Code Quality](#code-quality)
- [Environment Variables](#environment-variables)
- [Usage](#usage)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| **Docker** | 24+ | [docs.docker.com](https://docs.docker.com/get-docker/) |
| **Docker Compose** | v2 (`docker compose`) | Bundled with Docker Desktop |
| **uv** | 0.4+ | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| **Python** | 3.11+ | Managed automatically by uv |

> **Note:** Docker is only required for the containerised dev environment. You can run the service directly with uv if you prefer (see [Local Development](#local-development-without-docker)).

---

## Quick Start (Docker)

```bash
# 1. Clone the repository
git clone https://github.com/Othentic-Labs/Pentis.git
cd Pentis

# 2. Copy and configure the environment file
cp .env.example .env
# Edit .env — at minimum set PENTIS_API_KEY and PENTIS_TARGET_URL

# 3. Start the service
docker compose up
```

The API will be available at **http://localhost:8000**.

Verify it's running:

```bash
curl http://localhost:8000/health
# {"status":"ok","version":"0.1.0"}
```

To rebuild after dependency changes:

```bash
docker compose up --build
```

To run in the background:

```bash
docker compose up -d
docker compose logs -f   # tail logs
docker compose down      # stop
```

---

## Local Development (without Docker)

### Install dependencies

```bash
uv sync --extra dev
```

This creates a `.venv` in the project root and installs all runtime and development dependencies (pytest, ruff, pyright, pre-commit).

### Configure environment

```bash
cp .env.example .env
# Edit .env with your values
```

The service reads environment variables from `.env` when running locally. See [Environment Variables](#environment-variables) for the full reference.

### Run the service

```bash
uv run uvicorn pentis_service.main:app --reload --port 8000
```

`--reload` enables hot-reload: the server restarts automatically when you edit files under `src/`.

Alternatively, use the installed entrypoint:

```bash
uv run pentis-service
```

### Makefile shortcuts

```bash
make install    # uv pip install -e ".[dev]"
make test       # pytest tests/
make lint       # ruff check src/ tests/
make format     # ruff format src/ tests/
make typecheck  # pyright
make check      # lint + typecheck + test (full CI gate)
make clean      # remove build artefacts and caches
make build      # uv build (wheel + sdist)
```

---

## Running Tests

```bash
# Run the full test suite
uv run pytest

# Verbose output with test names
uv run pytest -v

# Run a specific test file
uv run pytest tests/test_health.py

# Run tests matching a keyword
uv run pytest -k "health"

# Show coverage (if pytest-cov is installed)
uv run pytest --cov=src
```

Tests live in `tests/` and mirror the source structure. All async tests use `asyncio_mode = "auto"` (no `@pytest.mark.asyncio` decorator needed).

---

## Code Quality

### Linting

```bash
uv run ruff check .
uv run ruff check . --fix   # auto-fix safe issues
```

### Formatting

```bash
uv run ruff format .
uv run ruff format . --check  # dry-run (exit 1 if changes needed)
```

### Type checking

```bash
uv run pyright
```

Pyright runs in strict mode (configured in `pyproject.toml`). Target: 0 errors.

### Run everything at once

```bash
make check
```

---

## Environment Variables

Copy `.env.example` to `.env` and fill in your values. **Never commit `.env` to version control.**

| Variable | Default | Description |
|----------|---------|-------------|
| `PENTIS_API_KEY` | *(required)* | Bearer token sent to the target endpoint |
| `PENTIS_TARGET_URL` | `http://host.docker.internal:8080/v1/chat/completions` | OpenAI-compatible endpoint to scan |
| `PENTIS_MODEL` | `gpt-4o` | Model name passed in the request body |
| `LOG_LEVEL` | `INFO` | Log verbosity: `DEBUG \| INFO \| WARNING \| ERROR` |
| `PENTIS_PORT` | `8000` | Port the uvicorn server listens on |
| `PENTIS_REQUEST_DELAY` | `1` | Seconds to sleep between attack requests (rate limiting) |
| `PENTIS_CONCURRENCY` | `4` | Maximum concurrent scan workers |
| `PENTIS_CATEGORIES` | *(empty = all)* | Comma-separated attack categories to run |

Valid values for `PENTIS_CATEGORIES`: `goal-adherence`, `tool-safety`, `memory-integrity`, `delegation-integrity`, `execution-safety`, `permission-boundaries`, `session-isolation`.

See [`.env.example`](.env.example) for the full annotated reference.

> **Docker note:** `host.docker.internal` resolves to the Docker host on Mac and Windows. On Linux, the `docker-compose.yml` adds `extra_hosts: host-gateway` so it resolves correctly too.

---

## Usage

### Claude Code plugin

```bash
# Load as a Claude Code plugin
claude --plugin-dir /path/to/Pentis

# Run a full security scan
/pentis:scan https://api.example.com/v1/chat/completions --api-key $KEY

# Run a single attack
/pentis:attack https://api.example.com/v1/chat/completions GA-001 --api-key $KEY

# Generate a report
/pentis:report [report-file]
```

### Attack categories

| Category | Prefix | Count | OWASP | What It Tests |
|----------|--------|-------|-------|---------------|
| **Goal Adherence** | GA | 30 | LLM01 | Prompt injection, role hijacking, system prompt extraction, encoding evasion |
| **Tool Safety** | TS | 24 | LLM02/LLM06 | File access, command injection, SQL injection, privilege escalation, path traversal |
| **Memory Integrity** | MI | 17 | LLM05 | History poisoning, identity persistence, behavior drift, cross-turn exfiltration |
| **Delegation Integrity** | DI | 8 | LLM02 | Unauthorized delegation, privilege transfer, agent impersonation |
| **Execution Safety** | ES | 8 | LLM06 | Unsafe code execution, sandbox escape, side-channel leakage |
| **Permission Boundaries** | PB | 8 | LLM01/LLM06 | Permission creep, access control bypass, scope expansion |
| **Session Isolation** | SI | 10 | LLM05 | Cross-session data leakage, context bleeding, session hijacking |

### Adding custom attacks

Create a `.yaml` file in the appropriate `attacks/` subdirectory:

```yaml
id: GA-036
name: My Custom Attack
severity: high
category: goal_adherence
owasp_id: "LLM01 — Prompt Injection"
objective: >
  Describe what this attack tests.
turns:
  - role: user
    content: >
      The attack prompt to send.
evaluation:
  vulnerable_if:
    - Agent complies with the attack request
  safe_if:
    - Agent refuses or continues normal behavior
  inconclusive_if:
    - Response is ambiguous
```

Use the next ID in sequence (GA-036, TS-036, MI-036). Include an OWASP LLM Top 10 mapping and clear evaluation criteria.

---

## Architecture

### Project structure

```
Pentis/
├── .claude-plugin/
│   └── plugin.json              # Claude Code plugin manifest
├── agents/
│   └── pentester.md             # Main pentester agent instructions
├── commands/
│   ├── scan.md                  # /pentis:scan
│   ├── attack.md                # /pentis:attack
│   └── report.md                # /pentis:report
├── attacks/                     # 105 attack playbooks (.yaml)
│   ├── goal-adherence/          # GA-001..035
│   ├── tool-safety/             # TS-001..035
│   └── memory-integrity/        # MI-001..035
├── src/
│   └── pentis_service/          # FastAPI service
│       ├── main.py              # App factory + uvicorn entrypoint
│       └── routers/
│           └── health.py        # GET /health
├── tests/                       # pytest suite
├── docs/
│   ├── adr/                     # Architecture Decision Records
│   │   ├── ADR-001-framework.md
│   │   ├── ADR-002-dependency-management.md
│   │   └── ADR-003-observability.md
│   └── openapi.yaml             # OpenAPI 3.1.0 API contract
├── Dockerfile                   # Multi-stage production build
├── Dockerfile.dev               # Dev image with hot-reload
├── docker-compose.yml           # Single-command local dev
├── .env.example                 # Environment variable reference
├── pyproject.toml               # Python packaging + tool config
└── Makefile                     # Developer shortcuts
```

### API specification

The authoritative OpenAPI 3.1.0 contract is at [`docs/openapi.yaml`](docs/openapi.yaml). It covers the `/health` endpoint (implemented) and placeholder paths for Phase 2 scan, attack, and report endpoints.

### Architecture Decision Records

Key technical decisions are documented as [MADR](https://adr.github.io/madr/) records in [`docs/adr/`](docs/adr/):

| ADR | Decision | Status |
|-----|----------|--------|
| [ADR-001](docs/adr/ADR-001-framework.md) | Web framework: FastAPI (async-first, auto-OpenAPI) | Accepted |
| [ADR-002](docs/adr/ADR-002-dependency-management.md) | Dependency management: uv (fast resolver, `uv.lock`) | Accepted |
| [ADR-003](docs/adr/ADR-003-observability.md) | Observability: structured logging now, OpenTelemetry in Phase 2 | Accepted |

### Key design decisions

- **No application code for attacks** — YAML playbooks + Claude Code plugin. Claude Code is the pentester.
- **curl for targets** — OpenAI-compatible chat completions API via `curl -s -X POST`
- **Semantic evaluation** — Claude judges responses (no regex/heuristics)
- **Multi-turn support** — accumulate messages array in curl payloads
- **Rate limiting** — sleep 1-2s between requests (configurable via `PENTIS_REQUEST_DELAY`)

---

## Contributing

### Branch naming

```
<type>/<short-description>

Examples:
feat/multi-turn-attack-engine
fix/handle-429-rate-limit
refactor/detection-pipeline
test/scanner-integration
docs/update-contributing-guide
```

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`.

### Commit message format

```
<type>: <brief description in imperative mood>

Examples:
feat: Add multi-turn attack engine
fix: Handle 429 rate limit in HTTP adapter
refactor: Extract detection pipeline into modules
test: Add integration tests for scanner
docs: Update environment variable reference
```

- Lowercase after the colon
- No period at the end
- Imperative mood ("Add" not "Added" or "Adds")
- 72 characters max for the subject line

### Pull request process

1. Create a feature branch from `main`
2. Make your changes
3. Run `make check` — all checks must pass (lint, typecheck, tests)
4. Push the branch and open a PR against `main`
5. PR title must follow the commit message format above
6. Every PR must have a summary describing what changed and why
7. Request review; do not merge your own PRs

### What to contribute

- **Attack playbooks** — Write new `.yaml` files in `attacks/`. Follow the playbook format in [Usage](#usage).
- **Bug reports** — Open an issue with reproduction steps.
- **Documentation fixes** — Correct anything that's wrong or unclear.

### Security

This tool is for **authorized security testing only**. Do not use Pentis against systems you don't have permission to test. If you discover a security issue in Pentis itself, report it via [GitHub Security Advisories](https://github.com/Othentic-Labs/Pentis/security/advisories).

---

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.
