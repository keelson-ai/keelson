# Stage 1: builder — installs dependencies with uv
FROM python:3.11-slim AS builder

WORKDIR /app

# Install uv
RUN pip install --no-cache-dir uv

# Copy dependency manifests first for layer caching
COPY pyproject.toml uv.lock ./

# Install production dependencies only into an isolated venv
RUN uv sync --no-dev

# Copy source code
COPY src/ ./src/

# Stage 2: runtime — minimal image
FROM python:3.11-slim

WORKDIR /app

# Create non-root user
RUN useradd -m -u 1000 pentis && \
    chown -R pentis:pentis /app

# Copy the populated venv from builder
COPY --from=builder --chown=pentis:pentis /app/.venv /app/.venv
COPY --from=builder --chown=pentis:pentis /app/src /app/src

# Make venv binaries available on PATH
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/src"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Drop to non-root
USER pentis

EXPOSE 8000

ENTRYPOINT ["uvicorn", "pentis_service.main:app", "--host", "0.0.0.0", "--port", "8000"]
