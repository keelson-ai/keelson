# ADR-003: Observability Strategy — Structured Logging + Future OpenTelemetry

## Status

Accepted

## Context

The Keelson service will be deployed in containerised environments (Docker, Kubernetes) where logs are the primary signal for debugging, alerting, and auditing. As the service grows to include async scan workers and multi-tenant operation, distributed tracing and metrics will become necessary.

The team needs to decide:

1. What logging format and library to use from the outset
2. Whether to introduce a tracing library (OpenTelemetry) now or defer
3. How to handle sensitive data in logs (target URLs, API keys, scan payloads)

Options considered for logging:

1. **stdlib `logging` with JSON formatter** — zero extra dependencies; `logging.config.dictConfig` supports structured output
2. **`structlog`** — third-party; pipeline-based processors; native JSON output; integrates with stdlib `logging`
3. **`python-json-logger`** — thin wrapper over stdlib; produces JSON with `extra={}` field serialisation

Options considered for tracing:

1. **Defer OpenTelemetry** — instrument with structured log correlation IDs now; add OTel SDK when a tracing backend exists
2. **Add `opentelemetry-sdk` now** — full tracing from day one; higher initial complexity

## Decision

**Logging:** Use stdlib `logging` with a custom JSON formatter initially. Migrate to `structlog` when Phase 2 introduces async scan workers (where structlog's context-var based processors add clear value).

**Tracing:** Defer OpenTelemetry SDK integration until Phase 2. Emit `trace_id` / `span_id` fields in log records from the outset so logs can be correlated with future traces without log format changes.

**Sensitive data:** Apply a log sanitiser that redacts `api_key`, `authorization`, and `x-api-key` fields from any log record containing request/response data.

Key factors for deferring OTel:

- No tracing backend (Jaeger, Tempo, OTLP collector) exists in the current infrastructure.
- Adding the OTel SDK without a backend creates noise (spans exported to nowhere) and a ~10 MB dependency addition.
- Structured logs with correlation IDs satisfy 90% of debugging needs at the current scale.
- OTel auto-instrumentation for FastAPI and httpx is mature and can be added in a single PR when a backend is available.

## Consequences

**Positive:**
- Zero runtime dependency on tracing infrastructure; no startup errors if a collector is unreachable.
- JSON log output is immediately usable by log aggregators (CloudWatch, Datadog, Loki, Splunk) without parsing rules.
- `trace_id` in logs enables future correlation with OTel traces without a log format migration.
- stdlib `logging` is universally understood; contributors do not need to learn a new library to add log statements.

**Negative / trade-offs:**
- stdlib `logging` with a dict formatter does not serialise `extra={}` keyword arguments into the JSON output by default (this is a known stdlib limitation documented in `docs/status.md`). Until `structlog` or `python-json-logger` is adopted, `extra={}` fields are silently dropped.
- No distributed tracing means debugging multi-service flows (e.g., service → external LLM → service) requires manual log correlation.
- When OTel is introduced in Phase 2, the `logging.config.dictConfig` setup in `main.py` will need to be extended to bridge OTel's log handler.

**Neutral:**
- The `LOG_LEVEL` environment variable controls verbosity at startup; default is `INFO`.
- Audit logs (which attacks ran, which target, what verdict) will be emitted at `INFO` level with structured fields for compliance purposes.
- A future `KEELSON_OTEL_ENDPOINT` environment variable is reserved for the OTel OTLP exporter URL.

## Future Work

When Phase 2 begins:

1. Add `structlog` and `python-json-logger` to `[project.dependencies]`
2. Replace `logging.config.dictConfig` formatter with structlog's `JSONRenderer`
3. Add `opentelemetry-sdk`, `opentelemetry-instrumentation-fastapi`, and `opentelemetry-instrumentation-httpx` to `[project.optional-dependencies]` under a `[otel]` group
4. Emit traces to an OTLP collector via `KEELSON_OTEL_ENDPOINT`
