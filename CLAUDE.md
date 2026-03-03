# Pentis — AI Agent Security Scanner

Black-box vulnerability testing for LLM-powered agents. Scans OpenAI-compatible endpoints for vulnerabilities across 3 behavior categories.

## Quick Reference

```bash
# Setup
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# CLI
pentis scan --url <endpoint>    # Run security scan
pentis list                     # Show attack templates
pentis init                     # Create config file
```

## Architecture

```
src/pentis/              # Source code (import as `pentis`)
├── cli.py               # Typer CLI (scan, list, init)
├── adapters/http.py     # Async httpx adapter (OpenAI-compatible)
├── attacks/             # 28 YAML attack templates
│   ├── goal_adherence/  # GA-001..010 (OWASP LLM01)
│   ├── tool_safety/     # TS-001..010 (OWASP LLM02/LLM06)
│   └── memory_integrity/# MI-001..008 (OWASP LLM05)
├── core/
│   ├── models.py        # Dataclasses: Finding, ScanResult, AgentResponse
│   ├── engine.py        # Attack execution engine
│   ├── scanner.py       # Pipeline orchestrator
│   ├── templates.py     # YAML loader + jsonschema validation
│   ├── reporter.py      # Rich terminal + Jinja2 markdown reports
│   ├── discovery.py     # Endpoint capability probing
│   ├── banner.py        # ASCII art
│   └── detection/       # Detection pipeline
│       ├── refusal.py   # 50+ refusal phrase detector
│       ├── indicator.py # Word/regex/absence matching
│       ├── side_effect.py # Dangerous tool call detection
│       └── resolver.py  # Priority resolution → FindingStatus
└── strategies/fixed.py  # Template ordering
tests/                   # 246 tests (pytest + pytest-asyncio + respx)
```

## Key Patterns

- **Dataclasses** for all models (not Pydantic)
- **Async httpx** for all HTTP operations
- **respx** for mocking HTTP in tests
- **YAML + jsonschema** for attack templates
- **Rich + Typer** for CLI output
- **Jinja2** for markdown report generation

## Scan Pipeline

```
discover → load templates → order → execute → detect → report
```

## Detection Priority

1. Side effects (dangerous tool calls) → VULNERABLE
2. Strong indicators (weight ≥ threshold) → VULNERABLE
3. Clean refusal → SAFE
4. Refusal + weak indicators → SAFE
5. Weak indicators only → INCONCLUSIVE
6. Nothing detected → INCONCLUSIVE

## Adding Attack Templates

Templates are YAML files in `src/pentis/attacks/<behavior>/`. ID format: `XX-NNN`. Must include `owasp_id`. Validated against schema in `core/template_schema.py`.

## Tests

```bash
pytest tests/ -v              # All 246 tests
pytest tests/test_engine_extended.py -v  # Specific component
pytest tests/ -v -s           # With stdout
```
