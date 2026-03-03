# Coding Standards

## Python Style
- Python 3.10+ with type hints on all public functions
- Use dataclasses for data models (not Pydantic)
- Follow PEP 8 naming conventions
- Keep functions focused and single-purpose
- Use `async/await` for all HTTP operations (httpx)

## Project Structure
```
src/pentis/           # Source code (importable as `pentis`)
├── cli.py            # Typer CLI entrypoint
├── adapters/         # HTTP/framework adapters
├── attacks/          # YAML attack templates
├── core/             # Core logic (models, engine, scanner, detection)
│   └── detection/    # Refusal, indicator, side-effect detectors
├── strategies/       # Execution strategies
└── templates/        # Jinja2 report templates
tests/                # All tests (pytest)
```

## Import Convention
```python
# Always import from `pentis` package
from pentis.core.models import Finding, ScanResult
from pentis.adapters.http import HTTPAdapter
from pentis.core.detection.refusal import RefusalDetector
```

## Error Handling
```python
# Capture errors in evidence, don't crash the scan
try:
    response = await adapter.send(message)
except httpx.HTTPError as e:
    evidence.append(EvidenceItem(
        step_index=i, prompt=step.content,
        response=f"Error: {e}"
    ))
```

## YAML Templates
- Use jsonschema validation for all templates
- ID format: `XX-NNN` (e.g., GA-001, TS-005, MI-003)
- Every template must have OWASP mapping
- Indicators: word, regex, or absence types

## Testing
- Use pytest with pytest-asyncio for async tests
- Use respx to mock httpx requests
- Test files: `tests/test_<component>.py`
- Target: comprehensive coverage of all components
