# Python Standards

## Tooling
- **Formatter/Linter**: ruff (line-length 100, target py311)
- **Type checker**: pyright (strict mode)
- **Tests**: pytest with pytest-asyncio
- **Package manager**: uv / pip with hatchling build backend

## Code Style
- Type-annotate all public function signatures
- Use `from __future__ import annotations` for forward references
- Prefer functions and modules over class hierarchies
- Use dataclasses or NamedTuples for data containers, not raw dicts
- Use `pathlib.Path` over `os.path`
- Use `httpx` for HTTP (async-first), not `requests`
- Async functions where I/O is involved

## Conventions
- Imports: stdlib, then third-party, then local (ruff handles sorting)
- No wildcard imports (`from x import *`)
- No mutable default arguments
- Use `if __name__ == "__main__":` guards
- Raise specific exceptions, not bare `Exception`
- Use `logging` module, not `print` for diagnostic output

## Testing
- Test files mirror source structure: `src/pentis/core/engine.py` -> `tests/test_engine.py`
- Use `respx` for mocking HTTP calls
- Use `pytest.fixture` for shared setup
- Async tests use `pytest-asyncio` with `asyncio_mode = "auto"`

## What to Avoid
- Overly abstract class hierarchies (no Java-style patterns)
- ABCs/interfaces unless there are 3+ implementations
- Premature abstractions or utility modules for one-off logic
- `# type: ignore` without explanation
- Bare `except:` or `except Exception:`
