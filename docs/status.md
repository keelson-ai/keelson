# Task Status

## F-c3ddId — Configure Ruff, Pyright, and pre-commit hooks

**Status**: ✅ Complete

### Changes Made

1. **`pyproject.toml`** — Added `[tool.ruff.lint]` section with `select = ["E", "F", "I", "UP"]`. The `[tool.ruff]` (line-length 100, target py311) and `[tool.pyright]` (strict mode, pythonVersion 3.11) sections were already present from prior initialization.

2. **`.pre-commit-config.yaml`** (created) — Configures three hook repos:
   - `pre-commit/pre-commit-hooks` v4.6.0: trailing-whitespace, end-of-file-fixer, check-yaml, check-toml
   - `astral-sh/ruff-pre-commit` v0.5.0: ruff-format + ruff --fix
   - `RobertCraigie/pyright-python` v1.1.377: pyright

3. **`Makefile`** — Already had `make lint` (`ruff check src/ tests/`) and `make typecheck` (`pyright`) targets from prior work. No changes needed.

### Setup Instructions

```bash
# Install pre-commit (requires pre-commit package)
pip install pre-commit
pre-commit install

# Manual invocation
make lint
make typecheck
make check  # runs lint + typecheck + test
```

### Notes

- `uv` is not available in the CI execution environment; install locally with `pip install uv` or use `pip install -e ".[dev]"` directly.
- Pre-commit hooks run on staged files only; use `pre-commit run --all-files` for a full check.
