# Pre-Commit Requirements

All commits MUST pass tests before being accepted.

## Before Every Commit
```bash
# Run full test suite
source .venv/bin/activate && pytest tests/ -v

# Verify package installs
pip install -e ".[dev]"
```

## Fixing Failures
```bash
# Run specific test
pytest tests/test_models.py -v

# Run with output
pytest tests/ -v -s
```

## Never
- Commit with failing tests
- Use `--no-verify` to bypass checks
- Skip test run on code changes
