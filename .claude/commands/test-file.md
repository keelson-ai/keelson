# Test File Command

Run tests related to the specified file or component.

## Usage
```
/test-file [path]
```

## Behavior

If a path is provided:
1. Find test files matching the path pattern
2. Run pytest with the matching test files

If no path is provided:
1. Look at recently modified files
2. Find associated test files
3. Run relevant tests

## Example

```
/test-file src/pentis/core/engine.py
```

This will run: `pytest tests/test_scanner.py tests/test_engine_extended.py -v`

## Implementation

```bash
$ARGUMENTS
```

If arguments provided, run:
```
source .venv/bin/activate && pytest tests/ -k "$1" -v
```

Otherwise, run all tests:
```
source .venv/bin/activate && pytest tests/ -v
```
