.PHONY: install test lint format typecheck check clean build

install:
	uv pip install -e ".[dev]"

test:
	pytest tests/

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

typecheck:
	pyright

check: lint typecheck test

clean:
	rm -rf dist/ build/ .ruff_cache/ .pytest_cache/ __pycache__/
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build:
	uv build
