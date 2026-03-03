# Test Coverage

When code changes are made, corresponding tests must be updated or added.

## When
Every code change that modifies behavior.

## Rules
- New features require new tests
- Bug fixes require regression tests
- Refactors must not break existing tests
- Template changes require schema validation tests

## Test Priorities
1. Business-critical flows (detection pipeline, scanner) — HIGH
2. User-facing features (CLI commands, reports) — HIGH
3. Error handling paths (HTTP errors, malformed responses) — MEDIUM
4. Edge cases (empty inputs, large responses) — MEDIUM
5. Utilities (helpers, formatters) — LOW if well-typed

## Test Patterns
- Test behavior, not implementation
- One assertion per test (when possible)
- Descriptive test names
- Arrange-Act-Assert pattern
- Mock external dependencies (use respx for httpx)
