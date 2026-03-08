# Contributing to Keelson

Thanks for your interest in contributing to Keelson! Here's how to get started.

## Quick Start

```bash
git clone https://github.com/keelson-ai/keelson.git
cd keelson
pip install -e ".[dev]"
pytest
```

## Ways to Contribute

### Add Probe Playbooks (easiest)

Probe playbooks are YAML files — no Python needed. Create a new `.yaml` file in the appropriate `probes/` subdirectory:

```yaml
id: GA-067
name: Your Probe Name
severity: high
category: goal_adherence
owasp_id: "LLM01 — Prompt Injection"
objective: >
  What this probe tests (1-3 sentences).
turns:
  - role: user
    content: >
      The prompt to send to the target agent.
evaluation:
  vulnerable_if:
    - Agent complies with the probe
  safe_if:
    - Agent refuses or maintains boundaries
  inconclusive_if:
    - Response is ambiguous
```

**Rules for playbooks:**

- Must be fully self-contained — no vendor-specific references
- Use `example.com` for prober domains (RFC 2606)
- No real credentials or PII — use obvious fakes (`sk-live-abc123xyz`, `hunter2`)
- Copy the file to `src/keelson/probes/<category>/` to keep the mirror in sync

See `.claude/rules/probe-playbook-standards.md` for the full spec.

### Add Adapters

Implement the `BaseAdapter` interface in `src/keelson/adapters/`:

```python
class MyAdapter(BaseAdapter):
    async def _send_messages_impl(self, messages, model):
        # Send messages to target, return (response_text, status_code)
        ...

    async def health_check(self) -> bool:
        ...

    async def close(self) -> None:
        ...
```

### Improve Detection

Enhance pattern matching in `src/keelson/core/detection.py` or add new evaluation strategies.

### Report Bugs

Open an issue with:

- What you expected
- What happened
- Steps to reproduce
- Keelson version (`keelson --version`)

## Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Make your changes
4. Run checks:

   ```bash
   ruff check src/ tests/
   ruff format --check src/ tests/
   pytest
   ```

5. Submit a pull request

## Code Style

- Python 3.11+, type annotations on public functions
- `ruff` for linting and formatting (line-length 100)
- `pyright` strict mode
- `pytest` with `pytest-asyncio` for tests
- Use `httpx` for HTTP, `pathlib.Path` for paths

## Commit Messages

```text
<type>: <description>

Types: feat, fix, refactor, test, docs, chore
```

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
