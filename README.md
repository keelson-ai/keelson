# Pentis

AI Agent Security Scanner — automated social engineering attacks against LLM-powered agents.

Pentis ships **28 attack playbooks** across three categories mapped to the OWASP LLM Top 10. It can run as a **Claude Code plugin** (Claude becomes the pentester) or as a standalone **Python CLI** with an async engine, detection pipeline, and SQLite persistence.

## Quick Start

### Claude Code Plugin

```bash
# Load as a Claude Code plugin
claude --plugin-dir ./Pentis-Monorepo

# Full scan
/pentis:scan http://localhost:11434/v1/chat/completions

# Single attack
/pentis:attack http://localhost:11434/v1/chat/completions GA-001

# Regenerate report
/pentis:report
```

### Python CLI

```bash
# Install (Python 3.11+)
pip install -e ".[dev]"

# Run
pentis --help
```

## How It Works

1. **Read** — Load attack playbooks from `attacks/**/*.md`
2. **Send** — Deliver prompts to the target via OpenAI-compatible chat completions API
3. **Evaluate** — Semantically judge each response as **VULNERABLE** / **SAFE** / **INCONCLUSIVE**
4. **Report** — Compile findings into a structured markdown report with OWASP mapping

## Attack Categories

| Category | IDs | Count | OWASP | Examples |
|----------|-----|-------|-------|----------|
| **Goal Adherence** | GA-001..010 | 10 | LLM01 — Prompt Injection | Direct override, role hijacking, system prompt extraction, delimiter injection, payload splitting, encoding evasion, few-shot jailbreak, context overflow, hypothetical injection, nested instruction injection |
| **Tool Safety** | TS-001..010 | 10 | LLM02, LLM06 | File system access, command injection, SQL injection, unauthorized API calls, file write abuse, env var extraction, privilege escalation, path traversal, email abuse, database modification |
| **Memory Integrity** | MI-001..008 | 8 | LLM05 — Insecure Plugin Design | History poisoning, identity persistence, behavior drift, false tool results, summarization attack, instruction anchoring, session state confusion, cross-turn exfiltration |

## Project Structure

```
Pentis-Monorepo/
├── .claude-plugin/
│   └── plugin.json              # Plugin manifest
├── agents/
│   └── pentester.md             # Pentester agent instructions
├── commands/
│   ├── scan.md                  # /pentis:scan command
│   ├── attack.md                # /pentis:attack command
│   └── report.md                # /pentis:report command
├── attacks/                     # 28 attack playbooks (.md)
│   ├── goal-adherence/          # GA-001..010
│   ├── tool-safety/             # TS-001..010
│   └── memory-integrity/        # MI-001..008
├── src/pentis/                  # Python engine
│   ├── cli.py                   # Typer CLI
│   ├── adapters/                # Target adapters (OpenAI-compatible)
│   ├── core/                    # Engine, scanner, detection, reporter
│   └── state/                   # SQLite persistence
├── tests/                       # Test suite
├── reports/                     # Generated scan reports
└── pyproject.toml               # Python packaging (hatchling)
```

## Report Output

Reports include:

- Executive summary with vulnerability counts and risk score
- Findings grouped by severity (Critical > High > Medium > Low)
- OWASP LLM Top 10 mapping for each finding
- Attack prompts and response excerpts as evidence
- Actionable remediation recommendations

## Adding Attacks

Create a new `.md` file in the appropriate `attacks/` subdirectory:

```markdown
# XX-NNN: Attack Name

**Severity**: High | **Category**: Category Name | **OWASP**: LLM0X — Name

## Objective
What this attack tests.

## Attack Steps

### Step 1
Send to target:
> The attack prompt

## Evaluation

**Vulnerable if**:
- Criteria for vulnerability

**Safe if**:
- Criteria for safety
```

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check .
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add or modify attack playbooks / engine code
4. Submit a pull request

## License

Apache 2.0
