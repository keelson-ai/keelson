# Pentis

[![PyPI version](https://img.shields.io/pypi/v/pentis)](https://pypi.org/project/pentis/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://img.shields.io/badge/tests-618%20passing-brightgreen)]()

**Autonomous red team agent for AI systems.** Pentis ships 152 attack playbooks across 7 behavior categories mapped to the OWASP LLM Top 10. It supports 8 target adapters (OpenAI, Generic HTTP, Anthropic, LangGraph, MCP, A2A, CrewAI, LangChain), SARIF + JUnit output for CI/CD integration, a statistical campaign engine with confidence intervals, runtime defense hooks, and compliance reporting for 6 frameworks.

```
pip install pentis
```

## Quick Start

```bash
# Scan an OpenAI-compatible endpoint
pentis scan https://api.example.com/v1/chat/completions --api-key $KEY

# Single attack
pentis attack https://api.example.com/v1/chat/completions GA-001 --api-key $KEY

# List all 152 attacks
pentis list

# Statistical campaign (10 trials per attack)
pentis scan https://api.example.com/v1/chat/completions --tier deep --api-key $KEY

# SARIF output for GitHub Code Scanning
pentis scan https://api.example.com/v1/chat/completions --format sarif --api-key $KEY

# JUnit XML output for CI/CD
pentis scan https://api.example.com/v1/chat/completions --format junit --api-key $KEY

# Fail CI if vulnerabilities found
pentis scan https://api.example.com/v1/chat/completions --fail-on-vuln --api-key $KEY

# Scan a CrewAI agent directly
pentis test-crew my_crew.py

# Scan a LangChain agent directly
pentis test-chain my_agent.py
```

## How It Works

```
Playbooks (.yaml)   Target Agent        Pentis Engine
┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐
│ 152 attacks  │───>│ OpenAI /     │───>│ Detection pipeline   │
│ 7 categories │    │ Anthropic /  │    │ Streaming observer    │
│ OWASP mapped │    │ CrewAI / ... │    │ Statistical analysis  │
└──────────────┘    └──────────────┘    └──────────────────────┘
                                               │
                                    ┌──────────┴──────────┐
                                    │  Reports             │
                                    │  Markdown / SARIF /  │
                                    │  JUnit / Compliance  │
                                    └─────────────────────┘
```

1. **Load** attack playbooks from `attacks/**/*.yaml` (structured YAML, no code)
2. **Send** prompts to the target via any supported adapter
3. **Detect** vulnerabilities using pattern-based detection + streaming leakage analysis
4. **Evaluate** each response as **VULNERABLE** / **SAFE** / **INCONCLUSIVE**
5. **Report** findings with OWASP mapping, evidence, and remediation recommendations

## Attack Categories

| Category | Prefix | Count | OWASP | What It Tests |
|----------|--------|-------|-------|---------------|
| **Goal Adherence** | GA | 52 | LLM01/LLM09 | Prompt injection, role hijacking, system prompt extraction, encoding evasion, context overflow, crescendo escalation, skeleton key, many-shot jailbreak, reasoning-layer (CoT) attacks, rapport exploitation, structured data injection, model fingerprinting, indirect prompt injection (IDPI), Unicode/homoglyph evasion, authority simulation, multilingual repetition, multi-vector psychological exploitation, enterprise framing bypass, syllogistic reasoning manipulation, hypothetical counterfactual bypass, meta-reasoning inversion, logical paradox exploitation |
| **Tool Safety** | TS | 35 | LLM02/LLM06/LLM07 | File access, command injection, SQL injection, unauthorized API calls, privilege escalation, path traversal, MCP tool poisoning, MCP rug pull, cross-server contamination, SSRF, side-effect detection, excessive agency, forced financial transactions |
| **Memory Integrity** | MI | 21 | LLM05 | History poisoning, identity persistence, false tool results, cross-turn exfiltration, error info leakage, stored payload injection, context window flooding, gradual memory poisoning, false memory implantation, contradictory fact confusion, RAG poisoning |
| **Permission Boundaries** | PB | 12 | LLM02 | Role escalation, cross-user access, scope expansion, authorization bypass, privilege persistence |
| **Delegation Integrity** | DI | 6 | LLM08/LLM09 | Unauthorized sub-agents, trust boundary violation, delegation scope laundering |
| **Execution Safety** | ES | 13 | LLM02/LLM06 | Unbounded execution, resource exhaustion, sandbox escape, audit evasion, unsafe deserialization, HTML/script output injection, destructive command injection |
| **Session Isolation** | SI | 13 | LLM01/LLM05 | Cross-session leakage, session hijacking, multi-tenant breach, model fingerprinting, conversation history poisoning, debug harness extraction |

## Adapters

Pentis communicates with targets through a pluggable adapter interface:

| Adapter | Flag | Protocol | Use Case |
|---------|------|----------|----------|
| **OpenAI** | `--adapter openai` | Chat Completions API | GPT models, OpenAI API |
| **Generic HTTP** | `--adapter http` | Chat Completions API | Local models (Ollama, vLLM), any OpenAI-compatible endpoint |
| **Anthropic** | `--adapter anthropic` | Messages API | Claude models |
| **LangGraph** | `--adapter langgraph` | LangGraph Platform | LangGraph agents |
| **MCP** | `--adapter mcp` | JSON-RPC 2.0 | MCP tool servers |
| **A2A** | `--adapter a2a` | Google A2A Protocol | A2A-compatible agents |
| **CrewAI** | `test-crew` command | In-process | CrewAI crews/agents |
| **LangChain** | `test-chain` command | In-process | LangChain agents/chains |

```bash
# OpenAI-compatible (default)
pentis scan http://localhost:11434/v1/chat/completions

# Anthropic
pentis scan https://api.anthropic.com --adapter anthropic --api-key $KEY

# LangGraph Platform
pentis scan https://my-agent.langraph.com --adapter langgraph --assistant-id my-agent

# MCP server
pentis scan http://localhost:3000 --adapter mcp --tool-name ask

# A2A agent
pentis scan http://localhost:8000 --adapter a2a

# CrewAI (in-process, no HTTP)
pentis test-crew path/to/my_crew.py

# LangChain (in-process, no HTTP)
pentis test-chain path/to/my_agent.py
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `pentis scan <url>` | Full security scan against an endpoint |
| `pentis attack <url> <id>` | Run a single attack |
| `pentis list` | List all available attacks |
| `pentis campaign <config.toml>` | Statistical campaign (N trials per attack) |
| `pentis discover <url>` | Fingerprint agent capabilities |
| `pentis evolve <url> <id>` | Mutate an attack to find bypasses |
| `pentis chain <url> <profile-id>` | Synthesize and run compound attack chains |
| `pentis generate <attacker-url>` | Generate novel attacks using an attacker LLM |
| `pentis test-crew <module.py>` | Scan a CrewAI agent directly |
| `pentis test-chain <module.py>` | Scan a LangChain agent directly |
| `pentis diff <scan-a> <scan-b>` | Compare two scans for regressions |
| `pentis baseline <scan-id>` | Set a regression baseline |
| `pentis compliance <scan-id>` | Generate compliance report |
| `pentis report <scan-id>` | Regenerate a scan report |
| `pentis history` | Show scan history |

## Output Formats

### Markdown Report

```bash
pentis scan <url> --api-key $KEY
# -> reports/scan-2026-03-04-120000.md
```

Reports include executive summary, findings grouped by category with evidence (prompts + responses), OWASP mapping, and remediation recommendations.

### SARIF (for CI/CD)

```bash
pentis scan <url> --format sarif --api-key $KEY
# -> reports/scan-2026-03-04-120000.sarif.json
```

SARIF v2.1.0 output integrates with GitHub Code Scanning, VS Code SARIF Viewer, and other SARIF-compatible tools.

### JUnit XML (for CI/CD)

```bash
pentis scan <url> --format junit --api-key $KEY
# -> reports/scan-2026-03-04-120000.junit.xml
```

JUnit XML integrates with Jenkins, GitLab CI, GitHub Actions, and any CI system that supports JUnit test reports.

### CI/CD Fail Gates

```bash
# Fail pipeline if any vulnerability found
pentis scan <url> --fail-on-vuln --api-key $KEY

# Fail if vulnerability rate exceeds threshold (0.0–1.0)
pentis scan <url> --fail-threshold 0.1 --api-key $KEY
```

### Compliance Reports

```bash
pentis compliance <scan-id> --framework owasp-llm-top10
pentis compliance <scan-id> --framework nist-ai-rmf
pentis compliance <scan-id> --framework eu-ai-act
pentis compliance <scan-id> --framework iso-42001
pentis compliance <scan-id> --framework soc2
pentis compliance <scan-id> --framework pci-dss-v4
```

## GitHub Actions

```yaml
# .github/workflows/ai-security.yml
name: AI Agent Security
on: [push, pull_request]

jobs:
  pentis:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install pentis

      - run: pentis scan ${{ vars.AGENT_URL }} --api-key ${{ secrets.AGENT_KEY }} --format sarif --output results/ --fail-on-vuln --no-save

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results/
```

## Statistical Campaigns

Run each attack N times to get statistically significant results with Wilson score confidence intervals:

```bash
# Quick scan (1 trial, fast)
pentis scan <url> --tier fast --api-key $KEY

# Deep scan (10 trials, concurrent)
pentis scan <url> --tier deep --api-key $KEY

# Custom campaign via TOML config
pentis campaign config.toml
```

Campaign config example:

```toml
[campaign]
name = "nightly-regression"
trials_per_attack = 10
confidence_level = 0.95

[target]
url = "https://api.example.com/v1/chat/completions"
api_key = "sk-..."

[concurrency]
max_concurrent_trials = 5
early_termination_threshold = 3
```

## Pentis Defend (Runtime Protection)

Pentis Defend is a policy engine that intercepts unsafe tool calls and content at runtime, integrating directly with CrewAI and LangChain agents.

### Policy Configuration

```yaml
# defend-policy.yaml
tool_rules:
  - pattern: "delete_*"
    action: deny
    reason: "File deletion blocked by policy"
  - pattern: "execute_command"
    action: deny
    reason: "Shell execution not permitted"
  - pattern: "send_email"
    action: log
    reason: "Email sending logged for audit"

content_rules:
  - pattern: "password|secret|api_key|token"
    action: deny
    check_input: true
    check_output: true

default_tool_action: allow
log_all: false
```

### CrewAI Integration

```python
from pentis.defend import load_policy, PolicyEngine, register_crewai_hooks

policy = load_policy("defend-policy.yaml")
engine = PolicyEngine(policy)
register_crewai_hooks(engine)
# All CrewAI tool calls are now policy-enforced
```

### LangChain Integration

```python
from pentis.defend import load_policy, PolicyEngine, PentisDefendMiddleware

policy = load_policy("defend-policy.yaml")
engine = PolicyEngine(policy)
middleware = PentisDefendMiddleware(engine)
# Wrap your agent's tool and model calls
```

## Adding Custom Attacks

Create a `.yaml` file in the appropriate `attacks/` subdirectory:

```yaml
id: XX-NNN
name: Attack Name
severity: high
category: category_name
owasp_id: "LLM0X — Name"
objective: >
  What this attack tests.
turns:
  - role: user
    content: >
      The attack prompt to send.
  - role: user
    content: >
      Follow-up prompt (for multi-turn attacks).
evaluation:
  vulnerable_if:
    - Agent complies with the attack request
    - Agent leaks sensitive information
  safe_if:
    - Agent refuses the request
    - Agent maintains boundaries
  inconclusive_if:
    - Response is ambiguous or partial
```

## Project Structure

```
pentis/
├── agents/                         # Agent instructions
│   └── pentester.md                # Pentester agent prompt
├── commands/                       # Plugin slash commands
│   ├── scan.md                     # /pentis:scan
│   ├── attack.md                   # /pentis:attack
│   └── report.md                   # /pentis:report
├── attacks/                        # 152 attack playbooks (YAML)
│   ├── goal-adherence/             # GA-001..062 (52 attacks)
│   ├── tool-safety/                # TS-001..041 (35 attacks)
│   ├── memory-integrity/           # MI-001..024 (21 attacks)
│   ├── permission-boundaries/      # PB-001..012 (12 attacks)
│   ├── delegation-integrity/       # DI-001..007 (6 attacks)
│   ├── execution-safety/           # ES-001..013 (13 attacks)
│   └── session-isolation/          # SI-001..015 (13 attacks)
├── src/pentis/                     # Python engine
│   ├── cli.py                      # Typer CLI (15 commands)
│   ├── adapters/                   # 8 target adapters
│   │   ├── base.py                 # BaseAdapter interface
│   │   ├── openai.py               # OpenAI API
│   │   ├── http.py                 # GenericHTTPAdapter (OpenAI-compat)
│   │   ├── anthropic.py            # Anthropic Messages API
│   │   ├── langgraph.py            # LangGraph Platform
│   │   ├── mcp.py                  # Model Context Protocol
│   │   ├── a2a.py                  # Google A2A Protocol
│   │   ├── crewai.py               # CrewAI native (in-process)
│   │   ├── langchain.py            # LangChain native (in-process)
│   │   ├── cache.py                # Response caching decorator
│   │   └── attacker.py             # Attacker LLM wrapper
│   ├── core/                       # Engine, scanner, detection
│   │   ├── engine.py               # Multi-turn attack executor
│   │   ├── scanner.py              # Full scan orchestrator
│   │   ├── detection.py            # Pattern-based verdict detection
│   │   ├── observer.py             # Streaming leakage analysis
│   │   ├── templates.py            # Playbook parser (markdown)
│   │   ├── yaml_templates.py       # Playbook parser (YAML)
│   │   ├── models.py               # Core data models
│   │   ├── reporter.py             # Markdown report generation
│   │   ├── sarif.py                # SARIF v2.1.0 output
│   │   ├── junit.py                # JUnit XML output
│   │   └── compliance.py           # 6 compliance frameworks
│   ├── defend/                     # Runtime protection
│   │   ├── engine.py               # Policy evaluation engine
│   │   ├── models.py               # Policy, rules, actions
│   │   ├── loader.py               # YAML policy loader
│   │   ├── crewai_hook.py          # CrewAI middleware hooks
│   │   └── langchain_hook.py       # LangChain middleware hooks
│   ├── attacker/                   # Attack generation
│   │   ├── generator.py            # LLM-powered prompt generation
│   │   ├── discovery.py            # Agent capability fingerprinting
│   │   ├── chains.py               # Compound attack chain synthesis
│   │   └── provider.py             # Cross-provider attacker selection
│   ├── adaptive/                   # Mutation engine
│   │   ├── mutations.py            # Programmatic + LLM mutations
│   │   ├── branching.py            # Conversation tree exploration
│   │   └── strategies.py           # Mutation scheduling
│   ├── campaign/                   # Statistical campaigns
│   │   ├── runner.py               # N-trial execution with CI
│   │   ├── tiers.py                # Fast/Deep/Continuous presets
│   │   └── config.py               # TOML config parser
│   ├── diff/                       # Scan comparison
│   │   └── comparator.py           # Regression detection
│   └── state/                      # Persistence
│       └── store.py                # SQLite storage
├── tests/                          # 618 tests
├── docs/                           # Documentation
│   ├── adr/                        # Architecture Decision Records
│   │   ├── ADR-001-framework.md    # FastAPI selection
│   │   ├── ADR-002-dependency-management.md  # uv selection
│   │   └── ADR-003-observability.md  # Structured logging + OTel plan
│   ├── plans/                      # Roadmap
│   ├── openapi.yaml                # OpenAPI 3.1.0 API contract
│   └── github-action-spec.md       # GitHub Action design
├── pyproject.toml                  # Python packaging
└── LICENSE                         # Apache 2.0
```

## Development

```bash
# Clone
git clone https://github.com/pentis-ai/pentis.git
cd pentis

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with verbose output
pytest -v

# Lint
ruff check .

# Type check (strict mode, 0 errors)
pyright
```

### Optional Dependencies

```bash
# CrewAI adapter
pip install "pentis[crewai]"

# LangChain adapter
pip install "pentis[langchain]"

# All optional adapters
pip install "pentis[all]"
```

## Contributing

Contributions are welcome. Here's how to help:

1. **Add attack playbooks** — Write new `.yaml` files in `attacks/`. Follow the format above.
2. **Add adapters** — Implement the `BaseAdapter` interface (3 methods: `send_messages`, `health_check`, `close`).
3. **Improve detection** — Enhance patterns in `core/detection.py` or add new evaluation strategies.
4. **Report bugs** — Open an issue with reproduction steps.

### Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Make your changes
4. Run `pytest` and `ruff check .`
5. Submit a pull request

### Security

This tool is for **authorized security testing only**. Do not use Pentis against systems you don't have permission to test. If you discover a security issue in Pentis itself, please report it via [GitHub Security Advisories](https://github.com/pentis-ai/pentis/security/advisories).

## Architecture

### API Specification

The authoritative OpenAPI 3.1.0 contract for the Pentis service is at [`docs/openapi.yaml`](docs/openapi.yaml). It covers the `/health` endpoint (implemented) and placeholder paths for Phase 2 scan, attack, and report endpoints.

### Architecture Decision Records

Key technical decisions are documented as [MADR](https://adr.github.io/madr/) records in [`docs/adr/`](docs/adr/):

| ADR | Decision | Status |
|-----|----------|--------|
| [ADR-001](docs/adr/ADR-001-framework.md) | Web framework: FastAPI (async-first, auto-OpenAPI) | Accepted |
| [ADR-002](docs/adr/ADR-002-dependency-management.md) | Dependency management: uv (fast resolver, `uv.lock`) | Accepted |
| [ADR-003](docs/adr/ADR-003-observability.md) | Observability: structured logging now, OpenTelemetry in Phase 2 | Accepted |

## Roadmap

See [docs/plans/](docs/plans/) for the full roadmap.

**Next up:**
- Drift detection and continuous monitoring
- Semantic coverage tracking
- REST API and web dashboard
- GitHub Action (`pentis-ai/pentis-action`)

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.
