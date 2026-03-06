# Pentis

[![PyPI version](https://img.shields.io/pypi/v/pentis)](https://pypi.org/project/pentis/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://img.shields.io/badge/tests-703%20passing-brightgreen)]()

**Autonomous red team agent for AI systems.** Pentis ships 205 attack playbooks across 13 behavior categories mapped to the OWASP LLM Top 10. It supports 9 target adapters (OpenAI, Generic HTTP, Anthropic, LangGraph, MCP, A2A, CrewAI, LangChain, SiteGPT), SARIF + JUnit output for CI/CD integration, a statistical campaign engine with confidence intervals, runtime defense hooks, and compliance reporting for 6 frameworks.

```
pip install pentis
```

## Quick Start

```bash
# Scan an OpenAI-compatible endpoint
pentis scan https://api.example.com/v1/chat/completions --api-key $KEY

# Parallel pipeline scan with verification
pentis pipeline-scan https://api.example.com/v1/chat/completions --api-key $KEY

# Adaptive smart scan (discover → classify → execute with memo feedback)
pentis smart-scan https://api.example.com/v1/chat/completions --api-key $KEY

# Single attack
pentis attack https://api.example.com/v1/chat/completions GA-001 --api-key $KEY

# List all 205 attacks
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
│ 205 attacks  │───>│ 9 Adapters   │───>│ Scan Modes           │
│ 13 categories│    │ OpenAI /     │    │  scan (sequential)   │
│ OWASP mapped │    │ Anthropic /  │    │  pipeline (parallel) │
└──────────────┘    │ MCP / A2A /  │    │  smart (adaptive)    │
                    │ SiteGPT /... │    └──────────┬───────────┘
  Orchestrators     └──────────────┘               │
┌──────────────┐                        ┌──────────┴──────────┐
│ PAIR         │───────────────────────>│  Detection pipeline  │
│ Crescendo    │                        │  Pattern + LLM Judge │
│ Mutations    │                        │  Verification pass   │
│ (13 types)   │                        │  Memo feedback loop  │
└──────────────┘                        └──────────┬──────────┘
                                                   │
                                        ┌──────────┴──────────┐
                                        │  Reports             │
                                        │  Markdown / SARIF /  │
                                        │  JUnit / Compliance  │
                                        └─────────────────────┘
```

1. **Load** attack playbooks from `attacks/**/*.yaml` (structured YAML, no code)
2. **Send** prompts to the target via any supported adapter
3. **Detect** vulnerabilities using pattern detection, LLM-as-judge scoring, or combined mode
4. **Orchestrate** advanced strategies: PAIR iterative refinement, Crescendo gradual escalation, 13 mutation types
5. **Evaluate** each response as **VULNERABLE** / **SAFE** / **INCONCLUSIVE**
6. **Report** findings with OWASP mapping, evidence, and remediation recommendations

## Attack Categories

| Category | Prefix | Count | OWASP | What It Tests |
|----------|--------|-------|-------|---------------|
| **Goal Adherence** | GA | 54 | LLM01/LLM09 | Prompt injection, role hijacking, system prompt extraction, encoding evasion, context overflow, crescendo escalation, skeleton key, many-shot jailbreak, reasoning-layer (CoT) attacks, rapport exploitation, structured data injection, model fingerprinting, indirect prompt injection (IDPI), Unicode/homoglyph evasion, authority simulation, multilingual repetition, multi-vector psychological exploitation, enterprise framing bypass, syllogistic reasoning manipulation, hypothetical counterfactual bypass, meta-reasoning inversion, logical paradox exploitation, response template hijacking, shared resource injection |
| **Tool Safety** | TS | 38 | LLM02/LLM06/LLM07 | File access, command injection, SQL injection, unauthorized API calls, privilege escalation, path traversal, MCP tool poisoning, MCP rug pull, cross-server contamination, SSRF, side-effect detection, excessive agency, forced financial transactions, two-phase URL exfiltration, URI scheme redirect, forced URL opening |
| **Memory Integrity** | MI | 23 | LLM05 | History poisoning, identity persistence, false tool results, cross-turn exfiltration, error info leakage, stored payload injection, context window flooding, gradual memory poisoning, false memory implantation, contradictory fact confusion, RAG poisoning, natural language sleeper triggers, collapsed UI content poisoning |
| **Permission Boundaries** | PB | 12 | LLM02 | Role escalation, cross-user access, scope expansion, authorization bypass, privilege persistence |
| **Delegation Integrity** | DI | 7 | LLM08/LLM09 | Unauthorized sub-agents, trust boundary violation, delegation scope laundering, cross-agent lateral movement |
| **Execution Safety** | ES | 13 | LLM02/LLM06 | Unbounded execution, resource exhaustion, sandbox escape, audit evasion, unsafe deserialization, HTML/script output injection, destructive command injection |
| **Session Isolation** | SI | 13 | LLM01/LLM05 | Cross-session leakage, session hijacking, multi-tenant breach, model fingerprinting, conversation history poisoning, debug harness extraction |
| **Cognitive Architecture** | CA | 8 | LLM01/LLM09 | Chain-of-thought poisoning, reasoning manipulation, meta-cognitive attacks |
| **Conversational Exfiltration** | EX | 8 | LLM01/LLM06 | Data extraction via conversation, behavioral fingerprinting |
| **Supply Chain Language** | SL | 8 | LLM03/LLM05 | RAG document injection, dependency confusion, plugin poisoning |
| **Output Weaponization** | OW | 7 | LLM02/LLM06 | Backdoor code generation, malicious output crafting |
| **Temporal Persistence** | TP | 7 | LLM05/LLM08 | Delayed action injection, time-based persistence |
| **Multi-Agent Security** | MA | 7 | LLM08/LLM09 | Agent impersonation, cross-agent attacks |

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
| **SiteGPT** | `--adapter sitegpt` | WebSocket / REST | SiteGPT chatbots |

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

# SiteGPT chatbot (WebSocket or REST)
pentis scan https://widget.sitegpt.ai --adapter sitegpt --chatbot-id YOUR_CHATBOT_ID
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `pentis scan <url>` | Full security scan (sequential, with dynamic reorder) |
| `pentis pipeline-scan <url>` | Parallel scan with checkpoint/resume and verification |
| `pentis smart-scan <url>` | Adaptive scan: discover, classify, memo-guided sessions |
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
├── attacks/                        # 205 attack playbooks (YAML)
│   ├── goal-adherence/             # GA (54 attacks)
│   ├── tool-safety/                # TS (38 attacks)
│   ├── memory-integrity/           # MI (23 attacks)
│   ├── session-isolation/          # SI (13 attacks)
│   ├── execution-safety/           # ES (13 attacks)
│   ├── permission-boundaries/      # PB (12 attacks)
│   ├── cognitive-architecture/     # CA (8 attacks)
│   ├── conversational-exfiltration/# EX (8 attacks)
│   ├── supply-chain-language/      # SL (8 attacks)
│   ├── delegation-integrity/       # DI (7 attacks)
│   ├── multi-agent-security/       # MA (7 attacks)
│   ├── output-weaponization/       # OW (7 attacks)
│   └── temporal-persistence/       # TP (7 attacks)
├── src/pentis/                     # Python engine
│   ├── cli/                        # Typer CLI (17 commands)
│   │   ├── __init__.py             # App setup, shared helpers
│   │   ├── commands.py             # Command module registration
│   │   ├── scan_commands.py        # scan, pipeline-scan, smart-scan, attack
│   │   ├── ops_commands.py         # list, report, history, diff, discover, baseline, compliance
│   │   └── advanced_commands.py    # campaign, evolve, chain, generate, test-crew, test-chain
│   ├── adapters/                   # 9 target adapters
│   │   ├── base.py                 # BaseAdapter interface
│   │   ├── openai.py               # OpenAI API
│   │   ├── http.py                 # GenericHTTPAdapter (OpenAI-compat)
│   │   ├── anthropic.py            # Anthropic Messages API
│   │   ├── langgraph.py            # LangGraph Platform
│   │   ├── mcp.py                  # Model Context Protocol
│   │   ├── a2a.py                  # Google A2A Protocol
│   │   ├── crewai.py               # CrewAI native (in-process)
│   │   ├── langchain.py            # LangChain native (in-process)
│   │   ├── sitegpt.py              # SiteGPT (WebSocket / REST)
│   │   ├── cache.py                # Response caching decorator
│   │   └── attacker.py             # Attacker LLM wrapper
│   ├── core/                       # Engine, scanner, detection
│   │   ├── engine.py               # Multi-turn attack executor
│   │   ├── execution.py            # Shared primitives (sequential, parallel, verify)
│   │   ├── scanner.py              # Sequential scan with dynamic reorder
│   │   ├── pipeline.py             # Parallel scan with checkpoint/resume
│   │   ├── smart_scan.py           # Adaptive scan with memo feedback
│   │   ├── memo.py                 # Memo table for technique tracking
│   │   ├── strategist.py           # LLM-based target classification
│   │   ├── detection.py            # Pattern-based verdict detection
│   │   ├── observer.py             # Streaming leakage analysis
│   │   ├── llm_judge.py             # LLM-as-judge semantic evaluation
│   │   ├── templates.py            # Playbook parser (markdown)
│   │   ├── yaml_templates.py       # Playbook parser (YAML)
│   │   ├── models.py               # Core data models
│   │   ├── reporter.py             # Markdown report generation
│   │   ├── executive_report.py     # Executive summary format
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
│   ├── adaptive/                   # Mutation engine + orchestrators
│   │   ├── mutations.py            # 13 programmatic + LLM mutations
│   │   ├── branching.py            # Conversation tree exploration
│   │   ├── attack_tree.py          # Attack tree data structures
│   │   ├── pair.py                 # PAIR iterative refinement orchestrator
│   │   ├── crescendo.py            # Crescendo gradual escalation orchestrator
│   │   └── strategies.py           # Mutation scheduling
│   ├── campaign/                   # Statistical campaigns
│   │   ├── runner.py               # N-trial execution with CI
│   │   ├── tiers.py                # Fast/Deep/Continuous presets
│   │   ├── scheduler.py            # Campaign scheduling
│   │   └── config.py               # TOML config parser
│   ├── diff/                       # Scan comparison
│   │   └── comparator.py           # Regression detection
│   └── state/                      # Persistence
│       ├── base.py                 # Storage base interface
│       └── store.py                # SQLite storage
├── tests/                          # 703 tests
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
2. **Add adapters** — Implement the `BaseAdapter` interface (3 required methods: `send_messages`, `health_check`, `close`; optional: `reset_session`).
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

### Flow Diagrams

#### Core Scan Pipeline (Sequential)

```mermaid
flowchart TD
    A[Load Playbooks] --> B[Send Prompts via Adapter]
    B --> C[Collect Evidence]
    C --> D[Detection Pipeline<br/>Pattern / LLM Judge / Combined]
    D --> E{Verdict?}
    E -->|VULNERABLE| DP{Deep Probe<br/>enabled?}
    DP -->|Yes| BRANCH[Explore follow-up paths<br/>via conversation branching]
    BRANCH --> F[Record Finding + Probe Findings]
    DP -->|No| F
    E -->|SAFE| F[Record Finding]
    E -->|INCONCLUSIVE| F
    F --> G{More Attacks?}
    G -->|Yes| H[Dynamic Reorder<br/>by Vuln Categories]
    H --> B
    G -->|No| I[Generate Report]

    style E fill:#f9f,stroke:#333
    style I fill:#9f9,stroke:#333
    style BRANCH fill:#fde8e8,stroke:#333
```

#### Pipeline Scan (Parallel + Checkpoint + Verify)

```mermaid
flowchart TD
    subgraph Phase1[Phase 1: Load]
        L[Load Playbooks] --> CP{Checkpoint<br/>exists?}
        CP -->|Yes| RESUME[Resume from checkpoint<br/>skip completed attacks]
        CP -->|No| ALL[All templates]
    end

    subgraph Phase2[Phase 2: Parallel Execution]
        RESUME --> SEM[Semaphore-based concurrency<br/>max_concurrent attacks]
        ALL --> SEM
        SEM --> EX1[Attack 1]
        SEM --> EX2[Attack 2]
        SEM --> EXN[Attack N]
        EX1 --> COLL[Collect Findings]
        EX2 --> COLL
        EXN --> COLL
    end

    subgraph Phase3[Phase 3: Verification]
        COLL --> VULN[Filter VULNERABLE]
        VULN --> RE[Re-probe each finding]
        RE --> CONF{Agent complies<br/>again?}
        CONF -->|Yes| CONFIRMED[VULNERABLE confirmed]
        CONF -->|Refused| DOWN[Downgrade to INCONCLUSIVE]
    end

    subgraph Phase4[Phase 4: Report]
        CONFIRMED --> MERGE[Merge verified findings]
        DOWN --> MERGE
        MERGE --> RPT[Generate Report]
    end

    style Phase1 fill:#e8f4fd,stroke:#333
    style Phase2 fill:#fdf8e8,stroke:#333
    style Phase3 fill:#fde8e8,stroke:#333
    style Phase4 fill:#e8fde8,stroke:#333
```

#### Smart Scan with Memoization

```mermaid
flowchart TD
    subgraph Phase1[Phase 1: Discovery]
        P1[8 Capability Probes] --> P1R[Agent Profile]
    end

    subgraph Phase2[Phase 2: Classification]
        P1R --> CL[Classify Target Type]
        CL --> TP[Target Profile<br/>types, tools, memory, refusal style]
    end

    subgraph Phase3[Phase 3: Attack Selection]
        TP --> SEL[Select Relevant Attacks]
        SEL --> GRP[Group into Sessions by Category]
    end

    subgraph Phase4[Phase 4: Execute with Memo]
        GRP --> MEMO[Initialize Memo Table]
        MEMO --> SESS[Execute Session]
        SESS --> REC[Record Finding → Memo]
        REC --> REORDER[Reorder Remaining Sessions<br/>by Memo-Informed Scores]
        REORDER --> ADAPT{Adapt Plan?}
        ADAPT -->|Escalate/De-escalate| SESS
        ADAPT -->|Done| SUM[Final Memo Summary]
    end

    style Phase1 fill:#e8f4fd,stroke:#333
    style Phase2 fill:#fde8e8,stroke:#333
    style Phase3 fill:#e8fde8,stroke:#333
    style Phase4 fill:#fdf8e8,stroke:#333
```

#### Memo Feedback Loop

```mermaid
flowchart LR
    subgraph Record
        F[Finding] --> IT[Infer Techniques<br/>authority, roleplay, etc.]
        IT --> CO[Classify Outcome<br/>complied / partial / refused]
        CO --> EL[Extract Leaked Info<br/>tools, paths, URLs, env vars]
        EL --> MT[(Memo Table)]
    end

    subgraph Query
        MT --> EFF[Effective Techniques<br/>VULNERABLE → weight 1.0]
        MT --> PROM[Promising Techniques<br/>INCONCLUSIVE → weight 0.3]
        MT --> DEAD[Dead-End Techniques<br/>SAFE-only → penalize]
        MT --> CROSS[Cross-Category Signal<br/>global score × 0.5]
    end

    subgraph Apply
        EFF --> SCORE[Score & Reorder<br/>Next Session's Attacks]
        PROM --> SCORE
        DEAD --> SCORE
        CROSS --> SCORE
    end

    style MT fill:#f9f,stroke:#333
```

#### Attack Tree Execution

```mermaid
flowchart TD
    ROOT[Root Prompt] --> SEND[Send to Target]
    SEND --> CLASS{Classify Response}

    CLASS -->|Compliance| VULN{Vulnerable?}
    CLASS -->|Partial| BR_P[Select Branch<br/>for PARTIAL]
    CLASS -->|Refusal| BR_R[Select Branch<br/>for REFUSAL]

    VULN -->|Yes| STOP[Stop — Vulnerability Found]
    VULN -->|No| BR_C[Select Branch<br/>for COMPLIANCE]

    BR_P --> MEMO_SEL[Memo-Informed Selection<br/>Prefer effective techniques<br/>Avoid dead ends]
    BR_R --> MEMO_SEL
    BR_C --> MEMO_SEL

    MEMO_SEL --> NEXT[Execute Next Prompt]
    NEXT --> CLASS2{Classify Response}
    CLASS2 -->|Compliance| VULN2{Vulnerable?}
    CLASS2 -->|Partial/Refusal| DEEPER{Max Depth?}

    VULN2 -->|Yes| STOP
    VULN2 -->|No| DEEPER
    DEEPER -->|No| MEMO_SEL
    DEEPER -->|Yes| FINAL[Final Verdict]

    FINAL --> REC_MEMO[Record Result → Memo Table]

    style STOP fill:#f99,stroke:#333
    style MEMO_SEL fill:#f9f,stroke:#333
    style REC_MEMO fill:#9f9,stroke:#333
```

#### Detection Pipeline

```mermaid
flowchart TD
    EV[Evidence: prompts + responses] --> MODE{Scoring<br/>Method?}

    MODE -->|PATTERN| SE[Side Effects Check<br/>Tool call wrappers + dangerous names]
    MODE -->|COMBINED| BOTH_PATH[Run Pattern + LLM Judge in parallel]
    MODE -->|LLM_JUDGE| JUDGE_ONLY[LLM-as-Judge Only]

    SE -->|Match| V1[VULNERABLE]

    SE -->|No match| SIG[Collect Signals]
    SIG --> VM[vulnerable_if matches]
    SIG --> SM[safe_if matches]
    SIG --> RF[Refusal phrase matches]

    VM --> COMB{Both vuln<br/>and safe?}
    SM --> COMB
    RF --> COMB

    COMB -->|Yes, multi-step| LAST[Check last step only]
    LAST -->|Vuln without refusal| V2[VULNERABLE<br/>Bypassed initial refusal]
    LAST -->|Has refusal| SAFE1[SAFE]

    COMB -->|Yes, single-step| DISC[Substantial disclosure?<br/>Code blocks / structured lists]
    DISC -->|Yes| V3[VULNERABLE<br/>Disclosed despite refusal]
    DISC -->|No| SAFE1

    COMB -->|Only vuln| V4[VULNERABLE]
    COMB -->|Only safe/refusal| SAFE2[SAFE]
    COMB -->|Neither| LEAK{High-confidence<br/>leakage signals?}
    LEAK -->|Yes| V5[VULNERABLE]
    LEAK -->|No| INC[INCONCLUSIVE]

    JUDGE_ONLY --> JR[Judge LLM evaluates<br/>objective + evidence + criteria]
    JR --> JV[VERDICT + confidence + reasoning]

    BOTH_PATH --> PAT_V[Pattern Verdict]
    BOTH_PATH --> JDG_V[Judge Verdict]
    PAT_V --> RESOLVE{Resolve<br/>Disagreement}
    JDG_V --> RESOLVE
    RESOLVE -->|Both agree| BOOST[Use verdict<br/>confidence + 0.15]
    RESOLVE -->|Pattern VULN, Judge SAFE| TRUST_J1[Trust Judge → SAFE<br/>reduces false positives]
    RESOLVE -->|Pattern SAFE, Judge VULN| CONF{Judge<br/>confidence ≥ 0.7?}
    CONF -->|Yes| TRUST_J2[Trust Judge → VULNERABLE<br/>catches subtle compliance]
    CONF -->|No| KEEP_S[Keep SAFE]
    RESOLVE -->|One INCONCLUSIVE| DEFER[Defer to the other verdict]

    style V1 fill:#f99,stroke:#333
    style V2 fill:#f99,stroke:#333
    style V3 fill:#f99,stroke:#333
    style V4 fill:#f99,stroke:#333
    style V5 fill:#f99,stroke:#333
    style SAFE1 fill:#9f9,stroke:#333
    style SAFE2 fill:#9f9,stroke:#333
    style INC fill:#ff9,stroke:#333
    style JV fill:#f9f,stroke:#333
    style BOOST fill:#9f9,stroke:#333
    style TRUST_J1 fill:#9f9,stroke:#333
    style TRUST_J2 fill:#f99,stroke:#333
    style KEEP_S fill:#9f9,stroke:#333
```

#### PAIR Orchestrator (Prompt Automatic Iterative Refinement)

```mermaid
flowchart TD
    START[Initial Attack Prompt] --> SEND[Send to Target]
    SEND --> EVAL{Evaluate Response}

    EVAL -->|VULNERABLE| SUCCESS[Vulnerability Found — Stop]
    EVAL -->|SAFE / INCONCLUSIVE| CHECK{Max iterations<br/>reached?}

    CHECK -->|Yes| FINAL[Final Verdict from<br/>all collected evidence]
    CHECK -->|No| REFINE[Feed response to Attacker LLM]

    REFINE --> GEN[Attacker generates refined prompt<br/>• Different framing/angle<br/>• Addresses specific refusal reasons<br/>• New technique each iteration]
    GEN --> SEND

    style SUCCESS fill:#f99,stroke:#333
    style FINAL fill:#ff9,stroke:#333
    style REFINE fill:#f9f,stroke:#333
```

#### Crescendo Orchestrator (Gradual Escalation)

```mermaid
flowchart TD
    subgraph Phase1[Phase 1: Plan]
        OBJ[Attack Objective] --> PLAN[Attacker LLM plans<br/>N-turn escalation sequence]
        PLAN --> TURNS[Turn 1: Innocent rapport<br/>Turn 2-3: Domain introduction<br/>Turn 4-5: Approach objective<br/>Turn N: Full request]
    end

    subgraph Phase2[Phase 2: Execute]
        TURNS --> T1[Turn 1 — Establish rapport]
        T1 --> RESP1[Target responds cooperatively]
        RESP1 --> ADAPT[Adapt next turn based on<br/>target's actual response]
        ADAPT --> TN[Turn N — Escalated request]
    end

    subgraph Phase3[Phase 3: Evaluate]
        TN --> EVAL{Evaluate from<br/>turn 3 onward}
        EVAL -->|VULNERABLE| STOP[Escalation Succeeded<br/>at turn K/N]
        EVAL -->|SAFE| CONT{More turns?}
        CONT -->|Yes| ADAPT
        CONT -->|No| DONE[Final Verdict]
    end

    style Phase1 fill:#e8f4fd,stroke:#333
    style Phase2 fill:#fdf8e8,stroke:#333
    style Phase3 fill:#fde8e8,stroke:#333
    style STOP fill:#f99,stroke:#333
```

#### Mutation Engine

```mermaid
flowchart LR
    subgraph Programmatic[Programmatic Mutations]
        P1[Base64 Encode]
        P2[Leetspeak]
        P3[Context Overflow]
        P4[ROT13]
        P5[Unicode Homoglyph]
        P6[Char Split — ZWSP]
        P7[Reversed Words]
        P8[Morse Code]
        P9[Caesar Cipher]
    end

    subgraph LLMPowered[LLM-Powered Mutations]
        L1[Paraphrase]
        L2[Roleplay Wrap]
        L3[Gradual Escalation]
        L4[Translation]
    end

    ORIG[Original Prompt] --> Programmatic
    ORIG --> LLMPowered

    Programmatic --> MUT[Mutated Attack]
    LLMPowered --> MUT

    MUT --> EXEC[Execute against Target]
    EXEC --> DET[Detection Pipeline]

    style Programmatic fill:#e8f4fd,stroke:#333
    style LLMPowered fill:#fde8e8,stroke:#333
    style MUT fill:#f9f,stroke:#333
```

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
