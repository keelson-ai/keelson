# AgentSec v2 Implementation Roadmap

**Date**: 2026-03-04
**Version**: v0.3.0 → v0.4.0+ (Phase 1 target)
**Status**: Active

## Context

The AgentSec v2 vision describes Pentis as an **autonomous red team agent** — not a static scanner. The current codebase (v0.3.0) has a solid execution layer but is missing critical differentiators: 4 of 7 behavior categories, framework-native adapters/hooks, SARIF output, and the learning layer. This plan bridges the gap from v0.3.0 to the full AgentSec v2 vision across 4 phases.

---

## Phase 1: MVP Red Team Agent (Weeks 4-10, May 2026)

**Goal**: `pip install pentis`, 54+ playbooks, SARIF, GitHub Action, CrewAI/LangChain/A2A adapters.

### 1.1 Expand Category Enum (S)
- Add `PERMISSION_BOUNDARIES`, `DELEGATION_INTEGRITY`, `EXECUTION_SAFETY`, `SESSION_ISOLATION` to `Category` enum
- Update `CATEGORY_MAP` in templates.py, reporter.py sections, compliance.py OWASP mappings
- **Files**: `src/pentis/core/models.py`, `templates.py`, `reporter.py`, `compliance.py`

### 1.2-1.5 New Playbooks — 26 attacks across 4 categories (M each)
- **PB-001..008** (Permission Boundaries) — role escalation, cross-user access, scope expansion, auth bypass → OWASP LLM02
- **DI-001..008** (Delegation Integrity) — unauthorized sub-agents, chain amplification, trust boundary violation → LLM08/LLM09
- **ES-001..008** (Execution Safety) — unbounded execution, resource exhaustion, sandbox escape, audit evasion → LLM06
- **SI-001..006** (Session Isolation) — cross-session leakage, session hijacking, multi-tenant breach → LLM05
- **Files**: Create `attacks/permission-boundaries/`, `delegation-integrity/`, `execution-safety/`, `session-isolation/`
- **Deps**: Task 1.1

### 1.6 SARIF Output (M)
- Implement SARIF v2.1.0 JSON generation from ScanResult/CampaignResult
- Map severity → SARIF level, attacks → rules, findings → results
- Add `--format sarif` to CLI scan/report commands
- **Files**: Create `src/pentis/core/sarif.py`, `tests/test_sarif.py`; modify `cli.py`, `reporter.py`

### 1.7 GitHub Action Spec (S)
- Document `pentis-ai/pentis-action@v1` design (composite action: pip install → scan → upload SARIF)
- Add example CI workflow to README
- **Files**: Create `docs/github-action-spec.md`; modify `README.md`
- **Deps**: Task 1.6

### 1.8 PyPI Packaging (M)
- Move `attacks/` into `src/pentis/attacks/` for reliable pip install
- Update `templates.py` ATTACKS_DIR to use `importlib.resources` or `__file__`-relative
- Verify `pyproject.toml` scripts/classifiers/URLs, create publish workflow
- Bump to v0.4.0
- **Files**: Restructure `attacks/` → `src/pentis/attacks/`, modify `templates.py`, `pyproject.toml`, `__init__.py`
- **Deps**: Tasks 1.1-1.5, 1.6

### 1.9 Enhanced Attack Generator (M)
- Expand `attacker/generator.py` with multi-step generation, all 7 categories, capability-informed generation, batch mode
- Add `generate` CLI command
- **Files**: Modify `src/pentis/attacker/generator.py`, `cli.py`; create `tests/test_generator_v2.py`
- **Deps**: Task 1.1

### 1.10 CrewAI Native Adapter (L)
- `CrewAIAdapter(BaseAdapter)` wrapping `crew.kickoff()` directly (not HTTP)
- Add `pentis test-crew my_crew.py` CLI command
- CrewAI as optional dependency
- **Files**: Create `src/pentis/adapters/crewai.py`, `tests/test_crewai_adapter.py`; modify `pyproject.toml`, `cli.py`

### 1.11 LangChain Native Adapter (M)
- `LangChainAdapter(BaseAdapter)` wrapping `agent.invoke()` directly
- Add `pentis test-chain` CLI command
- LangChain as optional dependency
- **Files**: Create `src/pentis/adapters/langchain.py`, `tests/test_langchain_adapter.py`; modify `pyproject.toml`, `cli.py`

### 1.12 A2A Protocol Adapter (M)
- Google Agent-to-Agent protocol via JSON-RPC 2.0 (similar pattern to MCP adapter)
- Agent card discovery via `GET /.well-known/agent.json`, task lifecycle
- **Files**: Create `src/pentis/adapters/a2a.py`, `tests/test_a2a_adapter.py`; modify `cli.py`

---

## Phase 2: Continuous Testing + Defend (Weeks 11-20, Jul 2026)

**Goal**: Drift detection, CI/CD, Pentis Defend runtime hooks, compliance expansion.

### 2.1 Pentis Defend: CrewAI Hook (L)
- `PentisCrewAICallback` implementing CrewAI `step_callback` — intercept/block unsafe tool calls
- YAML-configurable policy engine (allow/deny/require-approval rules)
- Reuse detection patterns from `core/detection.py`
- **Files**: Create `src/pentis/defend/__init__.py`, `crewai_hook.py`, `rules.py`, `models.py`; tests

### 2.2 Pentis Defend: LangChain Hook (M)
- `PentisLangChainCallback(BaseCallbackHandler)` — `on_tool_start()`, `on_llm_start()`
- Shares policy engine from Task 2.1
- **Files**: Create `src/pentis/defend/langchain_hook.py`; tests
- **Deps**: Task 2.1

### 2.3 CI/CD Integration (S)
- JUnit XML output format, `--fail-on-vuln` exit codes, `--fail-threshold` flags
- **Files**: Create `src/pentis/core/junit.py`; modify `cli.py`

### 2.4 Drift Detection & Monitoring (M)
- Auto-diff after scheduled campaigns, webhook alerts on regressions
- `pentis monitor <url> --baseline <scan_id> --interval 24h --alert-webhook <url>`
- **Files**: Create `src/pentis/campaign/drift.py`, `alerts.py`; modify `scheduler.py`, `cli.py`

### 2.5 Compliance Expansion (S)
- Add PB/DI/ES/SI prefixes to all compliance mappings, PCI DSS 4.0 AI controls
- **Files**: Modify `src/pentis/core/compliance.py`
- **Deps**: Task 1.1

---

## Phase 3: Fleet Intelligence (Weeks 21-32)

**Goal**: Semantic coverage, cross-scan learning, REST API, dashboard.

### 3.1 Semantic Coverage Tracking (L)
- Embedding pipeline (OpenAI text-embedding-3-small or sentence-transformers)
- HDBSCAN clustering + UMAP 2D projection
- Coverage score = populated_clusters / total_clusters
- **Files**: Create `src/pentis/coverage/` (embeddings.py, clustering.py, scorer.py); modify `cli.py`, `pyproject.toml`

### 3.2 Cross-Scan Learning KB (L)
- SQLite-based knowledge graph: attack outcomes × target × model × framework
- RAG: retrieve attacks that worked against similar agents
- Feed context into generator.py and chains.py
- **Files**: Create `src/pentis/learning/` (knowledge_base.py, rag.py); modify `state/store.py`, `attacker/generator.py`
- **Deps**: Task 3.1

### 3.3 REST API — FastAPI (XL)
- `/api/v1/scans`, `/api/v1/targets`, `/api/v1/campaigns`, `/api/v1/reports`
- Async background tasks, WebSocket progress, Pydantic models, CORS
- `pentis serve --port 8000`
- **Files**: Create `src/pentis/api/` (app.py, routes/, deps.py); modify `pyproject.toml`, `cli.py`

### 3.4 Web Dashboard — Next.js (XL)
- Fleet management: scan results, findings, coverage map, timeline
- Consumes REST API from Task 3.3
- **Files**: Create `dashboard/` directory
- **Deps**: Task 3.3

---

## Phase 4: Enterprise & Scale (Months 9-12+)

### 4.1 Multi-Tenant Architecture (L)
- Tenant isolation in Store + API, API key auth
- **Deps**: Task 3.3

### 4.2 PostgreSQL Store Backend (L)
- Extract `BaseStore` interface, add asyncpg-based `PostgresStore`
- **Deps**: Task 3.3

### 4.3 Telemetry & Community Plugins (L)
- Opt-in anonymized telemetry, plugin loader for community attack packages
- **Deps**: Task 3.2

---

## Build Sequence

```
Week 1-2:   1.1 (enum) → 1.2-1.5 (26 playbooks, parallel)
Week 3:     1.6 (SARIF) + 1.8 (PyPI prep)
Week 4:     1.7 (GH Action spec) + 1.8 (PyPI publish)
Week 5-6:   1.9 (generator) + 1.10 (CrewAI adapter)
Week 7-8:   1.11 (LangChain adapter) + 1.12 (A2A adapter)
Week 9-10:  2.1 (Defend CrewAI) + 2.3 (CI/CD)
Week 11-12: 2.2 (Defend LangChain) + 2.4 (drift detection)
Week 13-14: 2.5 (compliance) + 3.1 (coverage tracking)
Week 15-18: 3.2 (knowledge base) + 3.3 (REST API)
Week 19-24: 3.4 (dashboard) + 4.1-4.3 (enterprise)
```

## Key Milestones

| Week | Milestone | Go/No-Go |
|------|-----------|----------|
| 2 | 54+ playbooks across 7 categories | If quality is low → revise |
| 4 | `pip install pentis` on PyPI | Must work end-to-end |
| 8 | All 7 adapters functional | If <5 → deprioritize niche ones |
| 10 | Pentis Defend MVP (CrewAI) | First revenue-capable product |
| 14 | 100 GitHub stars | If <50 → reassess positioning |
| 16 | 3 paying customers (Defend) | If 0 → pivot to consulting |
| 20 | Continuous mode shipped | Must ship before Aug 2 EU AI Act |
| 40 | $50K+ MRR | Series A or acquisition readiness |

## Architectural Decisions

1. **Attacks move into Python package** (`src/pentis/attacks/`) for reliable pip install
2. **SQLite for OSS, PostgreSQL optional for Cloud** — extract BaseStore interface later
3. **Defend hooks are in-process, not HTTP proxies** — CrewAI step_callback, LangChain BaseCallbackHandler
4. **Detection stays pattern-based** — LLM evaluation as optional enhancement, not replacement
5. **Adapter protocol unchanged** — 3 methods (send_messages, health_check, close), decorator composition

## Verification

- `pytest tests/ -v` — all existing + new tests pass
- `pentis list` — shows 54+ attacks across 7 categories
- `pentis scan <url> --format sarif` — valid SARIF JSON
- `pentis test-crew <file>` — runs against CrewAI agent
- `pentis campaign <url> --behaviors all --repetitions 5` — statistical results
- `pip install pentis && pentis --help` — works from clean install
