# Agentic Pentesting Platform — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Evolve the current Keelson MVP into a full agentic pentesting platform with statistical measurement, LLM-generated attacks, semantic coverage tracking, and cross-scan learning.

**Architecture:** Three-phase build: Execution Layer first (statistical runner, multi-turn branching, scan tiers, adapters), then Generation Layer (LLM attacker, mutation engine), then Learning Layer (semantic coverage, graph KB, RAG). Each phase delivers standalone value. See `agentic-pentesting-architecture.md` for full design.

**Tech Stack:** Python 3.12+, asyncio, httpx, PostgreSQL + pgvector, Dramatiq + Redis, HDBSCAN, UMAP, FastAPI, Typer, Next.js (dashboard).

---

## Progress Dashboard

> Update the `Status` column as tasks complete. Use: `⬜ TODO` · `🔄 IN PROGRESS` · `✅ DONE` · `⏸ BLOCKED`

### Phase 1 — Execution Layer

| #    | Task                                                      | Status  | Notes                                      |
|------|-----------------------------------------------------------|---------|--------------------------------------------|
| 1.1  | Statistical Runner core (`run_statistical`, Wilson score) | ✅ DONE | `campaign/runner.py`                       |
| 1.2  | `StatisticalFinding` model + DB schema                    | ✅ DONE | `core/models.py` + `state/store.py`        |
| 1.3  | Scan tiers config (`fast` / `deep` / `continuous`)        | ✅ DONE | `campaign/tiers.py`                        |
| 1.4  | CLI `--tier` flag + tier-aware scan pipeline              | ✅ DONE | `cli.py`                                   |
| 1.5  | Store abstraction layer (`BaseStore` protocol)            | ✅ DONE | `state/base.py`                            |
| 1.6  | `discovery.py` — endpoint capability probing              | ✅ DONE | `attacker/discovery.py`                    |
| 1.7  | Anthropic Messages API adapter                            | ✅ DONE | `adapters/anthropic.py`                    |
| 1.8  | Generic HTTP adapter (any OpenAI-compatible endpoint)     | ✅ DONE | `adapters/http.py`                         |
| 1.9  | YAML template format + loader                             | ✅ DONE | `core/yaml_templates.py` + `attacks/yaml/` |
| 1.10 | Conversation tree branching engine                        | ✅ DONE | `adaptive/branching.py`                    |
| 1.11 | PostgreSQL store + pgvector                               | ⬜ TODO |                                            |
| 1.12 | Dramatiq + Redis task queue (deep scan workers)           | ⬜ TODO |                                            |
| 1.13 | Streaming observer (gradual leakage detection)            | ✅ DONE | `core/observer.py`                         |
| 1.14 | Attack playbooks expansion (72 across 7 categories)       | ✅ DONE | `attacks/`                                 |
| 1.15 | SARIF v2.1.0 output                                       | ✅ DONE | `core/sarif.py`                            |
| 1.16 | GitHub Action spec                                        | ✅ DONE | `docs/github-action-spec.md`               |
| 1.17 | CrewAI native adapter                                     | ✅ DONE | `adapters/crewai.py`                       |
| 1.18 | LangChain native adapter                                  | ✅ DONE | `adapters/langchain.py`                    |
| 1.19 | A2A protocol adapter                                      | ✅ DONE | `adapters/a2a.py`                          |
| 1.20 | MCP adapter                                               | ✅ DONE | `adapters/mcp.py`                          |
| 1.21 | LangGraph adapter                                         | ✅ DONE | `adapters/langgraph.py`                    |

### Phase 2 — Generation Layer

| #   | Task                                                  | Status         | Notes                              |
|-----|-------------------------------------------------------|----------------|------------------------------------|
| 2.1 | Seed library migration to YAML (28 existing → YAML)   | 🔄 IN PROGRESS | Loader ready, attacks still in .md |
| 2.2 | LLM attacker — attack generation prompt + client      | ✅ DONE        | `attacker/generator.py`            |
| 2.3 | Cross-provider attacker selection (target ≠ attacker) | ✅ DONE        | `attacker/provider.py`             |
| 2.4 | Capability-aware attack graph synthesizer             | ✅ DONE        | `attacker/discovery.py`            |
| 2.5 | Mutation engine — programmatic transforms (free tier) | ✅ DONE        | `adaptive/mutations.py`            |
| 2.6 | Mutation engine — LLM reframing (paid tier)           | ✅ DONE        | `adaptive/mutations.py`            |
| 2.7 | Mutation trigger (5–80% success rate → mutate)        | ✅ DONE        | `adaptive/strategies.py`           |

### Phase 2.5 — Defend & CI/CD

| #   | Task                                                        | Status | Notes     |
|-----|-------------------------------------------------------------|--------|-----------|
| D.1 | CI/CD integration (JUnit XML, `--fail-on-vuln`, exit codes) | ⬜ TODO |           |
| D.2 | Keelson Defend: CrewAI hook (step_callback + policy engine)  | ⬜ TODO |           |
| D.3 | Keelson Defend: LangChain hook (BaseCallbackHandler)         | ⬜ TODO | Deps: D.2 |
| D.4 | Drift detection & monitoring (auto-diff, webhooks)          | ⬜ TODO |           |
| D.5 | Compliance expansion (PB/DI/ES/SI mappings, PCI DSS 4.0)    | ⬜ TODO |           |

### Phase 3 — Learning Layer

| #   | Task                                                      | Status | Notes |
|-----|-----------------------------------------------------------|--------|-------|
| 3.1 | Embedding pipeline (text-embedding-3-small)               | ⬜ TODO |       |
| 3.2 | HDBSCAN clustering + UMAP coverage visualization          | ⬜ TODO |       |
| 3.3 | Coverage score metric (% semantic space explored)         | ⬜ TODO |       |
| 3.4 | Kuzu graph DB schema (Attack, AgentConfig, Vulnerability) | ⬜ TODO |       |
| 3.5 | Cross-scan KB queries (what worked before)                | ⬜ TODO |       |
| 3.6 | Regression detection (baseline diff + alerts)             | ⬜ TODO |       |
| 3.7 | RAG pipeline — arXiv / CVE ingestion                      | ⬜ TODO |       |

### Infrastructure

| #   | Task                                                        | Status | Notes |
|-----|-------------------------------------------------------------|--------|-------|
| I.1 | FastAPI REST API (`/api/v1/scans`, `/findings`, `/targets`) | ⬜ TODO |       |
| I.2 | Auth / multi-tenancy (WorkOS or Clerk)                      | ⬜ TODO |       |
| I.3 | Next.js dashboard (findings, coverage map)                  | ⬜ TODO |       |
| I.4 | Docker + Kubernetes deployment                              | ⬜ TODO |       |
| I.5 | Compliance report templates (OWASP, NIST, EU AI Act)        | ⬜ TODO |       |

---

## Phase 1: Execution Layer

---

### Task 1.1 — Statistical Runner Core ✅ Completed

**What:** Replace single-run binary verdict with N-repetition execution + Wilson score confidence intervals. A vulnerability with 20% success rate is real — an adversary with unlimited retries will find it.

**Files:**

- Create: `src/keelson/core/runner.py`
- Create: `tests/test_runner.py`
- Read first: `src/keelson/core/engine.py`, `src/keelson/core/models.py`

**Step 1: Write failing tests**

```python
# tests/test_runner.py
import pytest
from unittest.mock import AsyncMock, patch
from keelson.core.runner import wilson_score, run_statistical
from keelson.core.models import Verdict

def test_wilson_score_all_success():
    lo, hi = wilson_score(successes=10, trials=10)
    assert lo > 0.7
    assert hi == pytest.approx(1.0, abs=0.01)

def test_wilson_score_zero_trials():
    lo, hi = wilson_score(successes=0, trials=0)
    assert lo == 0.0
    assert hi == 0.0

def test_wilson_score_half():
    lo, hi = wilson_score(successes=5, trials=10)
    assert 0.2 < lo < 0.5
    assert 0.5 < hi < 0.8

@pytest.mark.asyncio
async def test_run_statistical_all_vulnerable(sample_template, mock_adapter_vulnerable):
    result = await run_statistical(sample_template, mock_adapter_vulnerable, n=5)
    assert result.trials == 5
    assert result.successes == 5
    assert result.success_rate == 1.0
    assert result.confidence_low > 0.5

@pytest.mark.asyncio
async def test_run_statistical_all_safe(sample_template, mock_adapter_safe):
    result = await run_statistical(sample_template, mock_adapter_safe, n=5)
    assert result.success_rate == 0.0
    assert result.confidence_high < 0.5

@pytest.mark.asyncio
async def test_run_statistical_respects_concurrency(sample_template, mock_adapter_vulnerable):
    result = await run_statistical(sample_template, mock_adapter_vulnerable, n=10, concurrency=3)
    assert result.trials == 10
```

**Step 2–6:** Implementation, fixtures, verification, and commit — all complete.

---

### Task 1.2 — `StatisticalFinding` Model + DB Schema Extension ✅ Completed

**What:** Add `StatisticalFinding` dataclass to models and extend the SQLite store to persist statistical results alongside individual findings.

**Files:**

- Modify: `src/keelson/core/models.py`
- Modify: `src/keelson/state/store.py`
- Modify: `tests/test_store.py`

---

### Task 1.3 — Scan Tiers Configuration ✅ Completed

**What:** Define fast/deep/continuous tier presets. Tiers control repetitions, concurrency, delay, and which attacks to include.

**Files:**

- Create: `src/keelson/core/tiers.py`
- Create: `tests/test_tiers.py`

---

### Task 1.4 — CLI `--tier` Flag + Tier-Aware Scan Pipeline ✅ Completed

**What:** Wire tiers into the CLI and scanner. `keelson scan --tier deep --url http://...` runs with N=10 reps, etc.

**Files:**

- Modify: `src/keelson/cli.py`
- Modify: `src/keelson/core/scanner.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_scanner.py`

---

### Task 1.5 — Store Abstraction Layer (`BaseStore` Protocol) ✅ Completed

**What:** Extract a `BaseStore` protocol so the SQLite implementation can be swapped for PostgreSQL without changing the scanner or CLI.

**Files:**

- Create: `src/keelson/state/base.py`
- Modify: `src/keelson/state/store.py` (rename class to `SqliteStore`, implement protocol)
- Modify: `src/keelson/cli.py` (use `SqliteStore` explicitly)
- Modify: `tests/test_store.py`

---

### Task 1.6 — `discovery.py` — Endpoint Capability Probing ✅ Completed

**What:** `discovery.py` probes a target for available tools, model family, and system prompt hints.

**Files:**

- Create: `src/keelson/core/discovery.py`
- Create: `tests/test_discovery.py`

---

### Task 1.7 — Anthropic Messages API Adapter ✅ Completed

**What:** Adapter for Anthropic's Messages API so Keelson can test Claude-based agents directly.

**Files:**

- Create: `src/keelson/adapters/anthropic.py`
- Create: `tests/test_adapter_anthropic.py`

---

### Task 1.8 — Generic HTTP Adapter ✅ Completed

**What:** `GenericHTTPAdapter` that accepts any base URL, useful for testing local agents, LangChain servers, and custom deployments.

**Files:**

- Create: `src/keelson/adapters/http.py`
- Create: `tests/test_adapter_http.py`

---

### Task 1.9 — YAML Template Format + Loader ✅ Completed

**What:** YAML template support alongside existing `.md` templates. YAML enables branching trees, machine-readable metadata, and the mutation engine. Both formats coexist.

**Files:**

- Create: `src/keelson/core/yaml_templates.py`
- Create: `tests/test_yaml_templates.py`
- Modify: `src/keelson/core/templates.py` (unified loader)

---

### Task 1.10 — Conversation Tree Branching Engine ✅ Completed

**What:** Branching based on agent responses. Branch conditions use keyword matching first; LLM-based classification is Phase 2.

**Files:**

- Create: `src/keelson/core/branch.py`
- Modify: `src/keelson/core/engine.py`
- Create: `tests/test_branch.py`

---

### Task 1.11 — PostgreSQL Store + pgvector

**What:** Add a `PostgresStore` that implements `BaseStore` using PostgreSQL + pgvector. SQLite remains the default for local use.

> **Prerequisites:** Task 1.5 must be complete (BaseStore abstraction).

**Files:**

- Create: `src/keelson/state/postgres.py`
- Create: `tests/test_store_postgres.py`
- Modify: `pyproject.toml` (add optional `asyncpg` dependency)

**Step 1: Add optional dependency to `pyproject.toml`**

```toml
[project.optional-dependencies]
postgres = ["asyncpg>=0.29", "psycopg2-binary>=2.9"]
```

**Step 2: Write failing tests (use testcontainers or skip if no PG)**

```python
# tests/test_store_postgres.py
import pytest
pytest.importorskip("asyncpg", reason="asyncpg not installed")

@pytest.mark.asyncio
@pytest.mark.integration
async def test_postgres_store_save_and_load(pg_dsn):
    from keelson.state.postgres import PostgresStore
    store = PostgresStore(dsn=pg_dsn)
    await store.initialize()
    # ... save and load a ScanResult
    await store.close()
```

**Step 3: Implement `src/keelson/state/postgres.py`**

```python
import asyncpg
from keelson.state.base import BaseStore
from keelson.core.models import ScanResult, StatisticalFinding

class PostgresStore:
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None

    async def initialize(self) -> None:
        self._pool = await asyncpg.create_pool(self._dsn)
        await self._create_tables()

    async def _create_tables(self) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute("""
                CREATE EXTENSION IF NOT EXISTS vector;
                CREATE TABLE IF NOT EXISTS scans (...);
                CREATE TABLE IF NOT EXISTS statistical_findings (...);
                CREATE TABLE IF NOT EXISTS attack_embeddings (
                    attack_id TEXT PRIMARY KEY,
                    embedding vector(1536)
                );
            """)

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()
```

---

### Task 1.12 — Dramatiq + Redis Task Queue

**What:** Add Dramatiq + Redis for distributing deep scan work across multiple workers.

**Files:**

- Create: `src/keelson/workers/tasks.py`
- Create: `src/keelson/workers/__init__.py`
- Modify: `pyproject.toml` (add `dramatiq[redis]`)
- Create: `tests/test_tasks.py`

---

### Task 1.13 — Streaming Observer ✅ Completed

**What:** Streaming observer that detects partial/gradual information leakage across a multi-turn conversation.

**Files:**

- Create: `src/keelson/core/detection/streaming.py`
- Create: `tests/test_streaming_observer.py`

---

### Task 1.14 — Attack Playbooks Expansion ✅ Completed

**What:** Expand from 28 to 72 attack playbooks across 7 categories: Goal Adherence (GA), Tool Safety (TS), Memory Integrity (MI), Permission Boundaries (PB), Delegation Integrity (DI), Execution Safety (ES), Session Isolation (SI).

**Files:** `attacks/` directory with all category subdirectories.

---

### Task 1.15 — SARIF v2.1.0 Output ✅ Completed

**What:** SARIF v2.1.0 JSON generation from ScanResult/CampaignResult. Maps severity to SARIF level, attacks to rules, findings to results. `--format sarif` CLI flag.

**Files:** `src/keelson/core/sarif.py`, `tests/test_sarif.py`

---

### Task 1.16 — GitHub Action Spec ✅ Completed

**What:** `keelson-ai/keelson-action@v1` design (composite action: pip install, scan, upload SARIF).

**Files:** `docs/github-action-spec.md`

---

### Task 1.17 — CrewAI Native Adapter ✅ Completed

**What:** `CrewAIAdapter(BaseAdapter)` wrapping `crew.kickoff()` directly (not HTTP). Optional dependency.

**Files:** `src/keelson/adapters/crewai.py`, `tests/test_crewai_adapter.py`

---

### Task 1.18 — LangChain Native Adapter ✅ Completed

**What:** `LangChainAdapter(BaseAdapter)` wrapping `agent.invoke()` directly. Optional dependency.

**Files:** `src/keelson/adapters/langchain.py`, `tests/test_langchain_adapter.py`

---

### Task 1.19 — A2A Protocol Adapter ✅ Completed

**What:** Google Agent-to-Agent protocol via JSON-RPC 2.0. Agent card discovery via `GET /.well-known/agent.json`.

**Files:** `src/keelson/adapters/a2a.py`, `tests/test_a2a_adapter.py`

---

### Task 1.20 — MCP Adapter ✅ Completed

**What:** Model Context Protocol adapter for testing MCP-connected agents.

**Files:** `src/keelson/adapters/mcp.py`, `tests/test_mcp_adapter.py`

---

### Task 1.21 — LangGraph Adapter ✅ Completed

**What:** LangGraph adapter for testing stateful graph-based agents.

**Files:** `src/keelson/adapters/langgraph.py`, `tests/test_langgraph_adapter.py`

---

## Phase 2: Generation Layer

---

### Task 2.1 — Seed Library Migration to YAML 🔄 In Progress

**What:** Convert all existing `.md` attack templates to YAML format in `src/keelson/attacks/`. Keep `.md` files alongside for human readability. Update the loader to prefer YAML when both exist.

**Status:** YAML loader is ready (`core/yaml_templates.py`). Attacks are still in `.md` format — conversion pending.

**Files:**

- Create: YAML versions of all 72 attack playbooks
- Modify: `src/keelson/core/templates.py`

---

### Task 2.2 — LLM Attacker (Attack Generation) ✅ Completed

**What:** Use a cross-provider LLM to generate novel attacks from discovered capabilities. The attacker LLM must differ from the target (no same-family bias).

**Files:** `src/keelson/attacker/generator.py`, `tests/test_generator_v2.py`

---

### Task 2.3 — Cross-Provider Attacker Selection ✅ Completed

**What:** Automatically select a different LLM provider for the attacker than the target. Config-driven.

**Files:** `src/keelson/attacker/provider.py`

---

### Task 2.4 — Capability-Aware Attack Graph ✅ Completed

**What:** From discovered capabilities (Task 1.6), synthesize attack chains automatically.

**Files:** `src/keelson/attacker/discovery.py`

---

### Task 2.5 — Mutation Engine (Programmatic Transforms) ✅ Completed

**What:** Free-tier mutation strategies that require no LLM calls (base64, leetspeak, unicode substitution, rot13, zero-width insertion).

**Files:** `src/keelson/adaptive/mutations.py`

---

### Task 2.6 — Mutation Engine (LLM Reframing) ✅ Completed

**What:** LLM-powered mutation strategies: paraphrase, role-play reframe, gradual escalation, authority persona.

**Files:** `src/keelson/adaptive/mutations.py`

---

### Task 2.7 — Mutation Trigger Integration ✅ Completed

**What:** Wire the mutation trigger into the statistical runner. After deep scan, automatically queue mutations for partial successes (5–80% success rate).

**Files:** `src/keelson/adaptive/strategies.py`

---

## Phase 2.5: Defend & CI/CD

---

### Task D.1 — CI/CD Integration

**What:** Add JUnit XML output format for CI/CD pipeline integration. Include `--fail-on-vuln` exit codes and `--fail-threshold` flags so pipelines can gate on security results.

**Files:**

- Create: `src/keelson/core/junit.py`
- Modify: `src/keelson/cli.py`

**Key design:**

- JUnit XML output: map each attack template to a `<testcase>`, vulnerable findings to `<failure>`
- `--fail-on-vuln` flag: exit code 1 if any vulnerability found
- `--fail-threshold <severity>`: exit code 1 only for findings at or above threshold (e.g., `--fail-threshold high`)
- `--format junit` alongside existing `sarif` and `json` formats
- Compatible with GitHub Actions, GitLab CI, Jenkins, CircleCI test result uploads

```python
# src/keelson/core/junit.py
def scan_result_to_junit(result: ScanResult) -> str:
    """Convert ScanResult to JUnit XML string."""
    # <testsuite name="keelson" tests="72" failures="3">
    #   <testcase name="GA-001 Direct Override" classname="goal_adherence">
    #     <failure message="Vulnerable (80% success rate)">...</failure>
    #   </testcase>
    # </testsuite>
```

---

### Task D.2 — Keelson Defend: CrewAI Hook

**What:** Runtime defense layer for CrewAI agents. `KeelsonCrewAICallback` implementing CrewAI's `step_callback` to intercept and block unsafe tool calls in real time. YAML-configurable policy engine for allow/deny/require-approval rules.

**Files:**

- Create: `src/keelson/defend/__init__.py`
- Create: `src/keelson/defend/crewai_hook.py`
- Create: `src/keelson/defend/rules.py` (YAML policy engine)
- Create: `src/keelson/defend/models.py`
- Create: `tests/test_defend_crewai.py`

**Key design:**

- Reuse detection patterns from `core/detection.py`
- YAML policy format:

```yaml
# keelson-policy.yaml
rules:
  - action: deny
    tool: shell_exec
    reason: "Shell execution blocked by policy"
  - action: require_approval
    tool: send_email
    conditions:
      - contains_pii: true
  - action: allow
    tool: read_file
    paths: ["./data/*"]
```

- `KeelsonCrewAICallback.on_step(step)` → check against policy → allow/deny/log
- Emit structured audit log for every intercepted action

---

### Task D.3 — Keelson Defend: LangChain Hook

**What:** `KeelsonLangChainCallback(BaseCallbackHandler)` implementing `on_tool_start()` and `on_llm_start()` hooks. Shares the policy engine from Task D.2.

> **Prerequisites:** Task D.2 must be complete (policy engine).

**Files:**

- Create: `src/keelson/defend/langchain_hook.py`
- Create: `tests/test_defend_langchain.py`

**Key design:**

- `on_tool_start(tool_name, input_str)` → evaluate against `defend/rules.py` policy
- `on_llm_start(serialized, prompts)` → check for prompt injection patterns
- Raise `KeelsonBlockedError` when policy denies an action
- Same audit log format as CrewAI hook

---

### Task D.4 — Drift Detection & Monitoring

**What:** Auto-diff after scheduled campaigns, webhook alerts on regressions. New `keelson monitor` command for continuous security posture tracking.

**Files:**

- Create: `src/keelson/campaign/drift.py`
- Create: `src/keelson/campaign/alerts.py`
- Modify: `src/keelson/campaign/scheduler.py`
- Modify: `src/keelson/cli.py`

**Key design:**

- `keelson monitor <url> --baseline <scan_id> --interval 24h --alert-webhook <url>`
- Compare new scan results against baseline: flag newly vulnerable attacks, newly safe attacks, and success rate changes
- Webhook payload: JSON with `regressions[]`, `improvements[]`, `unchanged[]`
- Support Slack, PagerDuty, and generic webhook endpoints

---

### Task D.5 — Compliance Expansion

**What:** Add PB/DI/ES/SI prefixes to all compliance mappings. Add PCI DSS 4.0 AI-specific controls.

**Files:**

- Modify: `src/keelson/core/compliance.py`

**Key design:**

- Extend OWASP LLM Top 10 mappings for all 7 categories
- Add PCI DSS 4.0 requirement mappings (Req 6.2.4 — software security, Req 11 — testing)
- Ensure `compliance.py` handles the full category enum: GA, TS, MI, PB, DI, ES, SI

---

## Phase 3: Learning Layer

---

### Task 3.1 — Embedding Pipeline

**What:** Embed every attack attempt (input + response) for semantic coverage analysis.

**Files:**

- Create: `src/keelson/learning/__init__.py`
- Create: `src/keelson/learning/embedder.py`

```python
# Uses OpenAI text-embedding-3-small
async def embed_attack(prompt: str, response: str) -> list[float]:
    text = f"ATTACK: {prompt}\nRESPONSE: {response}"
    return embedding_vector  # 1536-dimensional
```

Store vectors in `attack_embeddings` table (pgvector `vector(1536)` column).

---

### Task 3.2 — HDBSCAN Clustering + UMAP Visualization

**What:** Cluster attack embeddings to find unexplored regions of the attack space.

**Files:**

- Create: `src/keelson/learning/coverage.py`

```python
def compute_coverage(embeddings: list[list[float]]) -> CoverageReport:
    labels = hdbscan.HDBSCAN(min_cluster_size=5).fit_predict(embeddings)
    projection = umap.UMAP(n_components=2).fit_transform(embeddings)
    coverage_pct = len(set(labels) - {-1}) / estimated_total_clusters
    return CoverageReport(coverage_pct=coverage_pct, projection=projection, labels=labels)
```

---

### Task 3.3 — Coverage Score Metric

**What:** Report `coverage_score` (% semantic space explored) per OWASP category. Target: >85% for deep scans.

```python
@dataclass
class CoverageReport:
    coverage_pct: float           # 0.0–1.0
    clusters_found: int
    uncovered_regions: int        # noise points from HDBSCAN
    projection: list[tuple[float, float]]  # UMAP 2D coords for visualization
    owasp_breakdown: dict[str, float]      # per-category coverage
```

---

### Task 3.4 — Kuzu Graph DB Schema

**What:** Add embedded graph database for cross-scan knowledge. Kuzu is embedded (no separate server).

```python
# Graph schema
# (Attack)-[:SUCCEEDED_AGAINST]->(AgentConfig)
# (Attack)-[:MUTATED_FROM]->(Attack)
# (Vulnerability)-[:MAPS_TO]->(OWASPCategory)
```

---

### Task 3.5 — Cross-Scan KB Queries

**What:** Query the graph DB to prime new scans with attacks that worked against similar agent configurations.

```python
def get_attacks_for_similar_agents(capabilities: list[str]) -> list[str]:
    """Return attack IDs that succeeded against agents with these capabilities."""
```

---

### Task 3.6 — Regression Detection

**What:** Compare daily lightweight scan results to a stored baseline. Alert on previously-blocked attacks that now succeed.

```python
@dataclass
class RegressionAlert:
    template_id: str
    previous_success_rate: float
    current_success_rate: float
    severity: str
    message: str
```

---

### Task 3.7 — RAG Pipeline

**What:** Daily ingestion of arXiv/CVE feeds → embed → classify by attack category → add to attack candidate pool.

**Sources:**

- arXiv API: cs.CR + cs.AI papers
- NVD CVE feed: agent framework vulnerabilities
- OWASP LLM Top 10 updates

---

## Infrastructure Tasks

---

### Task I.1 — FastAPI REST API

**What:** Add a REST API alongside the CLI. Required for dashboard and CI/CD integrations.

```
POST   /api/v1/scans              — Start scan (returns scan_id)
GET    /api/v1/scans/:id           — Poll status + results
GET    /api/v1/scans/:id/findings  — List vulnerabilities
POST   /api/v1/targets             — Register target agent
GET    /api/v1/targets/:id/surface — Attack surface map
GET    /api/v1/coverage/:scan_id   — Semantic coverage report
```

**Files:**

- Create: `src/keelson/api/__init__.py`
- Create: `src/keelson/api/app.py`
- Create: `src/keelson/api/routes/`

---

### Task I.2 — Auth / Multi-Tenancy

**What:** WorkOS or Clerk for SSO + RBAC. PostgreSQL schema-per-tenant isolation (Task 1.11 prerequisite).

---

### Task I.3 — Next.js Dashboard

**What:** Web UI for findings, coverage map (UMAP visualization), scan history.

---

### Task I.4 — Docker + Kubernetes

**What:** Containerize all services. Helm chart for Kubernetes deployment.

---

### Task I.5 — Compliance Report Templates

**What:** Jinja2 templates for OWASP LLM Top 10, NIST AI RMF, EU AI Act, ISO 42001, SOC 2. Export as PDF, HTML, JSON, JUnit XML.

---

## Build Sequence

```
Week 1-2:   Category enum expansion → 72 playbooks (parallel)      ✅ DONE
Week 3:     SARIF output + PyPI prep                               ✅ DONE
Week 4:     GitHub Action spec + PyPI publish                      ✅ DONE
Week 5-6:   Enhanced generator + CrewAI adapter                    ✅ DONE
Week 7-8:   LangChain/LangGraph/A2A/MCP adapters                   ✅ DONE
Week 9-10:  Cross-provider selection + mutation engine             ✅ DONE
Week 11-12: D.1 (CI/CD JUnit) + D.2 (Defend CrewAI)                ⬜ NEXT
Week 13-14: D.3 (Defend LangChain) + D.4 (drift detection)         ⬜ TODO
Week 15-16: D.5 (compliance) + 2.1 (YAML migration)                ⬜ TODO
Week 17-18: 3.1 (embedding pipeline) + 3.2 (clustering)            ⬜ TODO
Week 19-22: 3.3-3.5 (coverage + knowledge base)                    ⬜ TODO
Week 23-26: I.1 (REST API) + I.3 (dashboard)                       ⬜ TODO
Week 27-32: 3.6-3.7 (regression + RAG) + I.2/I.4 (enterprise)      ⬜ TODO
```

## Key Milestones

| Week | Milestone                                  | Go/No-Go                          |
|------|--------------------------------------------|-----------------------------------|
| 2    | 72 playbooks across 7 categories           | ✅ Achieved                       |
| 4    | `pip install keelson` on PyPI               | Must work end-to-end              |
| 8    | All 7 adapters functional                  | ✅ Achieved                       |
| 10   | Mutation engine + cross-provider selection | ✅ Achieved                       |
| 12   | CI/CD integration (JUnit + fail gates)     | First CI/CD-capable product       |
| 14   | Keelson Defend MVP (CrewAI + LangChain)     | First revenue-capable product     |
| 16   | 100 GitHub stars                           | If <50 → reassess positioning     |
| 18   | 3 paying customers (Defend)                | If 0 → pivot to consulting        |
| 22   | Continuous mode + drift detection shipped  | Must ship before Aug 2 EU AI Act  |
| 26   | REST API + dashboard MVP                   | Enterprise readiness gate         |
| 40   | $50K+ MRR                                  | Series A or acquisition readiness |

## Architectural Decisions

1. **Attacks move into Python package** (`src/keelson/attacks/`) for reliable pip install
2. **SQLite for OSS, PostgreSQL optional for Cloud** — extract BaseStore interface later
3. **Defend hooks are in-process, not HTTP proxies** — CrewAI step_callback, LangChain BaseCallbackHandler
4. **Detection stays pattern-based** — LLM evaluation as optional enhancement, not replacement
5. **Adapter protocol unchanged** — 3 methods (send_messages, health_check, close), decorator composition

## Verification

- `pytest tests/ -v` — all existing + new tests pass
- `keelson list` — shows 72 attacks across 7 categories
- `keelson scan <url> --format sarif` — valid SARIF JSON
- `keelson scan <url> --format junit` — valid JUnit XML
- `keelson test-crew <file>` — runs against CrewAI agent
- `keelson campaign <url> --behaviors all --repetitions 5` — statistical results
- `pip install keelson && keelson --help` — works from clean install
- `keelson monitor <url> --baseline <id>` — drift detection running

---

## Dependency Installation Reference

```bash
# Phase 1 (core)
pip install httpx typer rich jinja2 pyyaml

# Phase 1 (PostgreSQL)
pip install asyncpg psycopg2-binary pgvector

# Phase 1 (workers)
pip install "dramatiq[redis]" redis

# Phase 2 (generation)
pip install openai anthropic

# Phase 2.5 (defend)
pip install crewai langchain-core  # optional deps

# Phase 3 (learning)
pip install hdbscan umap-learn plotly scikit-learn kuzu

# Phase 3 (RAG)
pip install feedparser arxiv httpx
```

---

## Testing Strategy

```bash
# Unit tests (no external services)
pytest tests/ -v -m "not integration"

# Integration tests (requires Docker services)
pytest tests/ -v -m integration

# Full suite
pytest tests/ -v

# Coverage report
pytest tests/ --cov=keelson --cov-report=html
```

**Test markers to add to `pyproject.toml`:**

```toml
[tool.pytest.ini_options]
markers = [
    "integration: requires external services (postgres, redis)",
    "slow: takes more than 10 seconds",
]
```

---

*Last updated: 2026-03-04 | Architecture ref: `agentic-pentesting-architecture.md`*
