# Node.js Migration Design

## Decision Summary

Migrate Keelson from Python to TypeScript. Clean-room rewrite with `_legacy/` folder as reference.

## Tech Stack

| Layer           | Choice                                             |
|-----------------|----------------------------------------------------|
| Language        | TypeScript 5.x (strict, ESM-only, NodeNext)        |
| Node            | >= 22 (LTS), tested on 22 + 24                     |
| CLI parsing     | Commander                                          |
| Terminal UI     | Ink + React (live scan output, progress, findings) |
| HTTP client     | axios (retry interceptors for 429/5xx)             |
| YAML parser     | `yaml` v2 (YAML 1.2)                               |
| Validation      | Zod (runtime schemas for probes + config)          |
| Testing         | Vitest + nock (HTTP mocking)                       |
| Linting         | ESLint 9 + typescript-eslint (strict) + import-x   |
| Formatting      | Prettier (single quotes, 120 width)                |
| Build           | `tsc` (plain compilation to `dist/`, no bundler)   |
| Package manager | pnpm (pinned exact deps, Dependabot for updates)   |

## Architecture Reference

- **Primary**: existing Python codebase (copied to `_legacy/`)
- **Secondary**: [Othentic-Labs/jarvis](https://github.com/Othentic-Labs/jarvis) — TypeScript security engagement tool with similar patterns (phase orchestrator, transport abstraction, detection pipeline, mutations engine)

## What Stays Unchanged

- `probes/` — 210 YAML probe playbooks (data, not code)
- `agents/` — Agent instruction markdown files
- `commands/` — Command spec markdown files
- `docs/` — Architecture docs, ADRs

## What Gets Migrated

All Python source in `src/keelson/` and `tests/` → TypeScript in `src/` and `tests/`.

## What's Excluded (Add Later When Needed)

- Fastify service layer (health endpoint, API routes)
- Docker / docker-compose
- Defense hooks (`defend/`)
- Differential scan comparison (`diff/`)
- Campaign runner, scheduler, tiers (`campaign/`)
- Persistent state storage (`state/`)

## Project Structure

```text
keelson/
├── src/
│   ├── cli/                    # Commander command definitions
│   │   ├── index.ts            # Entry point, program setup
│   │   ├── scan.ts             # scan commands
│   │   ├── probe.ts            # Single probe command
│   │   ├── report.ts           # Report generation command
│   │   └── ops.ts              # config, validate, list
│   │
│   ├── components/             # Ink/React terminal UI
│   │   ├── ScanProgress.tsx    # Live scan dashboard
│   │   ├── FindingCard.tsx     # Single finding display
│   │   ├── ProbeResult.tsx     # Probe execution result
│   │   └── ReportView.tsx      # Report summary
│   │
│   ├── hooks/                  # React hooks for Ink
│   │   ├── useEngine.ts
│   │   └── useStreamingScan.ts
│   │
│   ├── core/                   # Core engine
│   │   ├── engine.ts           # Probe execution (multi-turn, early termination)
│   │   ├── scanner.ts          # Scan pipeline + prioritization
│   │   ├── detection.ts        # Pattern-based verdict detection
│   │   ├── llm-judge.ts        # LLM-as-judge semantic evaluation
│   │   ├── observer.ts         # Streaming per-step analysis
│   │   ├── memo.ts             # Technique effectiveness tracking
│   │   ├── strategist.ts       # Adaptive probe selection
│   │   ├── convergence.ts      # Iterative cross-category feedback
│   │   └── smart-scan.ts       # Adaptive scanning with memo loop
│   │
│   ├── adapters/               # Target communication
│   │   ├── base.ts             # Abstract base with retry logic (429/502/503/504)
│   │   ├── http.ts             # Generic OpenAI-compatible HTTP
│   │   ├── openai.ts           # OpenAI Chat Completions
│   │   ├── anthropic.ts        # Anthropic Messages API
│   │   ├── langgraph.ts        # LangGraph Platform
│   │   ├── mcp.ts              # JSON-RPC 2.0 MCP servers
│   │   ├── a2a.ts              # Google A2A Protocol
│   │   ├── crewai.ts           # CrewAI agents
│   │   ├── langchain.ts        # LangChain chains/agents
│   │   └── sitegpt.ts          # SiteGPT WebSocket/REST
│   │
│   ├── strategies/             # Advanced orchestration
│   │   ├── mutations.ts        # 13 prompt mutation types
│   │   ├── pair.ts             # PAIR iterative refinement
│   │   ├── crescendo.ts        # Gradual escalation
│   │   ├── branching.ts        # Conversation branching
│   │   └── attack-tree.ts      # Branching attack tree
│   │
│   ├── reporting/              # Output generation
│   │   ├── markdown.ts         # Markdown report
│   │   ├── sarif.ts            # SARIF format
│   │   ├── junit.ts            # JUnit XML
│   │   ├── compliance.ts       # Compliance framework mapping
│   │   └── executive.ts        # Executive summary
│   │
│   ├── schemas/                # Zod schemas (runtime validation)
│   │   ├── probe.ts            # Probe playbook schema
│   │   ├── config.ts           # Target config schema
│   │   ├── finding.ts          # Finding/verdict schema
│   │   └── index.ts            # Barrel export
│   │
│   ├── types/                  # TypeScript type definitions
│   │   └── index.ts            # All interfaces, enums, type aliases
│   │
│   └── config.ts               # App config, env loading
│
├── _legacy/                    # Python source for reference (delete post-migration)
│   ├── src/keelson/
│   └── tests/
│
├── probes/                     # 210 YAML playbooks (unchanged)
├── agents/                     # Agent instruction MDs (unchanged)
├── commands/                   # Command spec MDs (unchanged)
├── reports/                    # Generated reports
├── docs/plans/                 # Design & implementation plans
├── tests/                      # Vitest tests (mirrors src/ structure)
│   ├── core/
│   ├── adapters/
│   ├── strategies/
│   ├── reporting/
│   └── ...
│
├── package.json
├── tsconfig.json
├── vitest.config.ts
└── .github/workflows/          # CI (rewritten for Node)
```

## Core Patterns

### Types & Schemas

- `types/index.ts` — barrel file with all enums, interfaces, type aliases (camelCase)
- `schemas/` — Zod schemas for runtime validation of external data (snake_case matching YAML)
- Conversion from snake_case → camelCase happens at the loading boundary
- Enums for fixed value sets (Severity, Verdict, Category, MutationType, ScanMode)
- Interfaces for data shapes, not classes (no class hierarchies for data)

### Adapter Pattern

- `Adapter` interface: `send(messages: Turn[]): Promise<AdapterResponse>` + `healthCheck()`
- `BaseAdapter` abstract class: axios instance with retry interceptor (429 with Retry-After, 502/503/504 with exponential backoff)
- Each adapter is a thin class extending `BaseAdapter`, only implementing `send()`
- Factory function `createAdapter(config)` maps config type string to adapter class

### Detection Pipeline

Three layers (matches Python + Jarvis):

1. **Pattern detection** — keyword matching against `vulnerable_if`/`safe_if` criteria + 60+ refusal phrases. Fast, free.
2. **LLM judge** — sends probe objective + conversation + criteria to a judge LLM. Accurate, costly.
3. **Combined** — merges both. Resolution: agree = boost confidence; pattern-VULN + judge-SAFE = trust judge; judge-VULN high confidence = trust judge.

### Engine

- `executeProbe()` — pure function, takes probe + adapter + options, returns Finding
- Multi-turn: sends each turn, accumulates conversation
- Early termination: hard refusal on first turn skips remaining
- Rate limiting: configurable delay between turns
- `onTurn` callback for streaming UI updates

### Scanner

- `scan()` — loads probes, filters by category/severity, executes with configurable concurrency
- Callbacks (`onProbeStart`, `onProbeComplete`, `onProgress`) hook into Ink components
- Chunked `Promise.all` for concurrency control

### CLI + UI Split

- Commander: argument parsing, validation, dispatch
- Ink/React: rendering scan progress, findings, reports
- Hooks bridge engine → UI (`useEngine`, `useStreamingScan`)

## Migration Strategy

1. **Phase 0 — Skeleton** ✅: scaffold project, install deps, configure tsconfig/vitest/eslint/prettier, create `_legacy/`, define all types + schemas + interfaces + base classes. 21 tests passing.
2. **Phase 1 — Parallel tracks**: each developer takes a module group, implements against the skeleton's interfaces
3. **Phase 2 — Integration**: wire modules together, end-to-end scan works
4. **Phase 3 — Cleanup**: delete `_legacy/`, update CI/CD, update README/docs
