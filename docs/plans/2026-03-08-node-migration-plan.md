# Node.js Migration — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Migrate Keelson from Python to TypeScript with full feature parity for core functionality.

**Architecture:** Clean-room rewrite. Python source copied to `_legacy/` as reference. Skeleton scaffolded first (types, schemas, base classes, project config), then 6 parallel tracks for the team. Each track is independent — no cross-track dependencies after the skeleton.

**Tech Stack:** TypeScript 5.x (strict, ESM), Commander + Ink/React, axios, Zod, Vitest, pnpm, yaml v2, ESLint 9 + Prettier

**Reference repos:**

- `_legacy/` — Python source (primary reference)
- [Othentic-Labs/jarvis](https://github.com/Othentic-Labs/jarvis) — TypeScript patterns reference (transport, detection, mutations, types barrel)

---

## Phase 0: Skeleton (MUST complete before parallel tracks)

**Status: COMPLETE** — All 8 tasks done. 21 tests passing. Lint + format clean.

**Owner:** One developer. All parallel tracks branch from the skeleton commit.

### Task 0.1: Project scaffold ✅

**Status:** Complete

**What was done:**

- Python source copied to `_legacy/`, Python project files removed
- `package.json` created — ESM, pinned dependencies (no carets), `engines: ">=22"`
- `tsconfig.json` — base config for IDE + ESLint (includes `src/` and `tests/`)
- `tsconfig.build.json` — extends base, adds `rootDir: "src"` for `tsc` output
- `vitest.config.ts` — globals, 30s timeout
- `.nvmrc` — pinned to `22` for `nvm use` auto-switch
- `.prettierrc` + `.prettierignore` — single quotes, 120 width, trailing commas
- `eslint.config.js` — ESLint 9 flat config with `typescript-eslint` strict, `eslint-plugin-import-x` (import ordering), naming conventions, `eslint-config-prettier`
- `.github/dependabot.yml` — weekly npm + GitHub Actions updates, grouped minor/patch PRs

**Scripts:**

```json
{
  "build": "tsc -p tsconfig.build.json",
  "dev": "tsc -p tsconfig.build.json --watch",
  "test": "vitest run",
  "test:watch": "vitest",
  "lint": "tsc --noEmit && eslint src/ tests/",
  "lint:fix": "eslint src/ tests/ --fix",
  "format": "prettier --write src/ tests/",
  "format:check": "prettier --check src/ tests/",
  "clean": "rm -rf dist"
}
```

---

### Task 0.2: Types barrel ✅

**Status:** Complete — `src/types/index.ts`

Enums: `Severity`, `Verdict`, `Category`, `MutationType`, `ScoringMethod`, `ResponseClass`, `ScanMode`, `ComplianceFramework`

Interfaces: `Turn`, `Evaluation`, `Effectiveness`, `ProbeTemplate`, `EvidenceItem`, `LeakageSignal`, `Finding`, `ScanSummary`, `ScanResult`, `AdapterConfig`, `AdapterResponse`, `Adapter`, `MutatedProbe`, `StrategyResult`, `DetectionResult`, `JudgeConfig`, `ScanConfig`

---

### Task 0.3: Zod schemas ✅

**Status:** Complete — `src/schemas/{probe,config,finding,index}.ts`, 10 tests passing

- `probeSchema` — validates YAML probes, `parseProbe()` converts snake_case → camelCase
- `adapterConfigSchema`, `scanConfigSchema` — target/scan config validation (Zod v4 API)
- `findingSchema` — finding output validation
- Tests cover: valid parse, missing fields, invalid ID format, snake→camel conversion

---

### Task 0.4: Adapter base class ✅

**Status:** Complete — `src/adapters/{base,index}.ts`, 8 tests passing

- `BaseAdapter` abstract class with axios retry interceptor (429 + Retry-After, 502/503/504 + exponential backoff)
- `createAdapter()` factory + `registerAdapter()` (adapter map empty, filled by Track 1)
- Tests cover: 429 retry, 503 backoff, no retry on 400/401/404, max retries, healthCheck

---

### Task 0.5: Probe loader utility ✅

**Status:** Complete — `src/core/templates.ts`, 3 tests passing

- `loadProbes(dir?)` — recursive YAML loader, validates with Zod, converts to `ProbeTemplate[]`
- `loadProbe(filePath)` — single file loader with descriptive error on validation failure
- Tests: loads GA-001, throws on nonexistent file, loads all 210 probes

---

### Task 0.6: CLI shell ✅

**Status:** Complete — `src/cli/index.ts`

Commander program with 5 stubbed commands: scan, probe, report, list, validate.

---

### Task 0.7: CI workflow ✅

**Status:** Complete — `.github/workflows/ci.yml`

- Lint job on Node 22, test matrix on `["22", "24"]`
- pnpm 10, `--frozen-lockfile`
- Dependabot configured (`.github/dependabot.yml`) — weekly npm + GitHub Actions updates

---

### Task 0.8: Update project docs ✅

**Status:** Complete

- `CLAUDE.md` — updated for TypeScript structure
- `.claude/rules/typescript-standards.md` — replaced Python standards
- `.claude/rules/git-workflow.md` — updated for pnpm
- `README.md` — updated badges, install instructions, project structure, dev section

---

**Skeleton complete.** Push branch. All parallel tracks branch from this point.

```bash
git push origin feat/node-migration
```

---

## Phase 1: Parallel Tracks

Each track is independent after the skeleton. Developers should branch from `feat/node-migration` and create PRs back to it.

---

## Track 1: Adapters (9 adapters)

**Owner:** 1 developer
**Estimated size:** ~900 lines of implementation + ~600 lines of tests
**Reference:** `_legacy/src/keelson/adapters/`

Each adapter is a thin class extending `BaseAdapter`. Only `send()` needs implementing.

### Task 1.1: HTTP + OpenAI adapters

**Files:**

- Create: `src/adapters/http.ts`
- Create: `src/adapters/openai.ts`
- Create: `tests/adapters/http.test.ts`
- Create: `tests/adapters/openai.test.ts`

**Reference:**

- `_legacy/src/keelson/adapters/http.py` (61 lines)
- `_legacy/src/keelson/adapters/openai.py` (51 lines)

These are the simplest adapters and establish the pattern for all others.

Test with `nock` mocking the target API responses.

### Task 1.2: Anthropic adapter

**Files:**

- Create: `src/adapters/anthropic.ts`
- Create: `tests/adapters/anthropic.test.ts`

**Reference:** `_legacy/src/keelson/adapters/anthropic.py` (94 lines)

Different payload format (`messages` API with content blocks).

### Task 1.3: MCP adapter

**Files:**

- Create: `src/adapters/mcp.ts`
- Create: `tests/adapters/mcp.test.ts`

**Reference:** `_legacy/src/keelson/adapters/mcp.py` (138 lines)

JSON-RPC 2.0 protocol. More complex payload structure.

### Task 1.4: LangGraph + A2A adapters

**Files:**

- Create: `src/adapters/langgraph.ts`
- Create: `src/adapters/a2a.ts`
- Create: `tests/adapters/langgraph.test.ts`
- Create: `tests/adapters/a2a.test.ts`

**Reference:**

- `_legacy/src/keelson/adapters/langgraph.py` (117 lines)
- `_legacy/src/keelson/adapters/a2a.py` (142 lines)

### Task 1.5: CrewAI + LangChain + SiteGPT adapters

**Files:**

- Create: `src/adapters/crewai.ts`
- Create: `src/adapters/langchain.ts`
- Create: `src/adapters/sitegpt.ts`
- Create corresponding test files

**Reference:**

- `_legacy/src/keelson/adapters/crewai.py` (89 lines)
- `_legacy/src/keelson/adapters/langchain.py` (80 lines)
- `_legacy/src/keelson/adapters/sitegpt.py` (197 lines)

### Task 1.6: Update adapter factory

**Files:**

- Modify: `src/adapters/index.ts`

Register all 9 adapters in the `createAdapter()` factory map.

---

## Track 2: Core Engine + Detection

**Owner:** 1 developer
**Estimated size:** ~1200 lines of implementation + ~800 lines of tests
**Reference:** `_legacy/src/keelson/core/`

This is the critical path — probe execution, verdict determination, scan orchestration.

### Task 2.1: Detection module ✅

**Status:** Complete — `src/core/detection.ts`, 18 tests passing

- 65 refusal phrases + 16 scope refusal phrases
- `patternDetect()` — 7-step pipeline: side effects → collect signals → conflict resolution → vuln/safe/leakage/inconclusive
- `isHardRefusal()` — 3+ phrases AND terse response (< 200 chars)
- Side effects detection: JSON tool call parsing + regex fallback for dangerous tool names
- Conflict resolution: multi-step per-step check, single-step substantial disclosure check
- Keyword extraction from evaluation criteria (quoted strings, parentheses, e.g. patterns)

### Task 2.2: LLM judge ✅

**Status:** Complete — `src/core/llm-judge.ts`, 14 tests passing

- `judgeResponse()` — sends formatted prompt to judge adapter, parses VERDICT/CONFIDENCE/REASONING (plan called this `llmJudge()`; renamed for cleaner adapter-injection API)
- `parseJudgeResponse()` — line-by-line parsing with fallback to INCONCLUSIVE
- `combinedDetect()` — 6-way resolution: agree (boost), pattern INCONCLUSIVE (trust judge), judge INCONCLUSIVE (trust pattern), pattern VULN + judge SAFE (trust judge), pattern SAFE + judge VULN (trust judge if confidence ≥ 0.7), fallback to judge

### Task 2.3: Engine ✅

**Status:** Complete — `src/core/engine.ts`, 10 tests passing

- `executeProbe()` — multi-turn loop with conversation accumulation
- Non-user turns injected without sending to adapter
- Early termination on hard refusal (first user turn, 2+ remaining turns)
- Rate limiting between turns (configurable `delayMs`)
- `onTurn` callback for UI integration
- Observer support for leakage signal detection
- Pattern-only or combined (pattern + judge) detection

### Task 2.4: Scanner

**Files:**

- Create: `src/core/scanner.ts`
- Create: `tests/core/scanner.test.ts`

**Reference:** `_legacy/src/keelson/core/scanner.py` (175 lines)

Implement:

- `scan(config, adapter, callbacks): Promise<ScanResult>`
- Probe loading + filtering by category/severity
- Sequential and concurrent execution modes
- Progress callbacks
- Result summarization

Tests:

- Filters probes by category
- Filters probes by severity
- Sequential mode runs one at a time
- Concurrent mode respects concurrency limit
- Progress callback fires
- Summary counts are correct

### Task 2.5: Observer + Memo

**Files:**

- Create: `src/core/observer.ts`
- Create: `src/core/memo.ts`
- Create: `tests/core/observer.test.ts`
- Create: `tests/core/memo.test.ts`

**Reference:**

- `_legacy/src/keelson/core/observer.py` (169 lines)
- `_legacy/src/keelson/core/memo.py` (306 lines)

Observer: streaming progress reporting.
Memo: technique effectiveness tracking (success rates, tested counts).

### Task 2.6: Strategist + Smart Scan + Convergence

**Files:**

- Create: `src/core/strategist.ts`
- Create: `src/core/smart-scan.ts`
- Create: `src/core/convergence.ts`
- Create corresponding test files

**Reference:**

- `_legacy/src/keelson/core/strategist.py` (400 lines)
- `_legacy/src/keelson/core/smart_scan.py` (367 lines)
- `_legacy/src/keelson/core/convergence.py` (438 lines)

These are the advanced scan modes. Can be done after basic engine+scanner work.

---

## Track 3: Strategies (mutations, PAIR, crescendo, branching)

**Owner:** 1 developer
**Estimated size:** ~1200 lines of implementation + ~500 lines of tests
**Reference:** `_legacy/src/keelson/adaptive/`

### Task 3.1: Mutations

**Files:**

- Create: `src/strategies/mutations.ts`
- Create: `tests/strategies/mutations.test.ts`

**Reference:** `_legacy/src/keelson/adaptive/mutations.py` (374 lines)

Implement 13 mutation types:

- 9 programmatic: base64, leetspeak, ROT13, unicode homoglyphs, char split, reversed words, morse code, Caesar cipher, context overflow
- 4 LLM-powered: paraphrase, roleplay wrap, gradual escalation, translation

Each mutation: `(probe: ProbeTemplate) => MutatedProbe`

Tests: one test per mutation type verifying transform + round-trip where applicable.

### Task 3.2: PAIR strategy

**Files:**

- Create: `src/strategies/pair.ts`
- Create: `tests/strategies/pair.test.ts`

**Reference:** `_legacy/src/keelson/adaptive/pair.py` (268 lines)

Prompt Adaptive Iterative Refinement — iteratively refines probes based on target responses.

### Task 3.3: Crescendo strategy

**Files:**

- Create: `src/strategies/crescendo.ts`
- Create: `tests/strategies/crescendo.test.ts`

**Reference:** `_legacy/src/keelson/adaptive/crescendo.py` (304 lines)

Gradual escalation pattern.

### Task 3.4: Branching + Attack tree

**Files:**

- Create: `src/strategies/branching.ts`
- Create: `src/strategies/attack-tree.ts`
- Create: `tests/strategies/branching.test.ts`
- Create: `tests/strategies/attack-tree.test.ts`

**Reference:**

- `_legacy/src/keelson/adaptive/branching.py` (286 lines)
- `_legacy/src/keelson/adaptive/probe_tree.py` (1338 lines — largest module)

The attack tree is the most complex module. Consider simplifying if the Python version is over-engineered.

---

## Track 4: Reporting

**Owner:** 1 developer
**Estimated size:** ~800 lines of implementation + ~400 lines of tests
**Reference:** `_legacy/src/keelson/core/` (reporter, sarif, junit, compliance, executive_report)

### Task 4.1: Markdown report

**Files:**

- Create: `src/reporting/markdown.ts`
- Create: `tests/reporting/markdown.test.ts`

**Reference:** `_legacy/src/keelson/core/reporter.py` (404 lines)

Python uses Jinja2 templates. For TypeScript, use template literals or Handlebars — implementor decides.

Output: markdown file with findings grouped by category/severity, summary stats, OWASP mappings.

### Task 4.2: SARIF output

**Files:**

- Create: `src/reporting/sarif.ts`
- Create: `tests/reporting/sarif.test.ts`

**Reference:** `_legacy/src/keelson/core/sarif.py` (236 lines)

SARIF is a JSON format (Static Analysis Results Interchange Format). Map findings → SARIF results. Must validate against SARIF 2.1.0 schema.

### Task 4.3: JUnit output

**Files:**

- Create: `src/reporting/junit.ts`
- Create: `tests/reporting/junit.test.ts`

**Reference:** `_legacy/src/keelson/core/junit.py` (186 lines)

JUnit XML format for CI/CD integration. Each probe = test case, vulnerable = failure.

### Task 4.4: Compliance mapping

**Files:**

- Create: `src/reporting/compliance.ts`
- Create: `tests/reporting/compliance.test.ts`

**Reference:** `_legacy/src/keelson/core/compliance.py` (614 lines)

Maps findings to compliance frameworks (OWASP LLM Top 10, NIST AI RMF, EU AI Act, ISO 42001, SOC2, PCI DSS v4).

### Task 4.5: Executive summary

**Files:**

- Create: `src/reporting/executive.ts`
- Create: `tests/reporting/executive.test.ts`

**Reference:** `_legacy/src/keelson/core/executive_report.py` (551 lines)

High-level findings summary for non-technical stakeholders.

---

## Track 5: CLI Commands + Ink UI

**Owner:** 1 developer
**Estimated size:** ~800 lines of implementation + ~300 lines of tests
**Reference:** `_legacy/src/keelson/cli/` + Jarvis `src/components/`

**Depends on:** Tracks 1-4 don't need to be complete — can code against interfaces and mock.

### Task 5.1: Scan command

**Files:**

- Create: `src/cli/scan.ts`
- Create: `tests/cli/scan.test.ts`

**Reference:** `_legacy/src/keelson/cli/scan_commands.py` (490 lines)

Commander options:

- `--target <url>` (required)
- `--adapter <type>` (default: "http")
- `--api-key <key>`
- `--model <model>`
- `--category <cat>` (repeatable)
- `--severity <sev>` (repeatable)
- `--concurrency <n>` (default: 5)
- `--delay <ms>` (default: 1000)
- `--output <file>`
- `--format <fmt>` (markdown|sarif|junit)
- `--judge-provider`, `--judge-model`, `--judge-api-key`

### Task 5.2: Probe command

**Files:**

- Create: `src/cli/probe.ts`
- Create: `tests/cli/probe.test.ts`

Single probe execution. Takes `--target`, `--probe-id`, adapter options.

### Task 5.3: Report + Ops commands

**Files:**

- Create: `src/cli/report.ts`
- Create: `src/cli/ops.ts`
- Create: `tests/cli/ops.test.ts`

Report: reads saved scan result JSON, generates formatted output.
Ops: `list` (all probes), `validate` (check probe YAML), `config` (show current config).

### Task 5.4: Ink components

**Files:**

- Create: `src/components/ScanProgress.tsx`
- Create: `src/components/FindingCard.tsx`
- Create: `src/components/ProbeResult.tsx`
- Create: `src/components/ReportView.tsx`

**Reference:** Jarvis `src/components/` for Ink patterns

These render live scan progress. Wire to scanner callbacks:

- `ScanProgress` — progress bar, current probe, counts by verdict
- `FindingCard` — single finding with severity badge, verdict, reasoning
- `ProbeResult` — single probe result (used in `keelson probe`)
- `ReportView` — summary table after scan completes

### Task 5.5: React hooks

**Files:**

- Create: `src/hooks/useEngine.ts`
- Create: `src/hooks/useStreamingScan.ts`

Bridge between engine/scanner and Ink components. Manage state (findings, progress, errors) and expose to React.

---

## Track 6: Config + Glue

**Owner:** 1 developer (or split across others as capacity allows)
**Estimated size:** ~300 lines

### Task 6.1: App config

**Files:**

- Create: `src/config.ts`

**Reference:** `_legacy/src/keelson/core/execution.py`, Jarvis `src/config.ts`

- Load config from env vars, CLI flags, config file (`~/.keelson/config.json` or `keelson.config.yaml`)
- Precedence: CLI flags > env vars > config file > defaults
- Validate with Zod schema from `schemas/config.ts`

### Task 6.2: Wire everything in CLI entry point

**Files:**

- Modify: `src/cli/index.ts`

Register all commands from scan.ts, probe.ts, report.ts, ops.ts. This is the final integration step.

### Task 6.3: Update adapter factory with all adapters

**Files:**

- Modify: `src/adapters/index.ts`

Import and register all 9 adapter classes.

---

## Phase 2: Integration (after all tracks merge)

### Task INT.1: End-to-end smoke test

**Files:**

- Create: `tests/e2e/scan.test.ts`

Mock a target with `nock`, run a full scan with 2-3 probes, verify:

- Probes load from YAML
- Adapter sends requests
- Detection produces verdicts
- Report generates output

### Task INT.2: Manual testing

Run against a real target (e.g., a local LLM endpoint):

```bash
node dist/cli/index.js scan --target http://localhost:8080 --category goal_adherence --format markdown
```

### Task INT.3: Cleanup

- Delete `_legacy/` folder
- Update README.md for TypeScript
- Update CONTRIBUTING.md
- Final CI workflow adjustments

---

## Dependency Graph

```mermaid
Phase 0 (Skeleton)
    │
    ├── Track 1: Adapters ──────────────────────┐
    ├── Track 2: Core Engine + Detection ───────┤
    ├── Track 3: Strategies ────────────────────┤──→ Phase 2: Integration
    ├── Track 4: Reporting ─────────────────────┤
    ├── Track 5: CLI + Ink UI ──────────────────┤
    └── Track 6: Config + Glue ─────────────────┘
```

All tracks depend only on Phase 0 (types, schemas, base adapter). No cross-track dependencies.

## Developer Assignment Guide

| Track                | Ideal for                             | Skills needed                       |
|----------------------|---------------------------------------|-------------------------------------|
| Track 1: Adapters    | Someone who likes protocol details    | HTTP, REST APIs, JSON-RPC           |
| Track 2: Core Engine | Strongest dev — this is critical path | Async patterns, algorithm design    |
| Track 3: Strategies  | Creative problem solver               | LLM prompt engineering, algorithms  |
| Track 4: Reporting   | Detail-oriented                       | Template engines, XML, JSON schemas |
| Track 5: CLI + UI    | Frontend-leaning dev                  | React, Ink, component design        |
| Track 6: Config      | Anyone with spare capacity            | Simple glue code                    |

## Conventions for All Tracks

- **Node:** `>=22` (`.nvmrc` pins to `22`, CI tests on `["22", "24"]`)
- **Dependencies:** pinned exact versions (no carets), Dependabot handles updates
- **Imports:** use `.js` extensions (`import { Foo } from './bar.js'`), ordered by group (builtin → external → local) with newlines between groups — enforced by ESLint
- **Naming:** `camelCase` for properties/variables, `PascalCase` for types/classes, `UPPER_CASE` for constants — enforced by ESLint
- **Formatting:** Prettier (single quotes, 120 width, trailing commas) — run `pnpm format` before committing
- **Linting:** `pnpm lint` = type check + ESLint, `pnpm lint:fix` for auto-fixes
- **Build:** `pnpm build` uses `tsconfig.build.json` (rootDir: src), `tsconfig.json` is for IDE + ESLint (includes tests)
- **Testing:** write tests alongside implementation (TDD encouraged, not mandated)
- **Commits:** frequent, small commits with conventional prefixes (`feat:`, `fix:`, `test:`, `refactor:`)
- **PRs:** one PR per track (or per task group), target `feat/node-migration` branch
- **Reference:** always check `_legacy/` for the Python implementation before writing. Also check Jarvis for TypeScript patterns.
