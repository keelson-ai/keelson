# Node.js Migration — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Migrate Keelson from Python to TypeScript with full feature parity for core functionality.

**Architecture:** Clean-room rewrite. Python source copied to `_legacy/` as reference. Skeleton scaffolded first (types, schemas, base classes, project config), then 6 parallel tracks for the team. Each track is independent — no cross-track dependencies after the skeleton.

**Tech Stack:** TypeScript 5.x (strict, ESM), Commander + Ink/React, axios, Zod, Vitest, pnpm, yaml v2

**Reference repos:**

- `_legacy/` — Python source (primary reference)
- [Othentic-Labs/jarvis](https://github.com/Othentic-Labs/jarvis) — TypeScript patterns reference (transport, detection, mutations, types barrel)

---

## Phase 0: Skeleton (MUST complete before parallel tracks)

**Owner:** One developer. All parallel tracks branch from the skeleton commit.

### Task 0.1: Project scaffold

**Files:**

- Create: `package.json`
- Create: `tsconfig.json`
- Create: `vitest.config.ts`
- Create: `.gitignore`
- Create: `.npmrc`

**Steps:**

1. Copy Python source to `_legacy/`:

```bash
mkdir -p _legacy
cp -r src/keelson _legacy/src/
cp -r tests _legacy/tests/
```

1. Remove Python project files from root (keep `probes/`, `agents/`, `commands/`, `docs/`, `reports/`, `.claude/`, `.github/`):

```bash
rm -rf src/ tests/ scripts/
rm -f pyproject.toml pyrightconfig.json Makefile .pre-commit-config.yaml
rm -f Dockerfile Dockerfile.dev docker-compose.yml
```

1. Initialize Node project:

```bash
pnpm init
```

1. Write `package.json`:

```json
{
  "name": "keelson",
  "version": "0.5.0",
  "type": "module",
  "description": "AI agent security scanner",
  "bin": {
    "keelson": "dist/cli/index.js"
  },
  "scripts": {
    "build": "tsc",
    "dev": "tsc --watch",
    "test": "vitest run",
    "test:watch": "vitest",
    "lint": "tsc --noEmit",
    "clean": "rm -rf dist"
  },
  "engines": {
    "node": ">=20"
  }
}
```

1. Install dependencies:

```bash
pnpm add commander ink react yaml zod axios chalk
pnpm add -D typescript @types/node @types/react vitest nock @ink/testing-library
```

1. Write `tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "esModuleInterop": true,
    "forceConsistentCasingInFileNames": true,
    "skipLibCheck": true,
    "declaration": true,
    "sourceMap": true,
    "outDir": "dist",
    "rootDir": "src",
    "resolveJsonModule": true,
    "jsx": "react-jsx"
  },
  "include": ["src/**/*.ts", "src/**/*.tsx"],
  "exclude": ["node_modules", "dist", "_legacy"]
}
```

1. Write `vitest.config.ts`:

```typescript
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    include: ["tests/**/*.test.ts"],
    testTimeout: 30_000,
  },
});
```

1. Verify: `pnpm build` succeeds (empty build), `pnpm test` runs (no tests yet).

2. Commit:

```bash
git add -A
git commit -m "chore: scaffold TypeScript project for node migration"
```

---

### Task 0.2: Types barrel

**Files:**

- Create: `src/types/index.ts`

**Reference:** `_legacy/src/keelson/core/models.py` (383 lines)

**Steps:**

1. Create `src/types/index.ts` with all enums and interfaces. This is the single source of truth for all type definitions in the project.

Must include at minimum:

- Enums: `Severity`, `Verdict`, `Category`, `MutationType`, `ScanMode`
- Interfaces: `Turn`, `Evaluation`, `Effectiveness`, `ProbeTemplate`, `Finding`, `ScanResult`, `ScanSummary`
- Interfaces: `AdapterConfig`, `AdapterResponse`, `Adapter`
- Interfaces: `MutatedProbe`, `StrategyResult`, `DetectionResult`, `ScanConfig`

Conventions:

- Use `camelCase` for all properties (external snake_case converted at boundary)
- Use enums for fixed value sets (not union types)
- Use interfaces for data shapes (not classes)
- Reference `_legacy/src/keelson/core/models.py` for field completeness but adapt to TS idioms
- Reference Jarvis `src/types/index.ts` for barrel file patterns

1. Verify: `pnpm build` passes

2. Commit:

```bash
git add src/types/
git commit -m "feat: add core type definitions"
```

---

### Task 0.3: Zod schemas

**Files:**

- Create: `src/schemas/probe.ts`
- Create: `src/schemas/config.ts`
- Create: `src/schemas/finding.ts`
- Create: `src/schemas/index.ts`

**Reference:** `_legacy/src/keelson/core/yaml_templates.py` (225 lines), `_legacy/src/keelson/core/models.py`

**Steps:**

1. Create Zod schemas that validate external data (YAML probes, config files, API responses).

`schemas/probe.ts` — validates YAML probe playbook files:

- `id`: regex `^[A-Z]{2}-\d{3}$`
- `turns`: array of `{role, content}`, min 1
- `evaluation`: `{vulnerable_if, safe_if, inconclusive_if}`
- All field names in `snake_case` (matching YAML)
- Export `RawProbe` type via `z.infer`
- Export `parseProbe(raw: unknown): ProbeTemplate` that validates + converts to camelCase

`schemas/config.ts` — validates target/scan config.

`schemas/finding.ts` — validates finding output shape.

`schemas/index.ts` — barrel re-export.

1. Write tests: `tests/schemas/probe.test.ts`

- Valid probe parses correctly
- Missing required field fails
- Invalid ID format fails
- Snake_case converts to camelCase

1. Run: `pnpm test` — passes

2. Commit:

```bash
git add src/schemas/ tests/schemas/
git commit -m "feat: add Zod validation schemas for probes and config"
```

---

### Task 0.4: Adapter base class

**Files:**

- Create: `src/adapters/base.ts`
- Create: `src/adapters/index.ts`

**Reference:** `_legacy/src/keelson/adapters/base.py` (113 lines)

**Steps:**

1. Create `BaseAdapter` abstract class:

- Constructor takes `AdapterConfig`, creates axios instance
- Retry interceptor: 429 (respect `Retry-After`), 502/503/504 (exponential backoff)
- Abstract `send(messages: Turn[]): Promise<AdapterResponse>`
- Default `healthCheck()` implementation

1. Create `src/adapters/index.ts` with `createAdapter()` factory function (initially only maps to placeholder, real adapters added in Track 2).

2. Write tests: `tests/adapters/base.test.ts`

- Retry on 429 with Retry-After
- Retry on 503 with backoff
- No retry on 400/401/404
- Max retries exhausted throws

Use `nock` to mock HTTP responses.

1. Run: `pnpm test` — passes

2. Commit:

```bash
git add src/adapters/ tests/adapters/
git commit -m "feat: add adapter base class with retry logic"
```

---

### Task 0.5: Probe loader utility

**Files:**

- Create: `src/core/templates.ts`

**Reference:** `_legacy/src/keelson/core/yaml_templates.py` (225 lines)

**Steps:**

1. Create `loadProbes(dir?: string): Promise<ProbeTemplate[]>`:

- Defaults to `probes/` relative to project root
- Recursively reads all `.yaml` files
- Parses with `yaml` package
- Validates each with `probeSchema`
- Converts snake_case → camelCase
- Returns typed `ProbeTemplate[]`

1. Create `loadProbe(filePath: string): Promise<ProbeTemplate>` for single file.

2. Write tests: `tests/core/templates.test.ts`

- Loads a real probe from `probes/goal-adherence/GA-001.yaml`
- Returns correct typed structure
- Invalid YAML throws with descriptive error

1. Commit:

```bash
git add src/core/templates.ts tests/core/
git commit -m "feat: add probe YAML loader with Zod validation"
```

---

### Task 0.6: CLI shell

**Files:**

- Create: `src/cli/index.ts`

**Steps:**

1. Create minimal Commander program with subcommands stubbed:

```typescript
#!/usr/bin/env node
import { Command } from "commander";

const program = new Command()
  .name("keelson")
  .description("AI agent security scanner")
  .version("0.5.0");

program.command("scan").description("Run security scan").action(() => {
  console.log("scan: not yet implemented");
});

program.command("probe").description("Run single probe").action(() => {
  console.log("probe: not yet implemented");
});

program.command("report").description("Generate report").action(() => {
  console.log("report: not yet implemented");
});

program.command("list").description("List available probes").action(() => {
  console.log("list: not yet implemented");
});

program.parse();
```

1. Verify: `pnpm build && node dist/cli/index.js --help` works

2. Commit:

```bash
git add src/cli/
git commit -m "feat: add CLI shell with stubbed commands"
```

---

### Task 0.7: CI workflow

**Files:**

- Create/overwrite: `.github/workflows/ci.yml`

**Steps:**

1. Write CI workflow:

- Trigger on push/PR
- Node 20 + pnpm
- `pnpm install`, `pnpm lint`, `pnpm test`

1. Commit:

```bash
git add .github/workflows/ci.yml
git commit -m "chore: add Node.js CI workflow"
```

---

### Task 0.8: Update project docs

**Files:**

- Modify: `CLAUDE.md` — update structure section, remove Python references
- Modify: `.claude/rules/python-standards.md` → rename/replace with `typescript-standards.md`
- Modify: `.claude/rules/git-workflow.md` — replace ruff/uv commands with pnpm equivalents

**Steps:**

1. Update all project docs to reflect TypeScript stack.

2. Commit:

```bash
git add CLAUDE.md .claude/rules/
git commit -m "docs: update project docs for TypeScript migration"
```

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

### Task 2.1: Detection module

**Files:**

- Create: `src/core/detection.ts`
- Create: `tests/core/detection.test.ts`

**Reference:** `_legacy/src/keelson/core/detection.py` (470 lines)

Implement:

- `REFUSAL_PHRASES` constant (60+ phrases)
- `patternDetect(probe, conversation): DetectionResult`
- Keyword extraction from `vulnerable_if` / `safe_if` criteria
- Conflicting signal resolution (vuln + safe → check substance)
- Helper: `isHardRefusal(content): boolean`

Tests:

- Clear vulnerability detected
- Clear refusal detected
- Conflicting signals (refusal + disclosure)
- Inconclusive when no signal
- Each refusal phrase category works

### Task 2.2: LLM judge

**Files:**

- Create: `src/core/llm-judge.ts`
- Create: `tests/core/llm-judge.test.ts`

**Reference:** `_legacy/src/keelson/core/llm_judge.py` (208 lines)

Implement:

- `llmJudge(probe, conversation, config): Promise<DetectionResult>`
- `formatJudgePrompt()` — structured prompt with objective + criteria + conversation
- `parseJudgeResponse()` — extracts VERDICT / CONFIDENCE / REASONING
- `combinedDetect()` — merges pattern + judge with resolution rules

Tests (mock the LLM call with `nock`):

- Judge returns VULNERABLE → parsed correctly
- Judge returns SAFE → parsed correctly
- Combined: both agree → boosted confidence
- Combined: pattern VULN + judge SAFE → trusts judge
- Combined: judge VULN high confidence → trusts judge
- Malformed judge response → falls back to pattern

### Task 2.3: Engine

**Files:**

- Create: `src/core/engine.ts`
- Create: `tests/core/engine.test.ts`

**Reference:** `_legacy/src/keelson/core/engine.py` (162 lines)

Implement:

- `executeProbe(probe, options): Promise<Finding>`
- Multi-turn execution loop
- Early termination on hard refusal
- Rate limiting between turns
- `onTurn` callback for UI integration

Tests (mock adapter):

- Single-turn probe produces finding
- Multi-turn probe accumulates conversation
- Hard refusal terminates early
- Rate limiting delay respected
- onTurn callback fires per turn

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

- **Imports:** use `.js` extensions (`import { Foo } from "./bar.js"`)
- **Naming:** `camelCase` for properties/variables, `PascalCase` for types/classes
- **Testing:** write tests alongside implementation (TDD encouraged, not mandated)
- **Commits:** frequent, small commits with conventional prefixes (`feat:`, `fix:`, `test:`, `refactor:`)
- **PRs:** one PR per track (or per task group), target `feat/node-migration` branch
- **Reference:** always check `_legacy/` for the Python implementation before writing. Also check Jarvis for TypeScript patterns.
