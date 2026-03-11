# Core Scanning & Probing Libraries

Libraries directly impacting probe execution, target communication, detection accuracy, and evaluation quality. UI/UX, reporting formats, and developer convenience libraries are excluded.

---

## Probe Execution

### p-queue — Priority Concurrency Control

Replaces the manual `Array.from({ length: concurrency }, () => worker())` pattern with priority-based execution (high-severity probes first), built-in rate limiting, pause/resume, and adaptive concurrency.

```ts
import PQueue from "p-queue"

const queue = new PQueue({ concurrency: 3 })
await queue.add(() => runProbe(target), { priority: probe.severity === "critical" ? 1 : 0 })
```

### p-retry — Composable Retry Logic

The base adapter's axios retry interceptor is tightly coupled and doesn't compose across the Intercom polling logic, browser stability waits, LLM judge calls, or strategy iterations. `p-retry` gives per-operation retry with exponential backoff and custom abort conditions.

```ts
import pRetry from "p-retry"

const response = await pRetry(() => adapter.sendMessage(probe), { retries: 3 })
```

### execa — Modern Subprocess Execution

Used extensively across strategies (branching, crescendo), chain execution, and defense hooks. Better error handling, stream management, timeout support, and cleanup over raw `child_process`.

```ts
import { execa } from "execa"

const { stdout } = await execa("node", ["agent-runner.js"], { timeout: 30_000 })
```

---

## Target Communication

### @modelcontextprotocol/sdk — Official MCP Protocol

The MCP adapter (`src/adapters/mcp.ts`) manually implements JSON-RPC 2.0. The official SDK handles protocol negotiation, capability discovery, transport layers (stdio, SSE, streamable HTTP), and schema evolution automatically.

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js"
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js"

const client = new Client({ name: "keelson", version: "1.0.0" })
await client.connect(new StreamableHTTPClientTransport(new URL(targetUrl)))
const result = await client.callTool({ name: "chat", arguments: { message: probe } })
```

### proxy-agent — HTTP Proxy Support

Zero proxy support today. Enterprise environments require scanning through corporate proxies, SOCKS tunnels, or interception proxies (Burp/ZAP). Auto-detects `HTTP_PROXY` / `HTTPS_PROXY` env vars.

```ts
import { ProxyAgent } from "proxy-agent"

const agent = new ProxyAgent()
axios.create({ httpAgent: agent, httpsAgent: agent })
```

### playwright-extra — Stealth Browser Sessions

Extends Playwright with stealth plugins for anti-bot evasion and fingerprint management during browser-based probe sessions against web chat widgets.

```ts
import { chromium } from "playwright-extra"
import StealthPlugin from "puppeteer-extra-plugin-stealth"

chromium.use(StealthPlugin())
```

### cheerio — HTML Response Extraction

The Intercom adapter strips HTML with regex; the browser adapter deals with raw DOM content. Cheerio gives reliable HTML parsing for response extraction — more robust than regex for detection accuracy.

```ts
import cheerio from "cheerio"

const $ = cheerio.load(html)
const answer = $(".message.assistant").text()
```

---

## Detection & Evaluation

### fastest-levenshtein — Fuzzy Pattern Detection

Detection (`src/core/detection.ts`) uses exact substring matching via `string.includes()`. Levenshtein distance catches near-misses — agents that leak system prompts with minor rewording, typos, or paraphrasing. Reduces false negatives.

```ts
import { distance } from "fastest-levenshtein"

const similarity = 1 - distance(leaked, original) / Math.max(leaked.length, original.length)
if (similarity > 0.85) flag("near-verbatim disclosure")
```

### js-rouge — Text Similarity Scoring

ROUGE scoring quantifies overlap between a response and known reference texts (system prompts, training data). Gives a numeric confidence score for leakage rather than binary substring match.

```ts
import { rouge } from "js-rouge"

const score = rouge(agentResponse, knownSystemPrompt, { rouge: "rougeL" })
if (score.f > 0.6) flag("significant system prompt leakage")
```

### lru-cache — Judge Evaluation Caching

The `CachingAdapter` reimplements LRU+TTL from scratch. `lru-cache` is battle-tested and supports `fetchMethod` for transparent cache-through — cache LLM judge evaluations and PAIR prober refinements to cut LLM costs during convergence scans.

---

## Probe Generation

### nunjucks — Parameterized Probe Payloads

Probes are currently static YAML. Nunjucks enables injecting target-specific context (company name, product, known tool names) into probe templates at scan time without duplicating playbooks.

```ts
import nunjucks from "nunjucks"

const rendered = nunjucks.renderString(probe.turns[0].content, {
  targetName: "Acme Support Bot",
  toolHint: "billing_lookup",
})
```

---

## Observability

### pino — Structured Scan Logging

Strategy transitions, pattern match results, technique effectiveness, and cross-category feedback loops are currently invisible. Pino with JSON output gives traceability across multi-pass convergence scans, PAIR iterations, and branching tree traversal.

```ts
import pino from "pino"

const logger = pino()
logger.info({ probe: "GA-001", turn: 2, strategy: "crescendo", verdict: "VULNERABLE" })
```
