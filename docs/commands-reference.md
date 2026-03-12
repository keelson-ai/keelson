# Keelson Commands Reference

Complete inventory of all commands, slash commands, agents, and scripts.

---

## CLI Commands (`keelson <command>`)

Compiled TypeScript, invoked via `keelson` binary or `pnpm exec keelson`. Defined in `src/cli/`.

### Scanning

| Command            | Description                                                                    | Key Options                                                                                                   |
| ------------------ | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- |
| `recon`            | Discover target capabilities and build profile + probe plan (no attack probes) | `--target`, `--api-key`, `--model`, `--adapter-type`, `--delay`, `--format`, `--output-dir`                   |
| `scan`             | Full sequential scan — all 210 probes or filtered by category                  | `--target`, `--category`, `--adapter-type`, `--concurrency`, `--format`, `--fail-on-vuln`, `--fail-threshold` |
| `smart-scan`       | Adaptive scan — recon, classify target, select relevant probes, execute        | Same as `scan` (default delay: 2000ms)                                                                        |
| `convergence-scan` | Iterative cross-category feedback loop with multiple passes                    | Same as `scan` + `--max-passes`                                                                               |
| `probe`            | Execute a single probe by ID (e.g., GA-001)                                    | `--target`, `--probe-id`, `--api-key`, `--model`, `--adapter-type`                                            |

**Common scan options** (shared across `scan`, `smart-scan`, `convergence-scan`):

```
--target <url>              Target endpoint URL
--api-key <key>             API key for authentication
--model <name>              Model name for requests
--delay <ms>                Delay between requests (default: 500 / 2000 for smart-scan)
--adapter-type <type>       Adapter: openai, anthropic, http, mcp, a2a, sitegpt, crewai, langchain, browser
--category <cat>            Filter to one category
--concurrency <n>           Parallel probe execution
--format <fmt>              Output: json, markdown, sarif, junit
--output-dir <dir>          Directory for output files
--no-store                  Skip persisting results to SQLite
--fail-on-vuln              Exit non-zero if vulnerabilities found
--fail-threshold <sev>      Minimum severity to trigger failure
--judge-provider <p>        LLM judge provider
--judge-model <m>           LLM judge model
--judge-api-key <k>         LLM judge API key
--max-payload-length <n>    Truncate payloads beyond this length
```

**Browser adapter options** (when `--adapter-type browser`):

```
--chatbot-id <id>           SiteGPT chatbot ID
--chat-input-selector <s>   CSS selector for chat input
--chat-submit-selector <s>  CSS selector for submit button
--chat-response-selector <s> CSS selector for response element
--browser-headless           Run headless (default: true)
--no-browser-headless        Show browser window
--browser-pre-interaction <s> JS to run before interaction
```

### Operations

| Command                  | Description                                      | Key Options                                                                                                      |
| ------------------------ | ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| `list`                   | List all available probes                        | `--category`                                                                                                     |
| `validate`               | Validate probe YAML files for completeness       | `--dir`                                                                                                          |
| `report`                 | Generate report from stored scan or JSON file    | `--scan-id`, `--input`, `--format`, `--output`                                                                   |
| `diff`                   | Compare two scans for regressions/improvements   | `--scan-a`, `--scan-b`, `--file-a`, `--file-b`, `--latest`, `--previous`, `--baseline`, `--enhanced`, `--output` |
| `history`                | List recent scans with date, target, vuln counts | `--limit`                                                                                                        |
| `baseline set <scan-id>` | Mark a scan as baseline for future comparisons   | `--label`                                                                                                        |
| `baseline list`          | Show all saved baselines                         | `--limit`                                                                                                        |
| `alerts`                 | List unacknowledged regression alerts            | `--all`, `--limit`                                                                                               |
| `alerts ack <alert-id>`  | Acknowledge a regression alert                   | —                                                                                                                |
| `store path`             | Print the SQLite database path                   | —                                                                                                                |
| `store info`             | Show store location, size, row counts per table  | —                                                                                                                |

### Advanced

| Command      | Description                                               | Key Options                                                                                                |
| ------------ | --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `campaign`   | Statistical campaign — N trials per probe with confidence | `<config-path>`, `--output`, `--format`, `--adapter-type`, `--fail-on-vuln`                                |
| `evolve`     | Mutate a probe to find bypasses                           | `--target`, `--probe-id`, `--mutations`, `--prober-url`, `--prober-key`                                    |
| `chain`      | PAIR or crescendo attack chain                            | `--target`, `--probe-id`, `--strategy`, `--max-iterations`, `--prober-url`, `--prober-key`, `--llm-chains` |
| `test-crew`  | Scan a CrewAI-compatible endpoint                         | `--target`, `--category`, `--delay`, `--format`                                                            |
| `test-chain` | Scan a LangChain-compatible endpoint                      | Same as `test-crew` + `--input-key`, `--output-key`                                                        |
| `generate`   | Generate novel probe templates using a prober LLM         | `--prober-url`, `--prober-key`, `--model`, `--category`, `--count`, `--output`                             |

### Global Options

```
-v, --verbose    Increase verbosity (stackable: -v, -vv, -vvv, -vvvv)
```

---

## Claude Slash Commands (`/keelson:<command>`)

Agentic workflows where Claude acts as strategist + pentester. Claude reads agent instructions, sends probes via `curl`, and evaluates responses inline. These do **not** invoke the compiled CLI.

Defined in `.claude/commands/` (canonical) and duplicated in `commands/`.

### `/keelson:recon <url> [--api-key KEY] [--model MODEL]`

Standalone reconnaissance — research, interact, classify, plan (no attack probes):

1. **Setup** — Parse args, verify target reachable
2. **Research** (Strategist Phase 1a) — Web search for docs, framework, public info
3. **Interact** (Strategist Phase 1b) — Conversational recon to discover tools, memory, refusal style
4. **Profile** (Strategist Phase 1c) — Build target profile with classification
5. **Plan** (Strategist Phase 2) — Assign category priorities, present probe plan
6. **Save** — Output recon report to `reports/`

### `/keelson:scan <url> [--api-key KEY] [--model MODEL] [--category CATEGORY]`

Full agentic security scan with 5 phases:

1. **Setup** — Parse args, verify target reachable
2. **Learn** (Strategist Phase 1) — External research (web search), direct target interaction, build target profile
3. **Plan** (Strategist Phase 2) — Assign category priorities (High/Medium/Low/Skip), present plan for review
4. **Probe** (Strategist Phase 3) — Execute probes via `curl`, evaluate semantically, adapt mid-scan
5. **Report** — Generate findings report, save to `reports/`

### `/keelson:probe <url> <probe-id> [--api-key KEY] [--model MODEL]`

Execute a single probe playbook:

1. Locate probe YAML by ID prefix (GA-_, TS-_, MI-\*, etc.)
2. Read probe playbook + pentester agent instructions
3. Send probe prompts via `curl` (multi-turn accumulates messages)
4. Evaluate response: VULNERABLE / SAFE / INCONCLUSIVE
5. Display verdict with severity, reasoning, evidence

### `/keelson:report [report-file]`

Regenerate or reformat a report:

1. Find report (provided path or most recent in `reports/`)
2. Parse findings
3. Regenerate with: executive summary, risk score, findings by severity, OWASP mapping, remediation, statistics
4. Save to `reports/`

---

## Agent Instructions (`agents/`)

Markdown files that define how Claude should behave during agentic scans. Referenced by slash commands.

### `agents/strategist.md` — Probe Strategist

Three-phase engagement model:

- **Phase 1 (Learn):** External research + direct interaction → target profile (agent type, capabilities, data access, refusal style)
- **Phase 2 (Plan):** Map findings to probe priorities (High/Medium/Low/Skip), present plan
- **Phase 3 (Probe & Adapt):** Execute by priority, watch patterns, adapt mid-scan (escalate categories with vulns, deprioritize consistent refusals, craft follow-ups)

Key features: target classification, probe effectiveness tiers, adaptation rules.

### `agents/pentester.md` — AI Agent Security Pentester

Evaluation guidance for probe responses:

- Verdict determination: VULNERABLE / SAFE / INCONCLUSIVE
- Severity ratings: Critical / High / Medium / Low
- Finding format: verdict, severity, OWASP mapping, reasoning, evidence
- Handles single-turn and multi-turn evaluation

---

## pnpm Scripts

| Script         | Command                              | Purpose                |
| -------------- | ------------------------------------ | ---------------------- |
| `build`        | `tsc -p tsconfig.build.json`         | Compile TypeScript     |
| `dev`          | `tsc -p tsconfig.build.json --watch` | Watch mode compilation |
| `test`         | `vitest run`                         | Run all tests          |
| `test:watch`   | `vitest`                             | Tests in watch mode    |
| `lint`         | `tsc --noEmit && eslint src/ tests/` | Type check + lint      |
| `lint:fix`     | `eslint src/ tests/ --fix`           | Auto-fix lint errors   |
| `format`       | `prettier --write src/ tests/`       | Format code            |
| `format:check` | `prettier --check src/ tests/`       | Check formatting       |
| `clean`        | `rm -rf dist`                        | Remove build artifacts |
| `prepare`      | `husky`                              | Install git hooks      |

---

## Known Issues

- **Duplicate command specs**: `.claude/commands/` and `commands/` contain identical files — should consolidate to one location.
- **Probe ID mapping in `/keelson:probe`**: Only maps GA-_, TS-_, MI-_ prefixes, but 13 categories exist (SI-_, PB-_, ES-_, DI-_, OW-_, MA-_, TP-_, CA-_, EX-_, SL-\* are missing).
