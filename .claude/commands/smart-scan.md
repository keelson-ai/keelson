# /keelson:smart-scan — Adaptive Engine Scan

Run Keelson's adaptive smart scan engine against a target. Unlike `/scan` (where Claude acts as the pentester), this command runs the compiled TypeScript scanner with the full 6-phase pipeline: infrastructure recon, capability discovery, target classification, probe selection, grouped session execution with memoization, and mid-scan adaptation.

## Usage

```
/keelson:smart-scan <url> [--api-key KEY] [--model MODEL] [--adapter-type TYPE] [--engagement PROFILE] [--judge-provider PROVIDER --judge-model MODEL --judge-api-key KEY] [--category CATEGORY] [--format FORMAT]
```

**Arguments** (from `$ARGUMENTS`):

- `<url>` — Target endpoint URL
- `--api-key KEY` — API key for target authentication (optional)
- `--model MODEL` — Model name for requests (default: `default`)
- `--adapter-type TYPE` — Adapter type: `openai`, `anthropic`, `http`, `browser`, `mcp`, `sitegpt`, `crewai`, `langchain`, `langgraph`, `a2a`, `intercom`, `hubspot` (default: `openai`)
- `--engagement PROFILE` — Engagement profile: `auto`, `stealth-cs-bot`, `stealth-coding-agent`, `stealth-general`, or path to YAML (default: none)
- `--judge-provider PROVIDER` — LLM judge adapter type for semantic evaluation (e.g., `openai`, `anthropic`)
- `--judge-model MODEL` — Judge model name (e.g., `gpt-4o`, `claude-sonnet-4-20250514`)
- `--judge-api-key KEY` — API key for judge
- `--category CATEGORY` — Filter to a single category (optional)
- `--format FORMAT` — Output format: `json`, `markdown`, `sarif`, `junit` (default: `json`)
- `--max-passes N` — Convergence passes for cross-category follow-up (default: `1`)
- `--delay MS` — Milliseconds between requests (default: `1000`)
- `--browser-headless` / `--no-browser-headless` — Browser mode for browser adapter

## Instructions

### Step 1: Parse and Validate

1. **Parse arguments** from `$ARGUMENTS`. The first positional arg is the URL. Extract all optional flags.
2. **Set defaults**: `--model default`, `--adapter-type openai`, `--delay 1000`, `--format json`.
3. **Build the command**: Construct the `keelson scan` CLI invocation with `--smart` and all provided flags.

### Step 2: Execute

4. **Run the scan** using the Bash tool:

```bash
node dist/cli/index.js scan \
  --target "<url>" \
  --smart \
  --adapter-type <type> \
  [--api-key <key>] \
  [--model <model>] \
  [--delay <ms>] \
  [--category <category>] \
  [--engagement <profile>] \
  [--judge-provider <provider> --judge-model <model> --judge-api-key <key>] \
  [--max-passes <n>] \
  [--format <format>] \
  --output-dir reports/
```

- Use `node dist/cli/index.js` to run the compiled CLI directly.
- If the build is stale, run `pnpm build` first.
- Stream output — the scanner prints phase progress, session info, and findings live.
- The scan may take several minutes depending on the target and number of selected probes.

### Step 3: Report

5. **Locate the output file**: The scanner saves results to `reports/` or `~/.keelson/output/`. Find the most recent scan result file.

6. **If format is JSON**, generate a human-readable markdown report:

```bash
node dist/cli/index.js report --input <scan-result.json> --format markdown
```

7. **Display summary** to the user:
   - Total probes executed, vulnerable/safe/inconclusive counts
   - Critical and high findings with probe ID, name, and brief reasoning
   - Defense model observations (if available in output): trigger words, refusal style, defense strength
   - Strategy recommendations logged during the scan
   - Composed probes count (if any were generated)
   - Link to the full report file

### Step 4: Save Report

8. **Save the markdown report** to `reports/scan-YYYY-MM-DD-HHMMSS-<target-slug>.md` if not already saved by the engine.

## Examples

```
# Basic smart scan against OpenAI-compatible endpoint
/keelson:smart-scan https://api.example.com/v1/chat/completions --api-key sk-xxx

# Smart scan with LLM judge for semantic evaluation
/keelson:smart-scan https://api.example.com/v1/chat/completions --api-key sk-xxx --judge-provider openai --judge-model gpt-4o --judge-api-key sk-judge-xxx

# Browser-based scan against a chat widget
/keelson:smart-scan https://www.example.com/chat --adapter-type browser --no-browser-headless

# Stealth scan against a customer service bot
/keelson:smart-scan https://api.example.com/chat --engagement auto

# Single category deep dive with convergence
/keelson:smart-scan https://api.example.com/chat --category goal_adherence --max-passes 3
```
