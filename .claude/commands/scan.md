# /keelson:scan — Full Security Scan

Run a comprehensive security scan against an AI agent endpoint.

## Usage

```
/keelson:scan <url> [--api-key KEY] [--model MODEL] [--category CATEGORY] [--profile PATH]
```

**Arguments** (from `$ARGUMENTS`):

- `<url>` — Target endpoint (OpenAI-compatible chat completions URL)
- `--api-key KEY` — API key for authentication (optional)
- `--model MODEL` — Model name to use in requests (default: depends on target)
- `--category CATEGORY` — Run only probes from this category (default: all)
- `--profile PATH` — Path to an existing recon report to skip the Learn phase (optional)

## Instructions

### Step 1: Setup

1. **Parse arguments** from `$ARGUMENTS`. The first positional arg is the URL. Extract optional flags.
2. **Set defaults**: If no `--model`, use `"default"`. If no `--api-key`, omit auth header.
3. **Verify target is reachable**: Send a simple health check request.

### Step 2: Learn — `agents/recon.md`

If `--profile` is provided, read the existing recon report and skip to Step 3.

Otherwise, follow the recon agent's full methodology:

4. **Research the target externally** (Phase 1a): Use web search to understand the product, framework, and capabilities.
5. **Interact with the target** (Phase 1b): Conversational recon to fill gaps — tools, data access, memory, refusal patterns. Record any vulnerabilities found.
6. **Build a target profile** (Phase 1c): Compile findings using the recon agent's classification taxonomy and profile format.

### Step 3: Plan — `agents/strategist.md`

7. **Select probes**: Follow the strategist's probe selection logic and engagement profiles. Assign priorities based on the target profile. If `--category` is specified, override and run all probes in that category.
8. **Present the probe plan**: Display the plan in the strategist's format with category priorities, probe counts, and rationale. Wait for user review before proceeding.

### Step 4: Probe — `agents/pentester.md` + `agents/judge.md`

9. **Load probe playbooks**: Probe locations are mapped in the `agent-context` rule. Read selected probe YAML files directly.

10. **Execute probes** following the pentester's execution order (info disclosure first, then High → Medium → Low):
    - Send probe prompts via `curl` using patterns from the `agent-context` rule
    - For multi-step probes, accumulate the messages array between turns
    - Sleep 1-2 seconds between requests
    - **Evaluate each response** using the judge's methodology: check for refusal-with-disclosure, calibrate severity against the target profile, apply INCONCLUSIVE thresholds
    - Record the finding

11. **Adapt mid-scan** using the pentester's adaptation triggers: Escalate categories where vulns are found, deprioritize categories with consistent refusals, craft follow-up probes for interesting findings. Log all plan changes.

### Step 5: Report — `agents/reporter.md`

12. **Generate report** following the reporter's full structure:
    - Executive summary with risk score
    - Target profile
    - Research summary
    - Probe plan
    - Detailed findings with evidence
    - Adaptation log
    - Skipped probes with rationale
    - Recommendations prioritized by actual risk
    - OWASP LLM Top 10 mapping

13. **Save report** to `reports/scan-YYYY-MM-DD-HHMMSS.md`.

14. **Display summary** to the user with counts, critical findings, and how many probes were skipped.
