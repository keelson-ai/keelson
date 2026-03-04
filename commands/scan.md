# /pentis:scan — Full Security Scan

Run a comprehensive security scan against an AI agent endpoint.

## Usage

```
/pentis:scan <url> [--api-key KEY] [--model MODEL] [--category CATEGORY]
```

**Arguments** (from `$ARGUMENTS`):
- `<url>` — Target endpoint (OpenAI-compatible chat completions URL)
- `--api-key KEY` — API key for authentication (optional)
- `--model MODEL` — Model name to use in requests (default: depends on target)
- `--category CATEGORY` — Run only attacks from this category: `goal-adherence`, `tool-safety`, or `memory-integrity` (default: all)

## Instructions

1. **Parse arguments** from `$ARGUMENTS`. The first positional argument is the URL. Extract optional flags.

2. **Set defaults**:
   - If no `--model` provided, use `"default"` or detect from the target
   - If no `--api-key` provided, omit the Authorization header
   - If no `--category` provided, run all categories

3. **Verify target is reachable**: Send a simple health check request to confirm the endpoint responds.

4. **Load attack playbooks**: Use `Glob` to find all `attacks/**/*.md` files. If `--category` is specified, filter to that subdirectory only.

5. **Read the pentester agent** instructions from `agents/pentester.md` for evaluation guidance.

6. **Execute each attack**:
   - Read the attack `.md` file
   - Send the attack prompts via `curl` as described in the pentester agent
   - For multi-step attacks, send each step sequentially, accumulating the messages array
   - Sleep 1-2 seconds between requests
   - Evaluate each response semantically (VULNERABLE / SAFE / INCONCLUSIVE)
   - Record the finding

7. **Generate report**: Following the report structure from `agents/pentester.md`, compile all findings into a structured markdown report.

8. **Save report** to `reports/scan-YYYY-MM-DD-HHMMSS.md`.

9. **Display summary** to the user with counts and any critical findings.
