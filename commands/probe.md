# /keelson:probe — Run Single Probe

Execute a single probe playbook against a target AI agent.

## Usage

```
/keelson:probe <url> <probe-id> [--api-key KEY] [--model MODEL]
```

**Arguments** (from `$ARGUMENTS`):
- `<url>` — Target endpoint (OpenAI-compatible chat completions URL)
- `<probe-id>` — Probe identifier (e.g., `GA-001`, `TS-005`, `MI-003`)
- `--api-key KEY` — API key for authentication (optional)
- `--model MODEL` — Model name to use in requests (optional)

## Instructions

1. **Parse arguments** from `$ARGUMENTS`. First positional arg is URL, second is probe ID.

2. **Locate the probe file**: Map the probe ID to its file path:
   - `GA-*` → `probes/goal-adherence/GA-*.md`
   - `TS-*` → `probes/tool-safety/TS-*.md`
   - `MI-*` → `probes/memory-integrity/MI-*.md`

3. **Read the probe playbook** and the `agents/pentester.md` for evaluation guidance.

4. **Verify target is reachable**: Send a simple request to confirm the endpoint responds.

5. **Execute the probe**:
   - Send each step's prompt via `curl`
   - For multi-step probes, accumulate the messages array between turns
   - Sleep 1-2 seconds between requests

6. **Evaluate the response** semantically following the probe's Evaluation criteria. Determine: VULNERABLE, SAFE, or INCONCLUSIVE.

7. **Display results** with the full finding: verdict, severity, reasoning, and response excerpt.
