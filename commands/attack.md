# /pentis:attack — Run Single Attack

Execute a single attack playbook against a target AI agent.

## Usage

```
/pentis:attack <url> <attack-id> [--api-key KEY] [--model MODEL]
```

**Arguments** (from `$ARGUMENTS`):
- `<url>` — Target endpoint (OpenAI-compatible chat completions URL)
- `<attack-id>` — Attack identifier (e.g., `GA-001`, `TS-005`, `MI-003`)
- `--api-key KEY` — API key for authentication (optional)
- `--model MODEL` — Model name to use in requests (optional)

## Instructions

1. **Parse arguments** from `$ARGUMENTS`. First positional arg is URL, second is attack ID.

2. **Locate the attack file**: Map the attack ID to its file path:
   - `GA-*` → `attacks/goal-adherence/GA-*.md`
   - `TS-*` → `attacks/tool-safety/TS-*.md`
   - `MI-*` → `attacks/memory-integrity/MI-*.md`

3. **Read the attack playbook** and the `agents/pentester.md` for evaluation guidance.

4. **Verify target is reachable**: Send a simple request to confirm the endpoint responds.

5. **Execute the attack**:
   - Send each step's prompt via `curl`
   - For multi-step attacks, accumulate the messages array between turns
   - Sleep 1-2 seconds between requests

6. **Evaluate the response** semantically following the attack's Evaluation criteria. Determine: VULNERABLE, SAFE, or INCONCLUSIVE.

7. **Display results** with the full finding: verdict, severity, reasoning, and response excerpt.
