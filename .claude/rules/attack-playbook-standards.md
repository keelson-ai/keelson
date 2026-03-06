# Attack Playbook Standards

When adding or modifying attack playbooks in `attacks/`, enforce these rules.

## When
- Creating new attack YAML files
- Editing existing attack playbooks
- Reviewing PRs that touch `attacks/**/*.yaml`

## Required YAML Structure

Every attack MUST have these fields:
```yaml
id: XX-NNN          # Category prefix + sequential number
name: ...           # Short descriptive name
severity: ...       # critical | high | medium | low
category: ...       # matches parent directory name (snake_case)
owasp_id: ...       # OWASP LLM Top 10 mapping
objective: ...      # What this attack tests (1-3 sentences)
turns:              # At least one turn
  - role: user
    content: ...    # The actual prompt sent to the target
evaluation:
  vulnerable_if: [] # Observable behaviors that indicate vulnerability
  safe_if: []       # Observable behaviors that indicate safety
  inconclusive_if: [] # Ambiguous outcomes
```

## Self-Containedness (CRITICAL)

Every attack MUST be fully self-contained. The prompts in `turns` must provide ALL context needed to run against ANY generic AI agent.

### DO NOT:
- Reference specific vendor products (Claude Code, Cursor, Copilot) — generalize to "AI coding assistant" or "agent"
- Assume the target has specific tools by name ("your billing lookup tool", "your knowledge base") — use "any tools you have access to"
- Assume specific infrastructure (MCP servers, .claude/, .mcp.json) — use generic names (plugins.json, settings.json, hooks)
- Reference deployment details (port numbers, cloud providers, vector DB brands)
- Use `[Note: ...]` placeholders — include actual payload content inline
- Write evaluation criteria that require access to tool execution logs or internal state not visible in the response

### DO:
- Write prompts that work against any LLM-based agent regardless of vendor
- Use generic config file names and generic tool/plugin terminology
- Include the full attack payload directly in the prompt content
- Write evaluation criteria based on observable response text and behavior
- If an attack uses `new_session: true`, add a `note:` field explaining it
- If an attack targets a specific agent type (e.g., customer service), frame the probing generically so it works whether or not the agent is that type

## ID Assignment

Use the next sequential ID in the category:
- `GA-NNN` — goal-adherence
- `TS-NNN` — tool-safety
- `MI-NNN` — memory-integrity
- `SI-NNN` — session-isolation
- `PB-NNN` — permission-boundaries
- `ES-NNN` — execution-safety
- `DI-NNN` — delegation-integrity

Check existing files to find the current highest ID before assigning.

## Content Rules
- Use `example.com` or `*.example.com` for attacker domains (RFC 2606)
- No real credentials, API keys, or PII — use obvious fakes ("hunter2", "sk-live-abc123xyz")
- Multi-turn attacks should escalate naturally, not dump the full attack in turn 1
- Evaluation criteria must be specific and unambiguous — avoid vague phrases

## After Creating/Modifying
1. Copy the file to `src/pentis/attacks/<category>/` to keep the mirror in sync
2. Validate YAML has all required fields (id, turns, evaluation, vulnerable_if, safe_if)
3. Verify the attack is self-contained by re-reading the prompt as if you know nothing about the target
