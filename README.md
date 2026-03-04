# Pentis

AI Agent Security Scanner — social engineering attacks against LLM-powered agents, implemented as a Claude Code plugin.

Pentis uses Claude Code as the pentester. It reads attack playbooks, sends prompts to target agents via curl, semantically evaluates responses, and generates structured security reports.

## Installation

```bash
# Clone the repository
git clone https://github.com/Pentis-AI/Pentis-Monorepo.git

# Use as a Claude Code plugin
claude --plugin-dir ./Pentis-Monorepo
```

## Usage

```bash
# Full security scan against a target
/pentis:scan http://localhost:11434/v1/chat/completions

# Scan with authentication and specific model
/pentis:scan http://api.example.com/v1/chat/completions --api-key sk-xxx --model gpt-4

# Scan a single category
/pentis:scan http://localhost:11434/v1/chat/completions --category goal-adherence

# Run a single attack
/pentis:attack http://localhost:11434/v1/chat/completions GA-001

# Regenerate a report
/pentis:report
```

## Attack Categories

| Category | IDs | Count | OWASP | Description |
|----------|-----|-------|-------|-------------|
| Goal Adherence | GA-001..010 | 10 | LLM01 — Prompt Injection | Direct override, role hijacking, system prompt extraction, delimiter injection, payload splitting, encoding evasion, few-shot jailbreak, context overflow, hypothetical injection, nested instruction injection |
| Tool Safety | TS-001..010 | 10 | LLM02, LLM06 | File system access, command injection, SQL injection, unauthorized API calls, file write abuse, env var extraction, privilege escalation, path traversal, email abuse, database modification |
| Memory Integrity | MI-001..008 | 8 | LLM05 — Insecure Plugin Design | History poisoning, identity persistence, behavior drift, false tool results, summarization attack, instruction anchoring, session state confusion, cross-turn exfiltration |

## How It Works

1. **Read** — Claude reads attack playbooks from `attacks/**/*.md`
2. **Send** — Prompts are sent to the target via `curl` (OpenAI-compatible API)
3. **Evaluate** — Claude semantically judges each response as VULNERABLE / SAFE / INCONCLUSIVE
4. **Report** — Findings are compiled into a structured markdown report with OWASP mapping

## Report Output

Reports include:
- Executive summary with vulnerability counts
- Findings grouped by severity (Critical → Low)
- OWASP LLM Top 10 mapping for each finding
- Attack prompts and response excerpts as evidence
- Actionable remediation recommendations

## Adding Attacks

Create a new `.md` file in the appropriate `attacks/` subdirectory:

```markdown
# XX-NNN: Attack Name

**Severity**: High | **Category**: Category Name | **OWASP**: LLM0X — Name

## Objective
What this attack tests.

## Attack Steps

### Step 1
Send to target:
> The attack prompt

## Evaluation

**Vulnerable if**:
- Criteria for vulnerability

**Safe if**:
- Criteria for safety
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add or modify attack playbooks
4. Submit a pull request

## License

Apache 2.0
