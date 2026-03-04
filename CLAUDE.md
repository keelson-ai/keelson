# Pentis — Claude Code Plugin

AI agent security scanner implemented as a pure Claude Code plugin. Claude Code becomes the pentester: reads attack playbooks, sends prompts via curl, semantically evaluates responses, and generates reports.

## Installation

```bash
# Load as a Claude Code plugin
claude --plugin-dir /path/to/Pentis-Monorepo
```

## Usage

```bash
/pentis:scan <url> [--api-key KEY] [--model MODEL] [--category CATEGORY]
/pentis:attack <url> <attack-id> [--api-key KEY] [--model MODEL]
/pentis:report [report-file]
```

## Structure

```
Pentis-Monorepo/
├── .claude-plugin/
│   └── plugin.json              # Plugin manifest
├── agents/
│   └── pentester.md             # Main pentester agent instructions
├── commands/
│   ├── scan.md                  # /pentis:scan — full security scan
│   ├── attack.md                # /pentis:attack — single attack
│   └── report.md                # /pentis:report — generate report
├── attacks/                     # 28 attack playbooks (pure .md)
│   ├── goal-adherence/          # GA-001..010 (OWASP LLM01)
│   ├── tool-safety/             # TS-001..010 (OWASP LLM02/LLM06)
│   └── memory-integrity/        # MI-001..008 (OWASP LLM05)
├── reports/                     # Generated scan reports
├── .claude/
│   ├── rules/
│   │   ├── git-workflow.md      # Git workflow rules
│   │   └── security-review.md   # Security review checklist
│   └── settings.json
├── CLAUDE.md                    # This file
├── README.md                    # Public readme
└── LICENSE
```

## Attack Playbook Format

Each attack is a `.md` file with this structure:

```markdown
# ID: Attack Name

**Severity**: Critical/High/Medium/Low | **Category**: ... | **OWASP**: LLM0X — Name

## Objective
What this attack tests.

## Attack Steps
### Step 1
Send to target:
> The prompt to send

### Step 2 (if multi-turn)
Send as follow-up:
> Next prompt

## Evaluation
**Vulnerable if**: [criteria]
**Safe if**: [criteria]
**Inconclusive if**: [criteria]
```

## Adding New Attacks

1. Choose category: `goal-adherence/`, `tool-safety/`, or `memory-integrity/`
2. Use next ID in sequence (e.g., GA-011, TS-011, MI-009)
3. Follow the playbook format above
4. Include OWASP LLM Top 10 mapping
5. Write clear evaluation criteria

## Key Design Decisions

- **No code** — pure markdown plugin. Claude Code is the pentester.
- **curl for targets** — OpenAI-compatible chat completions API via `curl -s -X POST`
- **Semantic evaluation** — Claude judges responses (no regex/heuristics)
- **Multi-turn support** — accumulate messages array in curl payloads
- **Rate limiting** — sleep 1-2s between requests
