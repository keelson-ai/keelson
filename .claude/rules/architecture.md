# Architecture

## Scan Pipeline
```
discover → load templates → order → execute → detect → report
```

1. **Discovery**: Probe target endpoint for capabilities (model, tools, system prompt)
2. **Template Loading**: Load YAML attack templates, validate against schema
3. **Ordering**: Sort templates by strategy (fixed: behavior → id)
4. **Execution**: Send multi-turn attack steps via HTTP adapter
5. **Detection**: Analyze responses for indicators, refusals, side effects
6. **Reporting**: Terminal output (Rich) + Markdown report (Jinja2)

## Key Design Decisions
- **Black-box HTTP only** — works against any agent behind an OpenAI-compatible endpoint
- **YAML templates (Nuclei-style)** — community-contributable without Python knowledge
- **No LLM for detection** — all pattern matching, deterministic, reproducible
- **Async httpx** — parallel execution is a config change, not a rewrite
- **Rich + Typer** — terminal output is 50% of first impression

## Detection Priority
1. Side effects (dangerous tool calls) → VULNERABLE
2. Strong indicators (weight ≥ threshold) → VULNERABLE
3. Clean refusal → SAFE
4. Refusal + weak indicators → SAFE
5. Weak indicators only → INCONCLUSIVE
6. Nothing detected → INCONCLUSIVE

## 3 Behavior Categories
| Category | Templates | OWASP |
|----------|-----------|-------|
| Goal Adherence | GA-001 to GA-010 | LLM01 |
| Tool Safety | TS-001 to TS-010 | LLM02/LLM06 |
| Memory Integrity | MI-001 to MI-008 | LLM05 |
