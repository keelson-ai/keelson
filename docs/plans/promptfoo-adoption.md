# Promptfoo → Keelson: Feature Adoption Plan

Analysis of [promptfoo](https://github.com/promptfoo/promptfoo) for features and patterns to adopt into keelson, ordered by impact.

---

## 1. Risk Scoring Model (HIGH IMPACT)

Promptfoo has a computed risk score combining multiple factors — keelson only has static `severity` on probes.

**What to adopt:**
- `impact` (from probe severity) × `exploitability` (actual success rate) × `humanFactor` (can a human do this?) × `strategyWeight` (attack complexity)
- Score 0–10 mapped to critical / high / medium / low / informational
- Strategy metadata: each strategy gets `humanExploitable: boolean` and `humanComplexity: 'low' | 'medium' | 'high'` — a base64 encoding attack is realistic (10/10 weight), a GCG token optimization is not (1/10)

**Score calculation:**
- Impact Base: Critical=4, High=3, Medium=2, Low=1
- Exploitation Modifier: Linear based on success rate (1.5–4.0)
- Human Factor: +0–1.5 if humans can execute
- Complexity Penalty: −0.1 to −0.5 for easy exploits
- Formula: `impact + exploitation + humanFactor + complexity` (capped at 10)

**Risk level mapping:**
- 9.0+: Critical
- 7.0–8.9: High
- 4.0–6.9: Medium
- 1.0–3.9: Low
- 0: Informational

**Where:** New `src/core/risk-scoring.ts`, integrated into `summarize.ts` and reporting.

---

## 2. Probe Presets / Collections (HIGH IMPACT)

Promptfoo has named plugin sets: `foundation` (38 core), `harmful` (22), `pii`, `medical`, `financial`, etc. Users write `plugins: [harmful, pii]` instead of listing 60 probes.

**What to adopt:**
- Named probe collections: `default`, `owasp-top10`, `agentic`, `data-privacy`, `quick` (fast subset)
- CLI: `keelson scan --preset owasp-top10` instead of `--category goal_adherence`
- Map collections to compliance frameworks (OWASP, NIST, EU AI Act, MITRE ATLAS)

**Where:** New `src/core/presets.ts`, extend CLI with `--preset` flag.

---

## 3. Multi-Language Attack Generation (HIGH IMPACT)

Promptfoo generates attacks in 15+ languages (Bengali, Swahili, Javanese, etc.) to bypass English-only guardrails. Keelson has no multilingual support.

**What to adopt:**
- `--language` flag that translates probe payloads via LLM before sending
- Batch translation with retry/fallback
- Some languages bypass safety filters more effectively — this is a real attack vector

**Where:** New `src/strategies/multilingual.ts`, or as a mutation type in `mutations.ts`.

---

## 4. Additional Encoding / Bypass Strategies (MEDIUM-HIGH)

Keelson has 13 mutations. Promptfoo adds several keelson is missing:

| Strategy | What it does |
|----------|-------------|
| `ascii-smuggling` | Unicode tag characters (invisible text injection) |
| `homoglyph` | Visually identical characters from other scripts |
| `emoji` | Emoji-encoded instructions |
| `authoritative-markup-injection` | XML/HTML schema that tricks structured output parsers |
| `math-prompt` | Mathematical reasoning framing to bypass filters |
| `citation` | False citation injection |
| `gcg` | Greedy Coordinate Gradient token optimization |
| `best-of-n` | Generate N variants, select the one that works |
| `goat` | Goal-Oriented Adversarial Testing (iterative LLM refinement) |

**Where:** Extend `src/strategies/mutations.ts` and add new strategy files.

---

## 5. Domain-Specific Probe Packs (MEDIUM-HIGH)

Promptfoo has industry-vertical plugins keelson completely lacks:

- **Financial** (11): SOX compliance, calculation errors, sycophancy, misconduct
- **Medical** (6): anchoring bias, hallucination, off-label drug use
- **Pharmacy** (3): controlled substances, drug interactions, dosage errors
- **Insurance** (4): coverage discrimination, PHI disclosure
- **E-commerce** (4): order fraud, price manipulation, PCI-DSS bypass
- **Telecom** (12): CPNI disclosure, account takeover, E911 abuse

**What to adopt:** Create domain-specific probe YAML packs under `probes/domains/`. These are high-value for enterprise customers.

---

## 6. Grader Remediation Suggestions (MEDIUM)

Each promptfoo grader returns `getSuggestions(): ResultSuggestion[]` — actionable fix recommendations per vulnerability type. Keelson's reports list findings but don't tell you *how to fix*.

**What to adopt:**
- Add a `remediation` field to probe YAML or a lookup table per category
- Include remediation in markdown/executive reports
- Example: "BFLA detected → Implement function-level authorization checks, validate user roles before executing privileged operations"

**Where:** Extend probe schema with optional `remediation:` field, update `src/reporting/`.

---

## 7. Caching Layer Integration (MEDIUM)

Promptfoo has transparent caching (Keyv + 14-day TTL) keyed on `hash(prompt + config + provider)`. Keelson has `src/adapters/cache.ts` but it's a separate wrapper, not integrated.

**What to adopt:**
- Integrate caching into the base adapter so ALL adapters get it transparently
- `--no-cache` flag to bypass
- Hash-based cache keys (prompt content + adapter config)
- Massive speedup when re-running scans or during development

**Where:** Integrate into `src/adapters/base.ts`.

---

## 8. Custom Plugin / Probe Protocol (MEDIUM)

Promptfoo supports `file:///path/to/plugin.ts` — users can write custom attack plugins in TypeScript. Keelson is YAML-only.

**What to adopt:**
- Support `file://` protocol for custom probe generators that return dynamic YAML
- Let users write TypeScript functions that generate probe content programmatically
- Useful for: company-specific policies, dynamic payload generation, integration with internal tools

**Where:** Extend probe loader in `src/core/` to support `.ts` / `.js` probe generators.

---

## 9. Compliance Framework Mappings (MEDIUM)

Promptfoo maps every plugin to compliance frameworks: MITRE ATLAS, NIST AI RMF, OWASP LLM, OWASP Agentic, EU AI Act, ISO 42001, GDPR, DoD AI Ethics. Keelson has `owasp_id` on probes and some compliance reporting, but the mapping is shallow.

**What to adopt:**
- Add `frameworks:` field to probe YAML mapping to multiple standards
- `keelson scan --framework nist-ai-rmf` to run only probes mapped to that framework
- Compliance-specific report sections with control-level pass/fail

**Where:** Extend probe schema, add framework constants, update compliance reports.

---

## 10. HTML Interactive Report (LOW-MEDIUM)

Promptfoo has a web viewer dashboard. Keelson outputs markdown / SARIF / JUnit but no interactive HTML.

**What to adopt:**
- Single-file HTML report (embedded CSS/JS) that can be opened in a browser
- Filterable findings table, severity charts, drill-down into probe results
- No server needed — just `open report.html`

**Where:** New `src/reporting/html.ts`.

---

## 11. OpenTelemetry Tracing (LOW)

Promptfoo has built-in OpenTelemetry integration for observability. Useful for debugging long scans and understanding performance.

**Where:** Would live in `src/tracing/` — lower priority but nice for enterprise.

---

## Summary

| # | Feature | Impact | Effort | Priority |
|---|---------|--------|--------|----------|
| 1 | Risk scoring model | High | Medium | P0 |
| 2 | Probe presets / collections | High | Low | P0 |
| 3 | Multi-language attacks | High | Medium | P0 |
| 4 | More encoding strategies | Medium-High | Medium | P1 |
| 5 | Domain-specific probe packs | Medium-High | High | P1 |
| 6 | Remediation suggestions | Medium | Low | P1 |
| 7 | Caching integration | Medium | Low | P2 |
| 8 | Custom plugin protocol | Medium | Medium | P2 |
| 9 | Compliance framework mappings | Medium | Medium | P2 |
| 10 | HTML interactive report | Low-Medium | Medium | P3 |
| 11 | OpenTelemetry tracing | Low | Medium | P3 |

The top 3 (risk scoring, presets, multilingual) would significantly close the gap with promptfoo's red teaming capabilities while being achievable without major architectural changes.
