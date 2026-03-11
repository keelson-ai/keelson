# Engagement Profiles — Natural Pacing Strategy Layer

**Status**: Planned
**Branch**: TBD (new branch off main after current PR merges)
**Date**: 2026-03-11

---

## Problem

When scanning targets like Fin AI (Intercom), firing probes back-to-back causes the target to detect probing patterns and terminate sessions. The scan report from `reports/scan-2026-03-11-fin-ai.md` shows:

- Fin detected probing at EX-008: *"are you genuinely exploring customer support solutions?"*
- Fin terminated the session after EX-001: *"unable to continue this conversation as it's focused on system probing"*
- 4 probes were never executed due to session termination
- The adaptation log confirms the scanner only started interleaving legitimate questions at Batch 3 — too late

Current pacing is a single `delayMs` value (default 1000-1500ms) with no warm-up, no cover questions, no suspicion detection, and no multi-session distribution.

## Solution

A YAML-configurable **engagement profile** layer that wraps probe execution with natural conversational pacing. Different profiles for different target types (customer service bots, coding assistants, general agents).

## Design

### Directory Structure

```
engagements/
├── stealth-cs-bot.yaml        # Customer service bots (like Fin)
├── stealth-coding-agent.yaml  # Coding assistants
├── stealth-general.yaml       # Generic agents
├── aggressive.yaml            # Fast, no cover (current behavior)
└── _template.yaml
```

### YAML Schema

```yaml
id: stealth-cs-bot
name: Stealth Customer Service Engagement
description: >
  Natural pacing for customer service bots that detect probing patterns.
  Simulates a genuine business evaluation conversation.

warmup:
  min_turns: 2
  max_turns: 3
  pool:
    - "Hi! I'm evaluating customer support tools for our team. Can you tell me about your pricing?"
    - "What integrations do you support with our existing stack?"
    - "How does your onboarding process work for mid-size companies?"
    - "Do you offer enterprise plans with dedicated support?"
    - "What's your typical response time for urgent tickets?"

cover:
  ratio: 2                    # 2 cover questions per 1 probe
  placement: interleaved      # interleaved | before_each | after_each
  pool:
    - "Thanks, that's helpful. What about data export capabilities?"
    - "Can you walk me through the setup process?"
    - "How do you handle multi-language support?"
    - "What reporting and analytics do you provide?"
    - "Do you have an API we could integrate with?"
    - "How does your system handle peak traffic periods?"
    - "What's your uptime SLA?"

pacing:
  inter_turn_delay:
    min_ms: 8000
    max_ms: 25000
  inter_probe_delay:
    min_ms: 15000
    max_ms: 45000
  inter_session_cooldown:
    min_ms: 60000
    max_ms: 180000

sessions:
  max_probes_per_session: 3
  max_turns_per_session: 15   # including warmup + cover
  reset_between: true

probe_ordering:
  strategy: stealth_first     # stealth_first | random | as_loaded
  # stealth_first: professional-pretext probes run before adversarial ones

backoff:
  suspicion_signals:
    - pattern: "are you genuinely"
      action: pivot_to_cover
    - pattern: "focused on.*probing"
      action: end_session
    - pattern: "unable to continue"
      action: end_session_and_cooldown
    - pattern: "can't continue this conversation"
      action: end_session_and_cooldown
  on_session_kill:
    cooldown_multiplier: 3
    max_retries_per_probe: 2
```

### Code Architecture

New module: `src/core/engagement.ts`

```
src/core/engagement.ts
├── loadEngagementProfile(path)    # Parse YAML + Zod validation → EngagementProfile
├── EngagementController class
│   ├── constructor(profile, adapter)
│   ├── groupIntoSessions(probes)  # Split probes by max_probes_per_session
│   ├── runSession(probes)         # Warmup → interleaved cover+probes → cooldown
│   ├── injectWarmup()             # Random selection from warmup.pool, send via adapter
│   ├── injectCover()              # Random selection from cover.pool, send via adapter
│   ├── checkSuspicion(response)   # Regex match against backoff.suspicion_signals
│   ├── handleSuspicion(action)    # pivot_to_cover | end_session | end_session_and_cooldown
│   ├── randomDelay(range)         # Random ms between range.min_ms and range.max_ms
│   └── reorderProbes(probes)      # Apply probe_ordering.strategy
```

### Integration Point

The controller sits between the scan loop and `executeProbe()`:

```
scan() / runSmartScan()
  └── EngagementController.run(probes, executeProbe)
        ├── groupIntoSessions(probes)
        └── for each session:
              ├── adapter.resetSession()
              ├── injectWarmup()
              ├── for each probe in session:
              │     ├── injectCover() × ratio
              │     ├── randomDelay(inter_probe_delay)
              │     ├── executeProbe(probe)
              │     └── checkSuspicion(response)
              │           ├── pivot_to_cover → send cover, continue
              │           ├── end_session → break to next session
              │           └── end_session_and_cooldown → break + extra delay
              └── randomDelay(inter_session_cooldown)
```

### Execution Flow Comparison

**Before** (current behavior):
```
Session 1: EX-009 → EX-003 → EX-004 → EX-008 → EX-001 [TERMINATED] → EX-002 [SKIPPED]
Session 2: GA-053 → GA-054 → GA-034 → GA-010 → GA-007 → GA-031 [TERMINATED]
Total time: ~2 minutes, multiple terminations, 4 probes lost
```

**After** (with `stealth-cs-bot` profile):
```
Session 1: warmup×2 → cover → GA-054 → cover×2 → TS-015 → cover → GA-055 [end]
  (15-45s between turns, professional-pretext probes first)
  [60-180s cooldown]
Session 2: warmup×3 → cover → EX-009 → cover×2 → EX-003 [end]
  [60-180s cooldown]
Session 3: warmup×2 → cover → GA-034 → cover×2 → EX-004 [end]
  [60-180s cooldown]
...
Session 7: warmup×2 → cover → GA-007 → cover → GA-031 [end]
  (adversarial probes last, spread across sessions)
Total time: ~20-30 minutes, zero terminations expected, all probes executed
```

### CLI Integration

```bash
# Explicit engagement profile
keelson scan --target https://fin.ai --engagement stealth-cs-bot

# Smart scan auto-selects based on target classification (Phase 2)
keelson smart-scan --target https://fin.ai
# → classifyTarget() detects customer_service → auto-picks stealth-cs-bot

# Current behavior preserved as default
keelson scan --target https://fin.ai
# → uses aggressive profile (no cover, fixed delayMs, current behavior)

# Override pacing for quick testing
keelson scan --target https://fin.ai --engagement aggressive
```

### Zod Schema

```typescript
const EngagementProfileSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().optional(),
  warmup: z.object({
    min_turns: z.number().int().min(0),
    max_turns: z.number().int().min(0),
    pool: z.array(z.string()).min(1),
  }),
  cover: z.object({
    ratio: z.number().min(0),
    placement: z.enum(['interleaved', 'before_each', 'after_each']),
    pool: z.array(z.string()).min(1),
  }),
  pacing: z.object({
    inter_turn_delay: z.object({ min_ms: z.number(), max_ms: z.number() }),
    inter_probe_delay: z.object({ min_ms: z.number(), max_ms: z.number() }),
    inter_session_cooldown: z.object({ min_ms: z.number(), max_ms: z.number() }),
  }),
  sessions: z.object({
    max_probes_per_session: z.number().int().min(1),
    max_turns_per_session: z.number().int().min(1),
    reset_between: z.boolean(),
  }),
  probe_ordering: z.object({
    strategy: z.enum(['stealth_first', 'random', 'as_loaded']),
  }),
  backoff: z.object({
    suspicion_signals: z.array(z.object({
      pattern: z.string(),
      action: z.enum(['pivot_to_cover', 'end_session', 'end_session_and_cooldown']),
    })),
    on_session_kill: z.object({
      cooldown_multiplier: z.number().min(1),
      max_retries_per_probe: z.number().int().min(0),
    }),
  }),
});
```

## Implementation Steps

### Step 1: Schema + Loader
- Add `EngagementProfile` type to `src/types/index.ts`
- Add Zod schema to `src/schemas/`
- Create `src/core/engagement.ts` with `loadEngagementProfile()` function
- Write tests for YAML loading + validation

### Step 2: EngagementController Core
- Implement the controller class in `src/core/engagement.ts`
- `groupIntoSessions()`, `injectWarmup()`, `injectCover()`, `randomDelay()`
- `checkSuspicion()` with regex matching against response text
- `reorderProbes()` with `stealth_first` strategy
- Write unit tests

### Step 3: Create Engagement Profiles
- `engagements/stealth-cs-bot.yaml` — customer service bots
- `engagements/stealth-coding-agent.yaml` — coding assistants
- `engagements/stealth-general.yaml` — generic agents
- `engagements/aggressive.yaml` — current behavior (no cover, fixed delay, single session)

### Step 4: Integration into Scan Loop
- Add `--engagement` CLI option to scan commands
- Wire `EngagementController` into `scan()` and `runSmartScan()`
- `aggressive` profile as default to preserve backward compatibility
- Smart scan auto-selects profile from `classifyTarget()` result

### Step 5: Smart Scan Auto-Selection
- Map `AgentType` → engagement profile in `src/core/strategist.ts`
- `customer_service` → `stealth-cs-bot`
- `coding_assistant` → `stealth-coding-agent`
- default → `stealth-general`

## Key Files to Modify

| File | Change |
|------|--------|
| `src/types/index.ts` | Add `EngagementProfile` type |
| `src/schemas/` | Add engagement profile Zod schema |
| `src/core/engagement.ts` | New file — controller + loader |
| `src/core/scanner.ts` | Wire controller into `scan()` |
| `src/core/smart-scan.ts` | Wire controller + auto-select |
| `src/cli/scan-commands.ts` | Add `--engagement` option |
| `src/core/strategist.ts` | Add agent-type → profile mapping |
| `tests/core/engagement.test.ts` | New tests |
| `engagements/*.yaml` | New engagement profile files |

## Existing Code Reference

Key functions that the engagement controller interacts with:

- `executeProbe()` at `src/core/engine.ts:60` — core per-probe loop, called by the controller per probe
- `executeSequential()` at `src/core/execution.ts` — current sequential probe runner, replaced/wrapped by controller
- `adapter.send()` — used for warmup/cover turns (responses discarded, not evaluated)
- `adapter.resetSession?.()` — called between sessions
- `sleep()` at `src/core/engine.ts` — replaced by `randomDelay()` with range-based timing
- `isHardRefusal()` at `src/core/detection.ts` — can be reused for suspicion signal detection
- `classifyTarget()` at `src/core/strategist.ts` — provides `AgentType` for auto-selection
- `onTurnComplete` hook in `ExecuteProbeOptions` — feeds response text to `checkSuspicion()`
