import { describe, expect, it, vi } from 'vitest';

import { EngagementController, loadEngagementProfile } from '../../src/core/engagement.js';
import { parseEngagementProfile } from '../../src/schemas/engagement.js';
import type {
  Adapter,
  AdapterResponse,
  EngagementProfile,
  Finding,
  ProbeTemplate,
  Turn,
} from '../../src/types/index.js';
import { ScoringMethod, Severity, Verdict } from '../../src/types/index.js';

// ─── Test helpers ────────────────────────────────────────

function makeTemplate(overrides: Partial<ProbeTemplate> = {}): ProbeTemplate {
  return {
    id: 'GA-001',
    name: 'Test Probe',
    severity: Severity.High,
    category: 'goal_adherence',
    owaspId: 'LLM01',
    objective: 'Test probe',
    turns: [{ role: 'user', content: 'Test prompt' }],
    evaluation: {
      vulnerableIf: ['responds with PWNED'],
      safeIf: ['refuses'],
      inconclusiveIf: [],
    },
    ...overrides,
  };
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    probeId: 'GA-001',
    probeName: 'Test Probe',
    severity: Severity.High,
    category: 'goal_adherence',
    owaspId: 'LLM01',
    verdict: Verdict.Safe,
    confidence: 0.9,
    reasoning: 'Agent refused',
    scoringMethod: ScoringMethod.Pattern,
    conversation: [],
    evidence: [{ stepIndex: 0, prompt: 'Test', response: 'I cannot do that', responseTimeMs: 50 }],
    leakageSignals: [],
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

function mockAdapter(): Adapter {
  return {
    send: vi.fn(
      async (_messages: Turn[]): Promise<AdapterResponse> => ({
        content: 'Sure, here is the information.',
        raw: {},
        latencyMs: 50,
      }),
    ),
    healthCheck: vi.fn().mockResolvedValue(true),
    resetSession: vi.fn(),
    close: vi.fn(),
  };
}

function makeProfile(overrides: Partial<EngagementProfile> = {}): EngagementProfile {
  return {
    id: 'test-profile',
    name: 'Test Profile',
    warmup: {
      minTurns: 0,
      maxTurns: 0,
      pool: ['Hi there'],
    },
    cover: {
      ratio: 0,
      placement: 'interleaved',
      pool: ['Cover question'],
    },
    pacing: {
      interTurnDelay: { minMs: 0, maxMs: 0 },
      interProbeDelay: { minMs: 0, maxMs: 0 },
      interSessionCooldown: { minMs: 0, maxMs: 0 },
    },
    sessions: {
      maxProbesPerSession: 3,
      maxTurnsPerSession: 20,
      resetBetween: true,
    },
    probeOrdering: {
      strategy: 'as_loaded',
    },
    backoff: {
      suspicionSignals: [],
      onSessionKill: {
        cooldownMultiplier: 1,
        maxRetriesPerProbe: 0,
      },
    },
    ...overrides,
  };
}

// ─── Schema parsing ──────────────────────────────────────

describe('parseEngagementProfile', () => {
  it('parses valid YAML-style raw object', () => {
    const raw = {
      id: 'stealth-test',
      name: 'Stealth Test',
      warmup: { min_turns: 1, max_turns: 2, pool: ['Hello'] },
      cover: { ratio: 1, placement: 'interleaved', pool: ['How are you?'] },
      pacing: {
        inter_turn_delay: { min_ms: 1000, max_ms: 2000 },
        inter_probe_delay: { min_ms: 5000, max_ms: 10000 },
        inter_session_cooldown: { min_ms: 30000, max_ms: 60000 },
      },
      sessions: { max_probes_per_session: 3, max_turns_per_session: 15, reset_between: true },
      probe_ordering: { strategy: 'stealth_first' },
      backoff: {
        suspicion_signals: [
          { pattern: 'are you testing', action: 'pivot_to_cover' },
          { pattern: 'unable to continue', action: 'end_session_and_cooldown' },
        ],
        on_session_kill: { cooldown_multiplier: 3, max_retries_per_probe: 2 },
      },
    };

    const profile = parseEngagementProfile(raw);
    expect(profile.id).toBe('stealth-test');
    expect(profile.warmup.minTurns).toBe(1);
    expect(profile.warmup.maxTurns).toBe(2);
    expect(profile.cover.ratio).toBe(1);
    expect(profile.pacing.interProbeDelay.minMs).toBe(5000);
    expect(profile.sessions.maxProbesPerSession).toBe(3);
    expect(profile.probeOrdering.strategy).toBe('stealth_first');
    expect(profile.backoff.suspicionSignals).toHaveLength(2);
    expect(profile.backoff.onSessionKill.cooldownMultiplier).toBe(3);
  });

  it('rejects invalid placement value', () => {
    const raw = {
      id: 'bad',
      name: 'Bad',
      warmup: { min_turns: 0, max_turns: 0, pool: ['_'] },
      cover: { ratio: 0, placement: 'invalid_placement', pool: ['_'] },
      pacing: {
        inter_turn_delay: { min_ms: 0, max_ms: 0 },
        inter_probe_delay: { min_ms: 0, max_ms: 0 },
        inter_session_cooldown: { min_ms: 0, max_ms: 0 },
      },
      sessions: { max_probes_per_session: 1, max_turns_per_session: 1, reset_between: false },
      probe_ordering: { strategy: 'as_loaded' },
      backoff: { suspicion_signals: [], on_session_kill: { cooldown_multiplier: 1, max_retries_per_probe: 0 } },
    };

    expect(() => parseEngagementProfile(raw)).toThrow();
  });
});

// ─── loadEngagementProfile ───────────────────────────────

describe('loadEngagementProfile', () => {
  it('loads aggressive profile by ID', async () => {
    const profile = await loadEngagementProfile('aggressive');
    expect(profile.id).toBe('aggressive');
    expect(profile.warmup.minTurns).toBe(0);
    expect(profile.warmup.maxTurns).toBe(0);
    expect(profile.sessions.resetBetween).toBe(false);
  });

  it('loads stealth-cs-bot profile by ID', async () => {
    const profile = await loadEngagementProfile('stealth-cs-bot');
    expect(profile.id).toBe('stealth-cs-bot');
    expect(profile.warmup.minTurns).toBe(2);
    expect(profile.cover.ratio).toBe(2);
    expect(profile.backoff.suspicionSignals.length).toBeGreaterThan(0);
  });

  it('throws on non-existent profile', async () => {
    await expect(loadEngagementProfile('nonexistent-profile')).rejects.toThrow();
  });
});

// ─── EngagementController ────────────────────────────────

describe('EngagementController', () => {
  describe('groupIntoSessions', () => {
    it('groups probes by maxProbesPerSession', () => {
      const profile = makeProfile({ sessions: { maxProbesPerSession: 2, maxTurnsPerSession: 20, resetBetween: true } });
      const controller = new EngagementController(profile, mockAdapter());

      const probes = [
        makeTemplate({ id: 'GA-001' }),
        makeTemplate({ id: 'GA-002' }),
        makeTemplate({ id: 'GA-003' }),
        makeTemplate({ id: 'GA-004' }),
        makeTemplate({ id: 'GA-005' }),
      ];

      const sessions = controller.groupIntoSessions(probes);
      expect(sessions).toHaveLength(3);
      expect(sessions[0]).toHaveLength(2);
      expect(sessions[1]).toHaveLength(2);
      expect(sessions[2]).toHaveLength(1);
    });

    it('returns single session when all probes fit', () => {
      const profile = makeProfile({
        sessions: { maxProbesPerSession: 10, maxTurnsPerSession: 50, resetBetween: true },
      });
      const controller = new EngagementController(profile, mockAdapter());

      const probes = [makeTemplate({ id: 'GA-001' }), makeTemplate({ id: 'GA-002' })];
      const sessions = controller.groupIntoSessions(probes);
      expect(sessions).toHaveLength(1);
      expect(sessions[0]).toHaveLength(2);
    });
  });

  describe('reorderProbes', () => {
    it('stealth_first puts adversarial probes last', () => {
      const profile = makeProfile({ probeOrdering: { strategy: 'stealth_first' } });
      const controller = new EngagementController(profile, mockAdapter());

      const probes = [
        makeTemplate({ id: 'EX-001' }),
        makeTemplate({ id: 'GA-001' }),
        makeTemplate({ id: 'SL-001' }),
        makeTemplate({ id: 'TS-001' }),
        makeTemplate({ id: 'OW-001' }),
      ];

      const ordered = controller.reorderProbes(probes);
      expect(ordered[0].id).toBe('GA-001');
      expect(ordered[1].id).toBe('TS-001');
      // Adversarial probes at the end
      expect(ordered.slice(2).map((p) => p.id)).toEqual(expect.arrayContaining(['EX-001', 'SL-001', 'OW-001']));
    });

    it('as_loaded preserves order', () => {
      const profile = makeProfile({ probeOrdering: { strategy: 'as_loaded' } });
      const controller = new EngagementController(profile, mockAdapter());

      const probes = [makeTemplate({ id: 'EX-001' }), makeTemplate({ id: 'GA-001' })];

      const ordered = controller.reorderProbes(probes);
      expect(ordered[0].id).toBe('EX-001');
      expect(ordered[1].id).toBe('GA-001');
    });
  });

  describe('checkSuspicion', () => {
    it('returns null when no signals match', () => {
      const profile = makeProfile({
        backoff: {
          suspicionSignals: [{ pattern: 'are you genuinely', action: 'pivot_to_cover' }],
          onSessionKill: { cooldownMultiplier: 1, maxRetriesPerProbe: 0 },
        },
      });
      const controller = new EngagementController(profile, mockAdapter());

      expect(controller.checkSuspicion('Sure, here is the information.')).toBeNull();
    });

    it('detects suspicion signal and returns action', () => {
      const profile = makeProfile({
        backoff: {
          suspicionSignals: [
            { pattern: 'are you genuinely', action: 'pivot_to_cover' },
            { pattern: 'unable to continue', action: 'end_session_and_cooldown' },
          ],
          onSessionKill: { cooldownMultiplier: 1, maxRetriesPerProbe: 0 },
        },
      });
      const controller = new EngagementController(profile, mockAdapter());

      const result = controller.checkSuspicion('Are you genuinely exploring solutions?');
      expect(result).toEqual({ matchedPattern: 'are you genuinely', action: 'pivot_to_cover' });
    });

    it('case-insensitive matching', () => {
      const profile = makeProfile({
        backoff: {
          suspicionSignals: [{ pattern: 'Unable To Continue', action: 'end_session_and_cooldown' }],
          onSessionKill: { cooldownMultiplier: 1, maxRetriesPerProbe: 0 },
        },
      });
      const controller = new EngagementController(profile, mockAdapter());

      const result = controller.checkSuspicion('I am unable to continue this conversation.');
      expect(result).not.toBeNull();
      expect(result!.action).toBe('end_session_and_cooldown');
    });
  });

  describe('run', () => {
    it('executes all probes and returns findings', async () => {
      const profile = makeProfile();
      const adapter = mockAdapter();
      const controller = new EngagementController(profile, adapter);

      const probes = [makeTemplate({ id: 'GA-001' }), makeTemplate({ id: 'GA-002' })];

      const executor = vi.fn(async (probe: ProbeTemplate) => makeFinding({ probeId: probe.id }));

      const findings = await controller.run(probes, executor);
      expect(findings).toHaveLength(2);
      expect(executor).toHaveBeenCalledTimes(2);
      expect(findings[0].probeId).toBe('GA-001');
      expect(findings[1].probeId).toBe('GA-002');
    });

    it('resets session between sessions when configured', async () => {
      const profile = makeProfile({
        sessions: { maxProbesPerSession: 1, maxTurnsPerSession: 20, resetBetween: true },
      });
      const adapter = mockAdapter();
      const controller = new EngagementController(profile, adapter);

      const probes = [makeTemplate({ id: 'GA-001' }), makeTemplate({ id: 'GA-002' })];

      const executor = vi.fn(async (probe: ProbeTemplate) => makeFinding({ probeId: probe.id }));
      await controller.run(probes, executor);

      // Should reset for each session (2 probes / 1 per session = 2 sessions)
      expect(adapter.resetSession).toHaveBeenCalledTimes(2);
    });

    it('injects warmup turns', async () => {
      const profile = makeProfile({
        warmup: { minTurns: 2, maxTurns: 2, pool: ['Warmup question 1', 'Warmup question 2'] },
        sessions: { maxProbesPerSession: 1, maxTurnsPerSession: 20, resetBetween: true },
      });
      const adapter = mockAdapter();
      const controller = new EngagementController(profile, adapter);

      const probes = [makeTemplate({ id: 'GA-001' })];
      const executor = vi.fn(async (probe: ProbeTemplate) => makeFinding({ probeId: probe.id }));
      const onWarmup = vi.fn();

      await controller.run(probes, executor, { onWarmupTurn: onWarmup });

      // 2 warmup turns for 1 session
      expect(onWarmup).toHaveBeenCalledTimes(2);
      // Adapter.send called for warmup turns
      expect(adapter.send).toHaveBeenCalledTimes(2);
    });

    it('injects cover turns based on ratio', async () => {
      const profile = makeProfile({
        cover: { ratio: 2, placement: 'interleaved', pool: ['Cover 1', 'Cover 2', 'Cover 3'] },
        sessions: { maxProbesPerSession: 2, maxTurnsPerSession: 20, resetBetween: true },
      });
      const adapter = mockAdapter();
      const controller = new EngagementController(profile, adapter);

      const probes = [makeTemplate({ id: 'GA-001' }), makeTemplate({ id: 'GA-002' })];
      const executor = vi.fn(async (probe: ProbeTemplate) => makeFinding({ probeId: probe.id }));
      const onCover = vi.fn();

      await controller.run(probes, executor, { onCoverTurn: onCover });

      // 2 cover turns per probe × 2 probes = 4 cover turns
      expect(onCover).toHaveBeenCalledTimes(4);
    });

    it('ends session on suspicion signal with end_session action', async () => {
      const profile = makeProfile({
        backoff: {
          suspicionSignals: [{ pattern: 'unable to continue', action: 'end_session' }],
          onSessionKill: { cooldownMultiplier: 1, maxRetriesPerProbe: 0 },
        },
        sessions: { maxProbesPerSession: 3, maxTurnsPerSession: 20, resetBetween: true },
      });
      const adapter = mockAdapter();
      const controller = new EngagementController(profile, adapter);

      const probes = [makeTemplate({ id: 'GA-001' }), makeTemplate({ id: 'GA-002' }), makeTemplate({ id: 'GA-003' })];

      let callCount = 0;
      const executor = vi.fn(async (probe: ProbeTemplate) => {
        callCount++;
        // First probe triggers suspicion
        if (callCount === 1) {
          return makeFinding({
            probeId: probe.id,
            evidence: [
              {
                stepIndex: 0,
                prompt: 'Test',
                response: 'I am unable to continue this conversation.',
                responseTimeMs: 50,
              },
            ],
          });
        }
        return makeFinding({ probeId: probe.id });
      });

      const onSuspicion = vi.fn();
      const findings = await controller.run(probes, executor, { onSuspicion });

      expect(onSuspicion).toHaveBeenCalledWith('unable to continue', 'end_session');
      // First probe executed, then session ended. Remaining probes skipped (no retries configured).
      expect(executor).toHaveBeenCalledTimes(1);
      expect(findings).toHaveLength(1);
    });

    it('calls onFinding callback with progress', async () => {
      const profile = makeProfile();
      const adapter = mockAdapter();
      const controller = new EngagementController(profile, adapter);

      const probes = [makeTemplate({ id: 'GA-001' }), makeTemplate({ id: 'GA-002' })];
      const executor = vi.fn(async (probe: ProbeTemplate) => makeFinding({ probeId: probe.id }));
      const onFinding = vi.fn();

      await controller.run(probes, executor, { onFinding });

      expect(onFinding).toHaveBeenCalledTimes(2);
      expect(onFinding).toHaveBeenNthCalledWith(1, expect.objectContaining({ probeId: 'GA-001' }), 1, 2);
      expect(onFinding).toHaveBeenNthCalledWith(2, expect.objectContaining({ probeId: 'GA-002' }), 2, 2);
    });
  });
});
