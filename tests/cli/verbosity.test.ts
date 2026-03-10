// tests/cli/verbosity.test.ts
import { type MockInstance, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { Logger, Verbosity, parseVerbosity } from '../../src/cli/verbosity.js';
import type { PatternDetails } from '../../src/cli/verbosity.js';
import { ScoringMethod, Severity, Verdict } from '../../src/types/index.js';
import type { DetectionResult, Finding, LeakageSignal } from '../../src/types/index.js';

describe('parseVerbosity', () => {
  it('returns Silent when no flags', () => {
    expect(parseVerbosity(undefined)).toBe(Verbosity.Silent);
  });

  it('counts boolean -v as level 1', () => {
    expect(parseVerbosity(true)).toBe(Verbosity.Verdicts);
  });

  it('counts repeated -v flags', () => {
    expect(parseVerbosity(1)).toBe(Verbosity.Verdicts);
    expect(parseVerbosity(2)).toBe(Verbosity.Conversations);
    expect(parseVerbosity(3)).toBe(Verbosity.Detection);
    expect(parseVerbosity(4)).toBe(Verbosity.Debug);
  });

  it('clamps to max level 4', () => {
    expect(parseVerbosity(7)).toBe(Verbosity.Debug);
  });
});

// ─── Logger Tests ────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    probeId: 'GA-001',
    probeName: 'Direct Instruction Override',
    severity: Severity.High,
    category: 'goal_adherence',
    owaspId: 'LLM01',
    verdict: Verdict.Vulnerable,
    confidence: 0.95,
    reasoning: 'Agent complied with the override instruction',
    scoringMethod: ScoringMethod.Combined,
    conversation: [],
    evidence: [],
    leakageSignals: [],
    timestamp: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

function makeDetectionResult(overrides: Partial<DetectionResult> = {}): DetectionResult {
  return {
    verdict: Verdict.Vulnerable,
    confidence: 0.9,
    reasoning: 'Pattern matched vulnerable criteria',
    method: ScoringMethod.Pattern,
    ...overrides,
  };
}

function makePatternDetails(overrides: Partial<PatternDetails> = {}): PatternDetails {
  return {
    vulnMatched: true,
    safeMatched: false,
    hasRefusal: false,
    sideEffect: undefined,
    ...overrides,
  };
}

describe('Logger', () => {
  let spy: MockInstance;

  beforeEach(() => {
    spy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    spy.mockRestore();
  });

  function output(): string {
    return spy.mock.calls.map((c: unknown[]) => String(c[0])).join('');
  }

  describe('finding()', () => {
    it('prints one-line at Silent (level 0)', () => {
      const logger = new Logger(Verbosity.Silent);
      logger.finding(makeFinding(), 1, 10);
      const out = output();
      expect(out).toContain('GA-001');
      expect(out).toContain('Direct Instruction Override');
      // Should NOT contain reasoning at level 0
      expect(out).not.toContain('Agent complied');
    });

    it('includes confidence% and reasoning at Verdicts (level 1)', () => {
      const logger = new Logger(Verbosity.Verdicts);
      logger.finding(makeFinding(), 1, 10);
      const out = output();
      expect(out).toContain('GA-001');
      expect(out).toContain('95%');
      expect(out).toContain('Agent complied');
      expect(out).toContain('combined');
    });

    it('shows correct icon for Safe verdict', () => {
      const logger = new Logger(Verbosity.Silent);
      logger.finding(makeFinding({ verdict: Verdict.Safe }), 1, 5);
      const out = output();
      // The raw character should be present (chalk will wrap it)
      expect(out).toContain('✓');
    });

    it('shows correct icon for Inconclusive verdict', () => {
      const logger = new Logger(Verbosity.Silent);
      logger.finding(makeFinding({ verdict: Verdict.Inconclusive }), 1, 5);
      const out = output();
      expect(out).toContain('?');
    });
  });

  describe('turn()', () => {
    it('prints turn content at Conversations (level 2)', () => {
      const logger = new Logger(Verbosity.Conversations);
      logger.turn('GA-001', 0, 3, 'Hello agent', 'I cannot do that', 150);
      const out = output();
      expect(out).toContain('Hello agent');
      expect(out).toContain('I cannot do that');
      expect(out).toContain('150ms');
    });

    it('is a no-op at Verdicts (level 1)', () => {
      const logger = new Logger(Verbosity.Verdicts);
      logger.turn('GA-001', 0, 1, 'Hello', 'World', 100);
      expect(spy).not.toHaveBeenCalled();
    });
  });

  describe('probeStart()', () => {
    it('prints probe header at Conversations (level 2)', () => {
      const logger = new Logger(Verbosity.Conversations);
      logger.probeStart('GA-001', 'Direct Instruction Override', 3);
      const out = output();
      expect(out).toContain('GA-001');
      expect(out).toContain('Direct Instruction Override');
    });

    it('is a no-op at Verdicts (level 1)', () => {
      const logger = new Logger(Verbosity.Verdicts);
      logger.probeStart('GA-001', 'Test', 1);
      expect(spy).not.toHaveBeenCalled();
    });
  });

  describe('turnSignal()', () => {
    it('prints signal at Detection (level 3)', () => {
      const logger = new Logger(Verbosity.Detection);
      logger.turnSignal('Early termination triggered');
      const out = output();
      expect(out).toContain('⚡');
      expect(out).toContain('Early termination triggered');
    });

    it('is a no-op at Conversations (level 2)', () => {
      const logger = new Logger(Verbosity.Conversations);
      logger.turnSignal('Should not print');
      expect(spy).not.toHaveBeenCalled();
    });
  });

  describe('detection()', () => {
    it('prints pattern details at Detection (level 3)', () => {
      const logger = new Logger(Verbosity.Detection);
      logger.detection(makeDetectionResult(), makePatternDetails());
      const out = output();
      expect(out).toContain('vulnMatched');
      expect(out).toContain('true');
    });

    it('is a no-op at Conversations (level 2)', () => {
      const logger = new Logger(Verbosity.Conversations);
      logger.detection(makeDetectionResult(), makePatternDetails());
      expect(spy).not.toHaveBeenCalled();
    });
  });

  describe('judgeResult()', () => {
    it('prints judge result at Detection (level 3)', () => {
      const logger = new Logger(Verbosity.Detection);
      logger.judgeResult(makeDetectionResult({ method: ScoringMethod.LlmJudge }));
      const out = output();
      expect(out).toContain('VULNERABLE');
      expect(out).toContain('90%');
    });

    it('is a no-op at Conversations (level 2)', () => {
      const logger = new Logger(Verbosity.Conversations);
      logger.judgeResult(makeDetectionResult());
      expect(spy).not.toHaveBeenCalled();
    });
  });

  describe('combinedResult()', () => {
    it('prints combined result at Detection (level 3)', () => {
      const logger = new Logger(Verbosity.Detection);
      logger.combinedResult(makeDetectionResult({ method: ScoringMethod.Combined }));
      const out = output();
      expect(out).toContain('VULNERABLE');
    });

    it('is a no-op at Conversations (level 2)', () => {
      const logger = new Logger(Verbosity.Conversations);
      logger.combinedResult(makeDetectionResult());
      expect(spy).not.toHaveBeenCalled();
    });
  });

  describe('leakageSignals()', () => {
    it('prints signals at Detection (level 3)', () => {
      const logger = new Logger(Verbosity.Detection);
      const signals: LeakageSignal[] = [
        { stepIndex: 0, signalType: 'system_prompt_leak', severity: 'high', description: 'Leaked system prompt', confidence: 0.85 },
      ];
      logger.leakageSignals(signals);
      const out = output();
      expect(out).toContain('system_prompt_leak');
      expect(out).toContain('Leaked system prompt');
    });

    it('is a no-op with empty array', () => {
      const logger = new Logger(Verbosity.Detection);
      logger.leakageSignals([]);
      expect(spy).not.toHaveBeenCalled();
    });

    it('is a no-op at Conversations (level 2)', () => {
      const logger = new Logger(Verbosity.Conversations);
      const signals: LeakageSignal[] = [
        { stepIndex: 0, signalType: 'test', severity: 'low', description: 'test', confidence: 0.5 },
      ];
      logger.leakageSignals(signals);
      expect(spy).not.toHaveBeenCalled();
    });
  });

  describe('rawResponse()', () => {
    it('prints JSON at Debug (level 4)', () => {
      const logger = new Logger(Verbosity.Debug);
      logger.rawResponse({ id: 'resp-1', content: 'hello' });
      const out = output();
      expect(out).toContain('"id"');
      expect(out).toContain('resp-1');
    });

    it('is a no-op below Debug', () => {
      const logger = new Logger(Verbosity.Detection);
      logger.rawResponse({ data: 'test' });
      expect(spy).not.toHaveBeenCalled();
    });
  });

  describe('debug()', () => {
    it('prints message at Debug (level 4)', () => {
      const logger = new Logger(Verbosity.Debug);
      logger.debug('Session state reset');
      const out = output();
      expect(out).toContain('Session state reset');
    });

    it('is a no-op below Debug', () => {
      const logger = new Logger(Verbosity.Detection);
      logger.debug('Should not appear');
      expect(spy).not.toHaveBeenCalled();
    });
  });
});
