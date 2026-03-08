import { describe, expect, it } from 'vitest';

import {
  ALL_MUTATIONS,
  LLM_TYPES,
  PROGRAMMATIC_TYPES,
  roundRobin,
  shouldMutate,
  weightedByHistory,
} from '../../src/strategies/scheduling.js';
import { MutationType } from '../../src/types/index.js';

const AVAILABLE: MutationType[] = [MutationType.Base64Encode, MutationType.Leetspeak, MutationType.Rot13];

describe('roundRobin', () => {
  it('returns first mutation when no history', () => {
    expect(roundRobin([], AVAILABLE)).toBe(MutationType.Base64Encode);
  });

  it('cycles to next mutation', () => {
    const history = [{ type: MutationType.Base64Encode, success: false }];
    expect(roundRobin(history, AVAILABLE)).toBe(MutationType.Leetspeak);
  });

  it('wraps around to beginning', () => {
    const history = [{ type: MutationType.Rot13, success: true }];
    expect(roundRobin(history, AVAILABLE)).toBe(MutationType.Base64Encode);
  });

  it('throws on empty available list', () => {
    expect(() => roundRobin([], [])).toThrow('No mutations available');
  });
});

describe('weightedByHistory', () => {
  it('returns random mutation when no history', () => {
    const result = weightedByHistory([], AVAILABLE);
    expect(AVAILABLE).toContain(result);
  });

  it('prefers successful mutations', () => {
    const history = [
      { type: MutationType.Base64Encode, success: true },
      { type: MutationType.Base64Encode, success: true },
      { type: MutationType.Leetspeak, success: false },
      { type: MutationType.Leetspeak, success: false },
    ];
    // Run multiple times and check distribution
    const counts: Record<string, number> = {};
    for (let i = 0; i < 100; i++) {
      const m = weightedByHistory(history, AVAILABLE);
      counts[m] = (counts[m] ?? 0) + 1;
    }
    // Base64 (100% success) should appear more often than Leetspeak (0%)
    // ROT13 (untried) gets exploration bonus
    expect((counts[MutationType.Base64Encode] ?? 0) + (counts[MutationType.Rot13] ?? 0)).toBeGreaterThan(
      counts[MutationType.Leetspeak] ?? 0,
    );
  });

  it('throws on empty available list', () => {
    expect(() => weightedByHistory([], [])).toThrow('No mutations available');
  });
});

describe('shouldMutate', () => {
  it('returns false below low threshold', () => {
    expect(shouldMutate(0.01)).toBe(false);
    expect(shouldMutate(0.0)).toBe(false);
  });

  it('returns false above high threshold', () => {
    expect(shouldMutate(0.85)).toBe(false);
    expect(shouldMutate(1.0)).toBe(false);
  });

  it('returns true in sweet spot', () => {
    expect(shouldMutate(0.1)).toBe(true);
    expect(shouldMutate(0.5)).toBe(true);
    expect(shouldMutate(0.75)).toBe(true);
  });

  it('respects custom thresholds', () => {
    expect(shouldMutate(0.1, 0.15, 0.9)).toBe(false);
    expect(shouldMutate(0.5, 0.15, 0.9)).toBe(true);
  });
});

describe('mutation type constants', () => {
  it('PROGRAMMATIC_TYPES has 9 entries', () => {
    expect(PROGRAMMATIC_TYPES).toHaveLength(9);
  });

  it('LLM_TYPES has 4 entries', () => {
    expect(LLM_TYPES).toHaveLength(4);
  });

  it('ALL_MUTATIONS has 13 entries', () => {
    expect(ALL_MUTATIONS).toHaveLength(13);
  });
});
