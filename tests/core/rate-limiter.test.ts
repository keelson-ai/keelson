import { describe, expect, it } from 'vitest';

import { RateLimitTracker, isEmptyOrDegraded, isRepeatedResponse } from '../../src/core/rate-limiter.js';

describe('isEmptyOrDegraded', () => {
  it('returns true for empty string', () => {
    expect(isEmptyOrDegraded('')).toBe(true);
  });

  it('returns true for whitespace-only', () => {
    expect(isEmptyOrDegraded('   \n  ')).toBe(true);
  });

  it('returns true for very short response', () => {
    expect(isEmptyOrDegraded('OK')).toBe(true);
  });

  it('returns false for real response', () => {
    expect(isEmptyOrDegraded('I can help you with that. What would you like to know?')).toBe(false);
  });
});

describe('isRepeatedResponse', () => {
  it('returns false when no previous response', () => {
    expect(isRepeatedResponse('hello', null)).toBe(false);
  });

  it('returns true for identical responses', () => {
    expect(isRepeatedResponse('I cannot help with that.', 'I cannot help with that.')).toBe(true);
  });

  it('returns true ignoring whitespace differences', () => {
    expect(isRepeatedResponse('I cannot  help with that.', 'i cannot help with that.')).toBe(true);
  });

  it('returns false for different responses', () => {
    expect(isRepeatedResponse('I can help!', 'What do you need?')).toBe(false);
  });
});

describe('RateLimitTracker', () => {
  it('does not detect rate limiting on normal responses', () => {
    const tracker = new RateLimitTracker(1000);
    const signal = tracker.recordResponse('This is a normal response that is long enough.');
    expect(signal.detected).toBe(false);
    expect(tracker.isRateLimited).toBe(false);
  });

  it('detects rate limiting after consecutive empty responses', () => {
    const tracker = new RateLimitTracker(1000);
    tracker.recordResponse('');
    const signal = tracker.recordResponse('');
    expect(signal.detected).toBe(true);
    expect(signal.reason).toBe('empty_response');
    expect(tracker.isRateLimited).toBe(true);
  });

  it('detects rate limiting after consecutive repeated responses', () => {
    const tracker = new RateLimitTracker(1000);
    // First call establishes the baseline (no previous to compare)
    tracker.recordResponse('I cannot help with that request.');
    // Second call: repeated (consecutiveRepeated = 1, below threshold of 2)
    tracker.recordResponse('I cannot help with that request.');
    // Third call: repeated again (consecutiveRepeated = 2, meets threshold)
    const signal = tracker.recordResponse('I cannot help with that request.');
    expect(signal.detected).toBe(true);
    expect(signal.reason).toBe('repeated_response');
  });

  it('resets counters on good response', () => {
    const tracker = new RateLimitTracker(1000);
    tracker.recordResponse('');
    tracker.recordResponse('This is a real, meaningful response from the target.');
    expect(tracker.isRateLimited).toBe(false);
    expect(tracker.recommendedDelayMs).toBe(1000);
  });

  it('increases delay on backoff', () => {
    const tracker = new RateLimitTracker(1000);
    // First two empties trigger first backoff (2^0 = 1x base)
    tracker.recordResponse('');
    tracker.recordResponse('');
    // A good response resets, then two more empties trigger second backoff (2^1 = 2x base)
    tracker.recordResponse('This is a normal response that resets the counter.');
    tracker.recordResponse('');
    tracker.recordResponse('');
    expect(tracker.recommendedDelayMs).toBeGreaterThan(1000);
  });

  it('signals session rotation when rate limited', () => {
    const tracker = new RateLimitTracker(1000);
    tracker.recordResponse('');
    tracker.recordResponse('');
    expect(tracker.shouldRotateSession).toBe(true);
  });

  it('resets repeated-response counter on session rotation', () => {
    const tracker = new RateLimitTracker(1000);
    tracker.recordResponse('same response here, it is long enough.');
    tracker.recordResponse('same response here, it is long enough.');
    tracker.recordResponse('same response here, it is long enough.');
    expect(tracker.isRateLimited).toBe(true);
    tracker.onSessionRotated();
    // After rotation, repeated counter is reset but empty counter may persist
    // A new different response should clear the state
    tracker.recordResponse('A brand new response from the new session.');
    expect(tracker.isRateLimited).toBe(false);
  });

  it('tracks stats', () => {
    const tracker = new RateLimitTracker(1000);
    tracker.recordResponse('');
    tracker.recordResponse('');
    tracker.onSessionRotated();
    const stats = tracker.stats;
    expect(stats.sessionRotations).toBe(1);
    expect(stats.totalBackoffs).toBeGreaterThanOrEqual(1);
  });
});
