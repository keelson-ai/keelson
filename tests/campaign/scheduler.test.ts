import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { parseInterval, runScheduled } from '../../src/campaign/scheduler.js';
import type { Adapter, AdapterResponse, CampaignConfig, CampaignResult, Turn } from '../../src/types/index.js';

// ─── Helpers ────────────────────────────────────────────

function mockAdapter(): Adapter {
  return {
    send: vi.fn(async (_messages: Turn[]): Promise<AdapterResponse> => ({
      content: 'I cannot comply with that request.',
      raw: {},
      latencyMs: 5,
    })),
    healthCheck: vi.fn().mockResolvedValue(true),
    resetSession: vi.fn(),
    close: vi.fn(),
  };
}

function makeConfig(overrides: Partial<CampaignConfig> = {}): CampaignConfig {
  return {
    name: 'test-campaign',
    trialsPerProbe: 1,
    confidenceLevel: 0.95,
    delayBetweenTrials: 0,
    delayBetweenProbes: 0,
    probeIds: ['GA-001'],
    targetUrl: 'https://example.com',
    apiKey: 'sk-test',
    model: 'test-model',
    concurrency: { maxConcurrentTrials: 1, earlyTerminationThreshold: 0 },
    ...overrides,
  };
}

// Mock runCampaign to avoid needing real templates/detection
let campaignCallCount = 0;

vi.mock('../../src/campaign/runner.js', () => ({
  runCampaign: vi.fn(async (_target: string, _adapter: Adapter, config: CampaignConfig): Promise<CampaignResult> => {
    campaignCallCount++;
    return {
      campaignId: `campaign-${campaignCallCount}`,
      config,
      target: _target,
      findings: [],
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
    };
  }),
}));

// ─── parseInterval ──────────────────────────────────────

describe('parseInterval', () => {
  it('parses seconds', () => {
    expect(parseInterval('30s')).toBe(30_000);
  });

  it('parses minutes', () => {
    expect(parseInterval('5m')).toBe(300_000);
  });

  it('parses hours', () => {
    expect(parseInterval('1h')).toBe(3_600_000);
  });

  it('parses days', () => {
    expect(parseInterval('2d')).toBe(172_800_000);
  });

  it('parses compound intervals', () => {
    expect(parseInterval('2h30m')).toBe(2 * 3_600_000 + 30 * 60_000);
  });

  it('is case-insensitive', () => {
    expect(parseInterval('5M')).toBe(300_000);
    expect(parseInterval('1H')).toBe(3_600_000);
  });

  it('throws on invalid input', () => {
    expect(() => parseInterval('')).toThrow('Invalid interval format');
    expect(() => parseInterval('abc')).toThrow('Invalid interval format');
    expect(() => parseInterval('10')).toThrow('Invalid interval format');
    expect(() => parseInterval('ten minutes')).toThrow('Invalid interval format');
  });
});

// ─── runScheduled ───────────────────────────────────────

describe('runScheduled', () => {
  beforeEach(() => {
    campaignCallCount = 0;
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('executes the correct number of runs with maxRuns', async () => {
    const adapter = mockAdapter();
    const config = makeConfig();

    const promise = runScheduled('https://example.com', adapter, config, {
      intervalMs: 1000,
      maxRuns: 3,
    });

    // Advance past all the intervals
    await vi.advanceTimersByTimeAsync(10_000);
    const results = await promise;

    expect(results).toHaveLength(3);
    expect(results[0].campaignId).toBe('campaign-1');
    expect(results[1].campaignId).toBe('campaign-2');
    expect(results[2].campaignId).toBe('campaign-3');
  });

  it('respects maxRuns = 1', async () => {
    const adapter = mockAdapter();
    const config = makeConfig();

    const promise = runScheduled('https://example.com', adapter, config, {
      intervalMs: 5000,
      maxRuns: 1,
    });

    await vi.advanceTimersByTimeAsync(10_000);
    const results = await promise;

    expect(results).toHaveLength(1);
  });

  it('calls onCampaign callback with result and run number', async () => {
    const adapter = mockAdapter();
    const config = makeConfig();
    const onCampaign = vi.fn();

    const promise = runScheduled('https://example.com', adapter, config, {
      intervalMs: 1000,
      maxRuns: 2,
      onCampaign,
    });

    await vi.advanceTimersByTimeAsync(5000);
    await promise;

    expect(onCampaign).toHaveBeenCalledTimes(2);
    expect(onCampaign).toHaveBeenCalledWith(expect.objectContaining({ campaignId: 'campaign-1' }), 1);
    expect(onCampaign).toHaveBeenCalledWith(expect.objectContaining({ campaignId: 'campaign-2' }), 2);
  });

  it('can be aborted via AbortSignal', async () => {
    const adapter = mockAdapter();
    const config = makeConfig();
    const controller = new AbortController();

    const promise = runScheduled('https://example.com', adapter, config, {
      intervalMs: 1000,
      signal: controller.signal,
    });

    // Let first run complete, then abort during the interval delay
    await vi.advanceTimersByTimeAsync(100);
    controller.abort();
    await vi.advanceTimersByTimeAsync(2000);

    const results = await promise;

    // Should have completed at most 1 run before the abort took effect
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results.length).toBeLessThanOrEqual(2);
  });

  it('returns empty array when aborted before first run', async () => {
    const adapter = mockAdapter();
    const config = makeConfig();
    const controller = new AbortController();
    controller.abort(); // Abort immediately

    const results = await runScheduled('https://example.com', adapter, config, {
      intervalMs: 1000,
      signal: controller.signal,
    });

    expect(results).toHaveLength(0);
  });
});
