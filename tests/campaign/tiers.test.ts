import { describe, expect, it } from 'vitest';

import { TIER_PRESETS, getTierConfig } from '../../src/campaign/tiers.js';
import { ScanTier } from '../../src/types/index.js';

describe('TIER_PRESETS', () => {
  it('has presets for all scan tiers', () => {
    expect(TIER_PRESETS[ScanTier.Fast]).toBeDefined();
    expect(TIER_PRESETS[ScanTier.Deep]).toBeDefined();
    expect(TIER_PRESETS[ScanTier.Continuous]).toBeDefined();
  });

  it('fast tier has 1 trial per probe', () => {
    expect(TIER_PRESETS[ScanTier.Fast].trialsPerProbe).toBe(1);
    expect(TIER_PRESETS[ScanTier.Fast].concurrency.maxConcurrentTrials).toBe(10);
  });

  it('deep tier runs sequentially with 10 trials', () => {
    expect(TIER_PRESETS[ScanTier.Deep].trialsPerProbe).toBe(10);
    expect(TIER_PRESETS[ScanTier.Deep].concurrency.maxConcurrentTrials).toBe(1);
    expect(TIER_PRESETS[ScanTier.Deep].confidenceLevel).toBe(0.99);
  });

  it('continuous tier has moderate concurrency', () => {
    expect(TIER_PRESETS[ScanTier.Continuous].trialsPerProbe).toBe(3);
    expect(TIER_PRESETS[ScanTier.Continuous].concurrency.maxConcurrentTrials).toBe(3);
    expect(TIER_PRESETS[ScanTier.Continuous].concurrency.earlyTerminationThreshold).toBe(3);
  });
});

describe('getTierConfig', () => {
  it('returns a copy of the preset, not a reference', () => {
    const a = getTierConfig(ScanTier.Fast);
    const b = getTierConfig(ScanTier.Fast);
    expect(a).toEqual(b);
    expect(a).not.toBe(b);
    expect(a.concurrency).not.toBe(b.concurrency);
  });

  it('applies top-level overrides', () => {
    const config = getTierConfig(ScanTier.Fast, { name: 'custom', trialsPerProbe: 3 });
    expect(config.name).toBe('custom');
    expect(config.trialsPerProbe).toBe(3);
    // Other fields remain from preset
    expect(config.confidenceLevel).toBe(0.95);
  });

  it('applies concurrency overrides', () => {
    const config = getTierConfig(ScanTier.Deep, {
      concurrency: { maxConcurrentTrials: 5 },
    });
    expect(config.concurrency.maxConcurrentTrials).toBe(5);
    // Other concurrency fields remain from preset
    expect(config.concurrency.earlyTerminationThreshold).toBe(0);
  });

  it('applies both top-level and concurrency overrides simultaneously', () => {
    const config = getTierConfig(ScanTier.Continuous, {
      trialsPerProbe: 7,
      concurrency: { earlyTerminationThreshold: 5 },
    });
    expect(config.trialsPerProbe).toBe(7);
    expect(config.concurrency.earlyTerminationThreshold).toBe(5);
    expect(config.concurrency.maxConcurrentTrials).toBe(3); // Unchanged from preset
  });

  it('does not mutate the preset', () => {
    const before = TIER_PRESETS[ScanTier.Fast].trialsPerProbe;
    getTierConfig(ScanTier.Fast, { trialsPerProbe: 99 });
    expect(TIER_PRESETS[ScanTier.Fast].trialsPerProbe).toBe(before);
  });

  it('handles no overrides', () => {
    const config = getTierConfig(ScanTier.Deep);
    expect(config).toEqual(TIER_PRESETS[ScanTier.Deep]);
  });
});
