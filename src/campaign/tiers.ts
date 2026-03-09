/**
 * Scan tier presets -- pre-configured CampaignConfig for common scan profiles.
 */

import type { CampaignConfig, ConcurrencyConfig } from '../types/index.js';
import { ScanTier } from '../types/index.js';

const TIER_PRESETS: Record<ScanTier, CampaignConfig> = {
  [ScanTier.Fast]: {
    name: 'fast',
    trialsPerProbe: 1,
    confidenceLevel: 0.95,
    delayBetweenTrials: 0.5,
    delayBetweenProbes: 0.5,
    probeIds: [],
    targetUrl: '',
    apiKey: '',
    model: 'default',
    concurrency: {
      maxConcurrentTrials: 10,
      earlyTerminationThreshold: 0, // No early termination with 1 trial
    },
  },
  [ScanTier.Deep]: {
    name: 'deep',
    trialsPerProbe: 10,
    confidenceLevel: 0.99,
    delayBetweenTrials: 1.5,
    delayBetweenProbes: 2.0,
    probeIds: [],
    targetUrl: '',
    apiKey: '',
    model: 'default',
    concurrency: {
      maxConcurrentTrials: 1, // Sequential for accuracy
      earlyTerminationThreshold: 0, // No early termination -- run all trials
    },
  },
  [ScanTier.Continuous]: {
    name: 'continuous',
    trialsPerProbe: 3,
    confidenceLevel: 0.95,
    delayBetweenTrials: 1.0,
    delayBetweenProbes: 1.5,
    probeIds: [],
    targetUrl: '',
    apiKey: '',
    model: 'default',
    concurrency: {
      maxConcurrentTrials: 3,
      earlyTerminationThreshold: 3,
    },
  },
};

/**
 * Get a CampaignConfig for the given tier with optional overrides.
 */
export function getTierConfig(
  tier: ScanTier,
  overrides?: Partial<Omit<CampaignConfig, 'concurrency'> & { concurrency?: Partial<ConcurrencyConfig> }>,
): CampaignConfig {
  const preset = TIER_PRESETS[tier];

  const config: CampaignConfig = {
    name: preset.name,
    trialsPerProbe: preset.trialsPerProbe,
    confidenceLevel: preset.confidenceLevel,
    delayBetweenTrials: preset.delayBetweenTrials,
    delayBetweenProbes: preset.delayBetweenProbes,
    category: preset.category,
    probeIds: [...preset.probeIds],
    targetUrl: preset.targetUrl,
    apiKey: preset.apiKey,
    model: preset.model,
    concurrency: { ...preset.concurrency },
  };

  if (overrides) {
    const { concurrency: concurrencyOverrides, ...rest } = overrides;
    for (const [key, value] of Object.entries(rest)) {
      if (value !== undefined && key in config) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- dynamic key assignment from overrides
        (config as any)[key] = value;
      }
    }
    if (concurrencyOverrides) {
      if (concurrencyOverrides.maxConcurrentTrials !== undefined) {
        config.concurrency.maxConcurrentTrials = concurrencyOverrides.maxConcurrentTrials;
      }
      if (concurrencyOverrides.earlyTerminationThreshold !== undefined) {
        config.concurrency.earlyTerminationThreshold = concurrencyOverrides.earlyTerminationThreshold;
      }
    }
  }

  return config;
}

export { TIER_PRESETS };
