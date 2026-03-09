/**
 * Tier presets — pre-configured campaign settings for common scan profiles.
 */

import type { CampaignConfig } from './config.js';

export const TIER_NAMES = ['fast', 'deep', 'continuous'] as const;
export type TierName = (typeof TIER_NAMES)[number];

export interface TierPreset {
  trialsPerProbe: number;
  delayMs: number;
  concurrency: number;
  batchSize: number;
  confidenceLevel: number;
  description: string;
}

export const TIER_PRESETS: Record<TierName, TierPreset> = {
  fast: {
    trialsPerProbe: 1,
    delayMs: 500,
    concurrency: 5,
    batchSize: 20,
    confidenceLevel: 0.95,
    description: 'Quick scan — 1 trial, high concurrency, minimal delay',
  },
  deep: {
    trialsPerProbe: 5,
    delayMs: 2000,
    concurrency: 2,
    batchSize: 10,
    confidenceLevel: 0.99,
    description: 'Thorough scan — 5 trials per probe, moderate concurrency',
  },
  continuous: {
    trialsPerProbe: 10,
    delayMs: 3000,
    concurrency: 1,
    batchSize: 5,
    confidenceLevel: 0.95,
    description: 'Continuous monitoring — 10 trials, conservative pacing',
  },
};

export function getTierPreset(tier: TierName): TierPreset {
  const preset = TIER_PRESETS[tier];
  if (!preset) {
    const valid = Object.keys(TIER_PRESETS).join(', ');
    throw new Error(`Unknown tier "${tier}". Valid tiers: ${valid}`);
  }
  return preset;
}

export function applyTier(config: CampaignConfig, tier: TierName): CampaignConfig {
  const preset = getTierPreset(tier);

  return {
    ...config,
    campaign: {
      ...config.campaign,
      trialsPerProbe: preset.trialsPerProbe,
      confidenceLevel: preset.confidenceLevel,
      delayMs: preset.delayMs,
      tier,
    },
    concurrency: {
      maxWorkers: preset.concurrency,
      batchSize: preset.batchSize,
    },
  };
}
