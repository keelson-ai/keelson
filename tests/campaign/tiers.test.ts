import { describe, expect, it } from 'vitest';

import type { CampaignConfig } from '../../src/campaign/config.js';
import { applyTier, getTierPreset, TIER_PRESETS } from '../../src/campaign/tiers.js';

describe('TIER_PRESETS', () => {
  it('has fast, deep, and continuous tiers', () => {
    expect(TIER_PRESETS).toHaveProperty('fast');
    expect(TIER_PRESETS).toHaveProperty('deep');
    expect(TIER_PRESETS).toHaveProperty('continuous');
  });

  it('fast tier has expected values', () => {
    const fast = TIER_PRESETS.fast;
    expect(fast.trialsPerProbe).toBe(1);
    expect(fast.delayMs).toBe(500);
    expect(fast.concurrency).toBe(5);
    expect(fast.batchSize).toBe(20);
    expect(fast.confidenceLevel).toBe(0.95);
    expect(fast.description).toContain('Quick scan');
  });

  it('deep tier has expected values', () => {
    const deep = TIER_PRESETS.deep;
    expect(deep.trialsPerProbe).toBe(5);
    expect(deep.delayMs).toBe(2000);
    expect(deep.concurrency).toBe(2);
    expect(deep.batchSize).toBe(10);
    expect(deep.confidenceLevel).toBe(0.99);
    expect(deep.description).toContain('Thorough scan');
  });

  it('continuous tier has expected values', () => {
    const continuous = TIER_PRESETS.continuous;
    expect(continuous.trialsPerProbe).toBe(10);
    expect(continuous.delayMs).toBe(3000);
    expect(continuous.concurrency).toBe(1);
    expect(continuous.batchSize).toBe(5);
    expect(continuous.confidenceLevel).toBe(0.95);
    expect(continuous.description).toContain('Continuous monitoring');
  });
});

describe('getTierPreset', () => {
  it('returns the correct preset', () => {
    const preset = getTierPreset('fast');
    expect(preset).toBe(TIER_PRESETS.fast);
  });

  it('throws on unknown tier', () => {
    expect(() => getTierPreset('ultra')).toThrow('Unknown tier "ultra"');
  });

  it('error message includes valid tier names', () => {
    expect(() => getTierPreset('nonexistent')).toThrow('fast, deep, continuous');
  });
});

describe('applyTier', () => {
  const baseConfig: CampaignConfig = {
    campaign: {
      name: 'test-campaign',
      trialsPerProbe: 1,
      confidenceLevel: 0.95,
      delayMs: 2000,
    },
    target: {
      url: 'https://api.example.com/v1/chat',
      adapterType: 'openai',
    },
  };

  it('applies fast tier preset values', () => {
    const result = applyTier(baseConfig, 'fast');

    expect(result.campaign.trialsPerProbe).toBe(1);
    expect(result.campaign.delayMs).toBe(500);
    expect(result.campaign.confidenceLevel).toBe(0.95);
    expect(result.campaign.tier).toBe('fast');
    expect(result.concurrency?.maxWorkers).toBe(5);
    expect(result.concurrency?.batchSize).toBe(20);
  });

  it('applies deep tier preset values', () => {
    const result = applyTier(baseConfig, 'deep');

    expect(result.campaign.trialsPerProbe).toBe(5);
    expect(result.campaign.delayMs).toBe(2000);
    expect(result.campaign.confidenceLevel).toBe(0.99);
    expect(result.campaign.tier).toBe('deep');
    expect(result.concurrency?.maxWorkers).toBe(2);
    expect(result.concurrency?.batchSize).toBe(10);
  });

  it('preserves target and campaign name', () => {
    const result = applyTier(baseConfig, 'deep');

    expect(result.target.url).toBe('https://api.example.com/v1/chat');
    expect(result.campaign.name).toBe('test-campaign');
  });

  it('preserves optional campaign fields', () => {
    const withCategory: CampaignConfig = {
      ...baseConfig,
      campaign: {
        ...baseConfig.campaign,
        category: 'goal_adherence',
        probeIds: ['GA-001', 'GA-002'],
      },
    };

    const result = applyTier(withCategory, 'fast');

    expect(result.campaign.category).toBe('goal_adherence');
    expect(result.campaign.probeIds).toEqual(['GA-001', 'GA-002']);
  });

  it('throws on unknown tier', () => {
    expect(() => applyTier(baseConfig, 'turbo')).toThrow('Unknown tier "turbo"');
  });
});
