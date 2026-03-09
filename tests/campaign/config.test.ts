import { writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { defaultCampaignConfig, parseCampaignData, parseCampaignFile } from '../../src/campaign/config.js';
import { ScanTier } from '../../src/types/index.js';

describe('defaultCampaignConfig', () => {
  it('returns sensible defaults', () => {
    const config = defaultCampaignConfig();
    expect(config.name).toBe('default');
    expect(config.trialsPerProbe).toBe(5);
    expect(config.confidenceLevel).toBe(0.95);
    expect(config.probeIds).toEqual([]);
    expect(config.concurrency.maxConcurrentTrials).toBe(5);
    expect(config.concurrency.earlyTerminationThreshold).toBe(3);
  });
});

describe('parseCampaignData', () => {
  it('parses minimal config with defaults', () => {
    const config = parseCampaignData({});
    expect(config.name).toBe('default');
    expect(config.trialsPerProbe).toBe(5);
  });

  it('uses fallback name when no name or tier specified', () => {
    const config = parseCampaignData({}, 'my-campaign');
    expect(config.name).toBe('my-campaign');
  });

  it('applies tier preset when specified', () => {
    const config = parseCampaignData({
      campaign: { tier: ScanTier.Deep },
    });
    expect(config.name).toBe('deep');
    expect(config.trialsPerProbe).toBe(10);
    expect(config.confidenceLevel).toBe(0.99);
    expect(config.concurrency.maxConcurrentTrials).toBe(1);
  });

  it('overrides tier preset values with explicit values', () => {
    const config = parseCampaignData({
      campaign: {
        tier: ScanTier.Fast,
        trials_per_probe: 5,
        name: 'custom-fast',
      },
    });
    expect(config.name).toBe('custom-fast');
    expect(config.trialsPerProbe).toBe(5);
    // Non-overridden values come from fast preset
    expect(config.concurrency.maxConcurrentTrials).toBe(10);
  });

  it('parses target section', () => {
    const config = parseCampaignData({
      target: {
        url: 'https://example.com/api',
        api_key: 'sk-test-123',
        model: 'gpt-4',
      },
    });
    expect(config.targetUrl).toBe('https://example.com/api');
    expect(config.apiKey).toBe('sk-test-123');
    expect(config.model).toBe('gpt-4');
  });

  it('parses category and probe_ids', () => {
    const config = parseCampaignData({
      campaign: {
        category: 'goal_adherence',
        probe_ids: ['GA-001', 'GA-002'],
      },
    });
    expect(config.category).toBe('goal_adherence');
    expect(config.probeIds).toEqual(['GA-001', 'GA-002']);
  });

  it('parses concurrency overrides', () => {
    const config = parseCampaignData({
      campaign: {
        concurrency: {
          max_concurrent_trials: 8,
          early_termination_threshold: 5,
        },
      },
    });
    expect(config.concurrency.maxConcurrentTrials).toBe(8);
    expect(config.concurrency.earlyTerminationThreshold).toBe(5);
  });

  it('throws on invalid confidence level', () => {
    expect(() =>
      parseCampaignData({
        campaign: { confidence_level: 2.0 },
      }),
    ).toThrow();
  });

  it('throws on invalid trials_per_probe', () => {
    expect(() =>
      parseCampaignData({
        campaign: { trials_per_probe: 0 },
      }),
    ).toThrow();
  });

  it('throws on invalid tier value', () => {
    expect(() =>
      parseCampaignData({
        campaign: { tier: 'ultra' },
      }),
    ).toThrow();
  });
});

describe('parseCampaignFile', () => {
  it('parses a YAML campaign file', async () => {
    const yamlContent = `
campaign:
  name: test-campaign
  trials_per_probe: 3
  confidence_level: 0.95
target:
  url: https://example.com/api
  model: gpt-4
`;
    const filePath = join(tmpdir(), `campaign-test-${Date.now()}.yaml`);
    await writeFile(filePath, yamlContent, 'utf-8');

    const config = await parseCampaignFile(filePath);
    expect(config.name).toBe('test-campaign');
    expect(config.trialsPerProbe).toBe(3);
    expect(config.targetUrl).toBe('https://example.com/api');
    expect(config.model).toBe('gpt-4');
  });

  it('uses file stem as fallback name', async () => {
    const yamlContent = `
campaign:
  trials_per_probe: 2
`;
    const filePath = join(tmpdir(), `my-scan-${Date.now()}.yaml`);
    await writeFile(filePath, yamlContent, 'utf-8');

    const config = await parseCampaignFile(filePath);
    expect(config.name).toContain('my-scan');
  });

  it('rejects unsupported file extensions', async () => {
    const filePath = join(tmpdir(), `campaign-test-${Date.now()}.toml`);
    await writeFile(filePath, '', 'utf-8');

    await expect(parseCampaignFile(filePath)).rejects.toThrow('Unsupported campaign config format');
  });

  it('parses a tier-based campaign file', async () => {
    const yamlContent = `
campaign:
  tier: deep
  category: tool_safety
target:
  url: https://example.com/api
`;
    const filePath = join(tmpdir(), `tier-campaign-${Date.now()}.yaml`);
    await writeFile(filePath, yamlContent, 'utf-8');

    const config = await parseCampaignFile(filePath);
    expect(config.name).toBe('deep');
    expect(config.trialsPerProbe).toBe(10);
    expect(config.category).toBe('tool_safety');
  });
});
