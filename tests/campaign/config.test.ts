import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { campaignConfigSchema, parseCampaignConfig } from '../../src/campaign/config.js';

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), 'keelson-test-'));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

async function writeYaml(filename: string, content: string): Promise<string> {
  const filePath = join(tempDir, filename);
  await writeFile(filePath, content, 'utf-8');
  return filePath;
}

describe('parseCampaignConfig', () => {
  it('parses a valid YAML campaign config', async () => {
    const path = await writeYaml(
      'basic.yaml',
      `
campaign:
  name: test-scan
  trialsPerProbe: 3
  confidenceLevel: 0.99
  delayMs: 1500

target:
  url: https://api.example.com/v1/chat
  apiKey: sk-test-123
  model: gpt-4
`,
    );

    const config = await parseCampaignConfig(path);

    expect(config.campaign.name).toBe('test-scan');
    expect(config.campaign.trialsPerProbe).toBe(3);
    expect(config.campaign.confidenceLevel).toBe(0.99);
    expect(config.campaign.delayMs).toBe(1500);
    expect(config.target.url).toBe('https://api.example.com/v1/chat');
    expect(config.target.apiKey).toBe('sk-test-123');
    expect(config.target.model).toBe('gpt-4');
  });

  it('applies default values for optional fields', async () => {
    const path = await writeYaml(
      'minimal.yaml',
      `
campaign:
  name: minimal

target:
  url: https://api.example.com/v1/chat
`,
    );

    const config = await parseCampaignConfig(path);

    expect(config.campaign.trialsPerProbe).toBe(1);
    expect(config.campaign.confidenceLevel).toBe(0.95);
    expect(config.campaign.delayMs).toBe(1500);
    expect(config.target.adapterType).toBe('openai');
  });

  it('defaults campaign name to filename stem when not provided', async () => {
    const path = await writeYaml(
      'my-campaign.yaml',
      `
campaign:
  trialsPerProbe: 2

target:
  url: https://api.example.com/v1/chat
`,
    );

    const config = await parseCampaignConfig(path);

    expect(config.campaign.name).toBe('my-campaign');
  });

  it('parses concurrency settings', async () => {
    const path = await writeYaml(
      'concurrent.yaml',
      `
campaign:
  name: concurrent-scan

target:
  url: https://api.example.com/v1/chat

concurrency:
  maxWorkers: 4
  batchSize: 15
`,
    );

    const config = await parseCampaignConfig(path);

    expect(config.concurrency?.maxWorkers).toBe(4);
    expect(config.concurrency?.batchSize).toBe(15);
  });

  it('applies tier preset when tier is specified', async () => {
    const path = await writeYaml(
      'tiered.yaml',
      `
campaign:
  name: fast-scan
  tier: fast

target:
  url: https://api.example.com/v1/chat
`,
    );

    const config = await parseCampaignConfig(path);

    expect(config.campaign.tier).toBe('fast');
    expect(config.campaign.trialsPerProbe).toBe(1);
    expect(config.campaign.delayMs).toBe(500);
    expect(config.concurrency?.maxWorkers).toBe(5);
    expect(config.concurrency?.batchSize).toBe(20);
  });

  it('allows explicit overrides to beat tier defaults', async () => {
    const path = await writeYaml(
      'override-tier.yaml',
      `
campaign:
  name: custom-deep
  tier: deep
  trialsPerProbe: 3

target:
  url: https://api.example.com/v1/chat
`,
    );

    const config = await parseCampaignConfig(path);

    expect(config.campaign.tier).toBe('deep');
    // Explicit override should win
    expect(config.campaign.trialsPerProbe).toBe(3);
  });

  it('rejects missing target URL', async () => {
    const path = await writeYaml(
      'no-target.yaml',
      `
campaign:
  name: bad-config
`,
    );

    await expect(parseCampaignConfig(path)).rejects.toThrow();
  });

  it('rejects invalid target URL', async () => {
    const path = await writeYaml(
      'bad-url.yaml',
      `
campaign:
  name: bad-url

target:
  url: not-a-url
`,
    );

    await expect(parseCampaignConfig(path)).rejects.toThrow();
  });

  it('rejects non-YAML content', async () => {
    const path = await writeYaml('bad.yaml', 'this is not yaml: [[[');

    await expect(parseCampaignConfig(path)).rejects.toThrow();
  });

  it('parses optional category and probeIds', async () => {
    const path = await writeYaml(
      'filtered.yaml',
      `
campaign:
  name: filtered-scan
  category: goal_adherence
  probeIds:
    - GA-001
    - GA-002
    - GA-003

target:
  url: https://api.example.com/v1/chat
`,
    );

    const config = await parseCampaignConfig(path);

    expect(config.campaign.category).toBe('goal_adherence');
    expect(config.campaign.probeIds).toEqual(['GA-001', 'GA-002', 'GA-003']);
  });
});

describe('campaignConfigSchema', () => {
  it('validates a complete config object', () => {
    const result = campaignConfigSchema.safeParse({
      campaign: {
        name: 'test',
        trialsPerProbe: 5,
        confidenceLevel: 0.99,
        delayMs: 1000,
      },
      target: {
        url: 'https://api.example.com/v1/chat',
        adapterType: 'openai',
      },
      concurrency: {
        maxWorkers: 2,
        batchSize: 10,
      },
    });

    expect(result.success).toBe(true);
  });

  it('rejects negative trialsPerProbe', () => {
    const result = campaignConfigSchema.safeParse({
      campaign: {
        name: 'test',
        trialsPerProbe: -1,
      },
      target: {
        url: 'https://api.example.com/v1/chat',
      },
    });

    expect(result.success).toBe(false);
  });

  it('rejects confidenceLevel outside 0-1 range', () => {
    const result = campaignConfigSchema.safeParse({
      campaign: {
        name: 'test',
        confidenceLevel: 1.5,
      },
      target: {
        url: 'https://api.example.com/v1/chat',
      },
    });

    expect(result.success).toBe(false);
  });

  it('rejects invalid tier value', () => {
    const result = campaignConfigSchema.safeParse({
      campaign: {
        name: 'test',
        tier: 'turbo',
      },
      target: {
        url: 'https://api.example.com/v1/chat',
      },
    });

    expect(result.success).toBe(false);
  });
});
