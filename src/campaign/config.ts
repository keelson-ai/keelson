/**
 * YAML campaign configuration parser.
 * Reads campaign config files and validates them with Zod.
 */

import { readFile } from 'node:fs/promises';
import { basename, extname } from 'node:path';

import YAML from 'yaml';
import { z } from 'zod';

import { TIER_NAMES, applyTier } from './tiers.js';
import type { TierName } from './tiers.js';

// ─── Zod Schema ─────────────────────────────────────────

export const campaignConfigSchema = z.object({
  campaign: z.object({
    name: z.string(),
    trialsPerProbe: z.number().int().positive().default(1),
    confidenceLevel: z.number().min(0).max(1).default(0.95),
    delayMs: z.number().int().min(0).default(1500),
    category: z.string().optional(),
    probeIds: z.array(z.string()).optional(),
    tier: z.enum(TIER_NAMES).optional(),
  }),
  target: z.object({
    url: z.url(),
    apiKey: z.string().optional(),
    model: z.string().optional(),
    adapterType: z.string().default('openai'),
  }),
  concurrency: z
    .object({
      maxWorkers: z.number().int().positive().default(1),
      batchSize: z.number().int().positive().default(10),
    })
    .optional(),
});

export type CampaignConfig = z.infer<typeof campaignConfigSchema>;

// ─── Parser ─────────────────────────────────────────────

export async function parseCampaignConfig(filePath: string): Promise<CampaignConfig> {
  const raw = await readFile(filePath, 'utf-8');
  const data = YAML.parse(raw) as unknown;

  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    throw new Error(`Campaign config at ${filePath} is not a valid YAML object`);
  }

  const record = data as Record<string, unknown>;

  // Default the campaign name to the file stem if not provided
  if (typeof record.campaign === 'object' && record.campaign !== null) {
    const campaign = record.campaign as Record<string, unknown>;
    if (!campaign.name) {
      campaign.name = basename(filePath, extname(filePath));
    }
  }

  // Parse and validate
  const config = campaignConfigSchema.parse(record);

  // If a tier is specified, apply tier presets (explicit fields override tier defaults)
  if (config.campaign.tier) {
    return applyTierWithOverrides(config, config.campaign.tier, record);
  }

  return config;
}

/**
 * Apply a tier preset but let explicitly-set YAML fields take priority.
 */
function applyTierWithOverrides(
  config: CampaignConfig,
  tier: TierName,
  rawData: Record<string, unknown>,
): CampaignConfig {
  const tiered = applyTier(config, tier);

  // Restore any values that were explicitly set in the YAML
  const rawCampaign = (rawData.campaign ?? {}) as Record<string, unknown>;
  const rawConcurrency = (rawData.concurrency ?? {}) as Record<string, unknown>;

  const baseConcurrency = tiered.concurrency ?? { maxWorkers: 1, batchSize: 10 };
  const concurrency = {
    maxWorkers:
      rawConcurrency.maxWorkers !== undefined
        ? (config.concurrency?.maxWorkers ?? baseConcurrency.maxWorkers)
        : baseConcurrency.maxWorkers,
    batchSize:
      rawConcurrency.batchSize !== undefined
        ? (config.concurrency?.batchSize ?? baseConcurrency.batchSize)
        : baseConcurrency.batchSize,
  };

  return {
    ...tiered,
    campaign: {
      ...tiered.campaign,
      ...(rawCampaign.trialsPerProbe !== undefined && {
        trialsPerProbe: config.campaign.trialsPerProbe,
      }),
      ...(rawCampaign.confidenceLevel !== undefined && {
        confidenceLevel: config.campaign.confidenceLevel,
      }),
      ...(rawCampaign.delayMs !== undefined && {
        delayMs: config.campaign.delayMs,
      }),
    },
    concurrency,
  };
}
