/**
 * Campaign YAML config parsing with Zod validation.
 */

import { readFile } from 'node:fs/promises';
import { basename, extname } from 'node:path';

import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

import { getTierConfig } from './tiers.js';
import type { CampaignConfig } from '../types/index.js';
import { ScanTier } from '../types/index.js';

// ─── Zod Schemas ────────────────────────────────────────

const concurrencySchema = z.object({
  max_concurrent_trials: z.number().int().min(1).optional(),
  early_termination_threshold: z.number().int().min(0).optional(),
});

const campaignSectionSchema = z.object({
  name: z.string().optional(),
  tier: z.nativeEnum(ScanTier).optional(),
  trials_per_probe: z.number().int().min(1).optional(),
  confidence_level: z.number().min(0).max(1).optional(),
  delay_between_trials: z.number().min(0).optional(),
  delay_between_probes: z.number().min(0).optional(),
  category: z.string().optional(),
  probe_ids: z.array(z.string()).optional(),
  concurrency: concurrencySchema.optional(),
});

const targetSectionSchema = z.object({
  url: z.string().optional(),
  api_key: z.string().optional(),
  model: z.string().optional(),
});

export const campaignFileSchema = z.object({
  campaign: campaignSectionSchema.optional().default({}),
  target: targetSectionSchema.optional().default({}),
});

export type RawCampaignFile = z.infer<typeof campaignFileSchema>;

// ─── Default Config ─────────────────────────────────────

export function defaultCampaignConfig(): CampaignConfig {
  return {
    name: 'default',
    trialsPerProbe: 5,
    confidenceLevel: 0.95,
    delayBetweenTrials: 1.0,
    delayBetweenProbes: 2.0,
    probeIds: [],
    targetUrl: '',
    apiKey: '',
    model: 'default',
    concurrency: {
      maxConcurrentTrials: 5,
      earlyTerminationThreshold: 3,
    },
  };
}

// ─── Parse Campaign Config ──────────────────────────────

/**
 * Parse a raw config object (already deserialized from YAML) into a CampaignConfig.
 */
export function parseCampaignData(data: unknown, fallbackName?: string): CampaignConfig {
  const parsed = campaignFileSchema.parse(data);
  const campaign = parsed.campaign;
  const target = parsed.target;

  // If a tier is specified, start from tier preset
  let config: CampaignConfig;
  if (campaign.tier) {
    config = getTierConfig(campaign.tier);
  } else {
    config = defaultCampaignConfig();
  }

  // Apply explicit overrides
  config.name = campaign.name ?? (campaign.tier ? config.name : (fallbackName ?? config.name));
  if (campaign.trials_per_probe !== undefined) config.trialsPerProbe = campaign.trials_per_probe;
  if (campaign.confidence_level !== undefined) config.confidenceLevel = campaign.confidence_level;
  if (campaign.delay_between_trials !== undefined) config.delayBetweenTrials = campaign.delay_between_trials;
  if (campaign.delay_between_probes !== undefined) config.delayBetweenProbes = campaign.delay_between_probes;
  if (campaign.category !== undefined) config.category = campaign.category;
  if (campaign.probe_ids !== undefined) config.probeIds = campaign.probe_ids;
  if (target.url !== undefined) config.targetUrl = target.url;
  if (target.api_key !== undefined) config.apiKey = target.api_key;
  if (target.model !== undefined) config.model = target.model;

  // Parse concurrency overrides
  if (campaign.concurrency) {
    if (campaign.concurrency.max_concurrent_trials !== undefined) {
      config.concurrency.maxConcurrentTrials = campaign.concurrency.max_concurrent_trials;
    }
    if (campaign.concurrency.early_termination_threshold !== undefined) {
      config.concurrency.earlyTerminationThreshold = campaign.concurrency.early_termination_threshold;
    }
  }

  return config;
}

/**
 * Parse a campaign config file (YAML) into a CampaignConfig.
 */
export async function parseCampaignFile(filePath: string): Promise<CampaignConfig> {
  const content = await readFile(filePath, 'utf-8');
  const ext = extname(filePath).toLowerCase();

  let data: unknown;
  if (ext === '.yaml' || ext === '.yml') {
    data = parseYaml(content);
  } else {
    throw new Error(`Unsupported campaign config format: ${ext}. Use .yaml or .yml`);
  }

  const stem = basename(filePath, ext);
  return parseCampaignData(data, stem);
}
