import type { AdapterConfig } from '../types/index.js';

// ─── Provider Rotation ──────────────────────────────────

/** Maps target provider to prober provider to avoid same-family bias. */
export const PROVIDER_ROTATION: Record<string, string> = {
  openai: 'anthropic',
  anthropic: 'openai',
  google: 'anthropic',
  azure: 'anthropic',
  custom: 'openai',
};

// ─── Provider Detection ─────────────────────────────────

export function detectProvider(url: string): string {
  const lower = url.toLowerCase();
  if (lower.includes('anthropic.com')) return 'anthropic';
  if (lower.includes('openai.com')) return 'openai';
  if (lower.includes('googleapis.com') || lower.includes('google.com')) return 'google';
  if (lower.includes('azure.com')) return 'azure';
  return 'custom';
}

// ─── Adapter Selection ──────────────────────────────────

export function selectProberAdapter(targetConfig: AdapterConfig): AdapterConfig {
  const targetProvider = detectProvider(targetConfig.baseUrl);
  const proberProvider = PROVIDER_ROTATION[targetProvider];

  if (!proberProvider) {
    return { ...targetConfig };
  }

  const baseUrls: Record<string, string> = {
    openai: 'https://api.openai.com',
    anthropic: 'https://api.anthropic.com',
  };

  const proberBaseUrl = baseUrls[proberProvider];
  if (!proberBaseUrl) {
    return { ...targetConfig };
  }

  return {
    ...targetConfig,
    type: proberProvider,
    baseUrl: proberBaseUrl,
  };
}
