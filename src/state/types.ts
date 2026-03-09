/**
 * Persisted data shapes for the SQLite store.
 */

import { Verdict } from '../types/index.js';

// ─── Persisted Data Shapes ──────────────────────────────

export interface PersistedTarget {
  url: string;
  apiKey: string;
  model: string;
  name: string;
}

export interface PersistedCampaignConfig {
  name: string;
  trialsPerProbe: number;
  confidenceLevel: number;
  category: string | null;
  probeIds: string[];
}

export interface PersistedEvidenceItem {
  stepIndex: number;
  prompt: string;
  response: string;
  responseTimeMs: number;
}

export interface PersistedTrialResult {
  trialIndex: number;
  verdict: Verdict;
  evidence: PersistedEvidenceItem[];
  reasoning: string;
  responseTimeMs: number;
}

export interface PersistedStatisticalFinding {
  templateId: string;
  templateName: string;
  severity: string;
  category: string;
  owasp: string;
  trials: PersistedTrialResult[];
  successRate: number;
  ciLower: number;
  ciUpper: number;
  verdict: Verdict;
}

export interface PersistedCampaignResult {
  campaignId: string;
  config: PersistedCampaignConfig;
  target: PersistedTarget;
  findings: PersistedStatisticalFinding[];
  startedAt: string;
  finishedAt: string | null;
}

export interface CacheEntry {
  cacheKey: string;
  messages: Array<Record<string, unknown>>;
  model: string;
  responseText: string;
  responseTimeMs: number;
  createdAt: string;
  hitCount: number;
}

export interface PersistedRegressionAlert {
  id: number;
  scanAId: string;
  scanBId: string;
  templateId: string;
  alertSeverity: string;
  changeType: string;
  description: string;
  createdAt: string;
  acknowledged: boolean;
}

export interface PersistedProbeStep {
  index: number;
  prompt: string;
  isFollowup: boolean;
}

export interface PersistedProbeChain {
  chainId: string;
  profileId: string | null;
  name: string;
  capabilities: string[];
  steps: PersistedProbeStep[];
  severity: string;
  category: string;
  owasp: string;
  createdAt: string;
}

export interface Baseline {
  scanId: string;
  label: string;
  createdAt: string;
}

export interface EventRecord {
  timestamp: string;
  eventType: string;
  data: Record<string, unknown>;
}

export interface ScanListEntry {
  scanId: string;
  target: string;
  startedAt: string;
  completedAt: string;
  total: number;
  vulnerable: number;
  safe: number;
}

export interface CampaignListEntry {
  campaignId: string;
  targetUrl: string;
  startedAt: string;
  finishedAt: string | null;
  totalProbes: number;
  vulnerable: number;
}
