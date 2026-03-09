/**
 * JSON file persistence for scans, findings, campaigns, agent profiles,
 * baselines, cache entries, regression alerts, and probe chains.
 *
 * Mirrors the Python SQLite store from `_legacy/src/state/store.py`,
 * using flat JSON files under `~/.keelson/` instead of SQLite.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

import { z } from 'zod';

import type { ScanResult } from '../types/index.js';
import { Severity, Verdict } from '../types/index.js';

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
  severity: Severity;
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

export interface AgentCapability {
  name: string;
  detected: boolean;
  probePrompt: string;
  responseExcerpt: string;
  confidence: number;
}

export interface AgentProfile {
  profileId: string;
  targetUrl: string;
  capabilities: AgentCapability[];
  createdAt: string;
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

export interface RegressionAlert {
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

export interface ProbeStep {
  index: number;
  prompt: string;
  isFollowup: boolean;
}

export interface ProbeChain {
  chainId: string;
  profileId: string | null;
  name: string;
  capabilities: string[];
  steps: ProbeStep[];
  severity: Severity;
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

// ─── Store Data Schema (Zod validation for persisted JSON) ──

const evidenceItemSchema = z.object({
  stepIndex: z.number(),
  prompt: z.string(),
  response: z.string(),
  responseTimeMs: z.number(),
});

const findingSchema = z.object({
  probeId: z.string(),
  probeName: z.string(),
  severity: z.string(),
  category: z.string(),
  owaspId: z.string(),
  verdict: z.string(),
  confidence: z.number(),
  reasoning: z.string(),
  scoringMethod: z.string(),
  conversation: z.array(z.object({ role: z.string(), content: z.string() })),
  evidence: z.array(evidenceItemSchema),
  leakageSignals: z.array(z.unknown()).default([]),
  timestamp: z.string(),
});

const scanSummarySchema = z.object({
  total: z.number(),
  vulnerable: z.number(),
  safe: z.number(),
  inconclusive: z.number(),
  bySeverity: z.record(z.string(), z.number()),
  byCategory: z.record(z.string(), z.number()),
});

const scanResultSchema = z.object({
  scanId: z.string(),
  target: z.string(),
  startedAt: z.string(),
  completedAt: z.string(),
  findings: z.array(findingSchema),
  summary: scanSummarySchema,
  memo: z.array(z.unknown()).optional(),
});

const trialResultSchema = z.object({
  trialIndex: z.number(),
  verdict: z.nativeEnum(Verdict),
  evidence: z.array(evidenceItemSchema),
  reasoning: z.string(),
  responseTimeMs: z.number(),
});

const statisticalFindingSchema = z.object({
  templateId: z.string(),
  templateName: z.string(),
  severity: z.nativeEnum(Severity),
  category: z.string(),
  owasp: z.string(),
  trials: z.array(trialResultSchema),
  successRate: z.number(),
  ciLower: z.number(),
  ciUpper: z.number(),
  verdict: z.nativeEnum(Verdict),
});

const campaignConfigSchema = z.object({
  name: z.string(),
  trialsPerProbe: z.number(),
  confidenceLevel: z.number(),
  category: z.string().nullable(),
  probeIds: z.array(z.string()),
});

const targetSchema = z.object({
  url: z.string(),
  apiKey: z.string(),
  model: z.string(),
  name: z.string(),
});

const campaignResultSchema = z.object({
  campaignId: z.string(),
  config: campaignConfigSchema,
  target: targetSchema,
  findings: z.array(statisticalFindingSchema),
  startedAt: z.string(),
  finishedAt: z.string().nullable(),
});

const agentCapabilitySchema = z.object({
  name: z.string(),
  detected: z.boolean(),
  probePrompt: z.string(),
  responseExcerpt: z.string(),
  confidence: z.number(),
});

const agentProfileSchema = z.object({
  profileId: z.string(),
  targetUrl: z.string(),
  capabilities: z.array(agentCapabilitySchema),
  createdAt: z.string(),
});

const cacheEntrySchema = z.object({
  cacheKey: z.string(),
  messages: z.array(z.record(z.string(), z.unknown())),
  model: z.string(),
  responseText: z.string(),
  responseTimeMs: z.number(),
  createdAt: z.string(),
  hitCount: z.number(),
});

const regressionAlertSchema = z.object({
  id: z.number(),
  scanAId: z.string(),
  scanBId: z.string(),
  templateId: z.string(),
  alertSeverity: z.string(),
  changeType: z.string(),
  description: z.string(),
  createdAt: z.string(),
  acknowledged: z.boolean(),
});

const probeStepSchema = z.object({
  index: z.number(),
  prompt: z.string(),
  isFollowup: z.boolean(),
});

const probeChainSchema = z.object({
  chainId: z.string(),
  profileId: z.string().nullable(),
  name: z.string(),
  capabilities: z.array(z.string()),
  steps: z.array(probeStepSchema),
  severity: z.nativeEnum(Severity),
  category: z.string(),
  owasp: z.string(),
  createdAt: z.string(),
});

const baselineSchema = z.object({
  scanId: z.string(),
  label: z.string(),
  createdAt: z.string(),
});

const eventRecordSchema = z.object({
  timestamp: z.string(),
  eventType: z.string(),
  data: z.record(z.string(), z.unknown()),
});

const storeDataSchema = z.object({
  scans: z.array(scanResultSchema).default([]),
  campaigns: z.array(campaignResultSchema).default([]),
  agentProfiles: z.array(agentProfileSchema).default([]),
  cache: z.array(cacheEntrySchema).default([]),
  regressionAlerts: z.array(regressionAlertSchema).default([]),
  probeChains: z.array(probeChainSchema).default([]),
  baselines: z.array(baselineSchema).default([]),
  events: z.array(eventRecordSchema).default([]),
});

type StoreData = z.infer<typeof storeDataSchema>;

// ─── Default path ───────────────────────────────────────

const DEFAULT_STORE_PATH = join(homedir(), '.keelson', 'store.json');

// ─── Store Implementation ───────────────────────────────

export class Store {
  private data: StoreData;
  private dirty = false;
  private nextAlertId = 1;

  private constructor(
    readonly storePath: string,
    data: StoreData,
  ) {
    this.data = data;
    // Derive next alert ID from existing data
    const maxId = data.regressionAlerts.reduce(
      (max, a) => Math.max(max, a.id),
      0,
    );
    this.nextAlertId = maxId + 1;
  }

  /** Create or open a store at the given path. */
  static async open(storePath?: string): Promise<Store> {
    const path = storePath ?? DEFAULT_STORE_PATH;
    let data: StoreData;
    try {
      const raw = await readFile(path, 'utf-8');
      const parsed: unknown = JSON.parse(raw);
      data = storeDataSchema.parse(parsed);
    } catch (err: unknown) {
      // File doesn't exist -- start with empty store (normal first-run)
      if (
        err instanceof Error &&
        'code' in err &&
        (err as NodeJS.ErrnoException).code === 'ENOENT'
      ) {
        data = storeDataSchema.parse({});
      } else if (err instanceof z.ZodError) {
        // Zod validation failed -- data is corrupt/outdated, warn and reset
        console.warn(
          `[keelson] Store file at ${path} failed validation, starting fresh: ${err.message}`,
        );
        data = storeDataSchema.parse({});
      } else if (err instanceof SyntaxError) {
        // Corrupt JSON -- warn and reset
        console.warn(
          `[keelson] Store file at ${path} contains invalid JSON, starting fresh: ${err.message}`,
        );
        data = storeDataSchema.parse({});
      } else {
        // Permission denied, disk full, etc. -- do NOT silently swallow
        throw err;
      }
    }
    return new Store(path, data);
  }

  // ─── Scan persistence ──────────────────────────────────

  async saveScan(scan: ScanResult): Promise<void> {
    // Remove existing scan with same ID (upsert)
    this.data.scans = this.data.scans.filter((s) => s.scanId !== scan.scanId);
    this.data.scans.push(scan as unknown as StoreData['scans'][number]);
    this.logEvent('scan_completed', {
      scanId: scan.scanId,
      target: scan.target,
    });
    await this.flush();
  }

  getScan(scanId: string): ScanResult | undefined {
    const found = this.data.scans.find((s) => s.scanId === scanId);
    return found as unknown as ScanResult | undefined;
  }

  listScans(limit = 20): ScanListEntry[] {
    const sorted = [...this.data.scans].sort(
      (a, b) =>
        new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime(),
    );
    return sorted.slice(0, limit).map((s) => ({
      scanId: s.scanId,
      target: s.target,
      startedAt: s.startedAt,
      completedAt: s.completedAt,
      total: s.summary.total,
      vulnerable: s.summary.vulnerable,
      safe: s.summary.safe,
    }));
  }

  // ─── Campaign persistence ─────────────────────────────

  async saveCampaign(campaign: PersistedCampaignResult): Promise<void> {
    this.data.campaigns = this.data.campaigns.filter(
      (c) => c.campaignId !== campaign.campaignId,
    );
    this.data.campaigns.push(campaign);
    this.logEvent('campaign_completed', {
      campaignId: campaign.campaignId,
      target: campaign.target.url,
    });
    await this.flush();
  }

  getCampaign(campaignId: string): PersistedCampaignResult | undefined {
    return this.data.campaigns.find((c) => c.campaignId === campaignId);
  }

  listCampaigns(limit = 20): CampaignListEntry[] {
    const sorted = [...this.data.campaigns].sort(
      (a, b) =>
        new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime(),
    );
    return sorted.slice(0, limit).map((c) => ({
      campaignId: c.campaignId,
      targetUrl: c.target.url,
      startedAt: c.startedAt,
      finishedAt: c.finishedAt,
      totalProbes: c.findings.length,
      vulnerable: c.findings.filter((f) => f.verdict === Verdict.Vulnerable)
        .length,
    }));
  }

  // ─── Agent profile persistence ────────────────────────

  async saveAgentProfile(profile: AgentProfile): Promise<void> {
    this.data.agentProfiles = this.data.agentProfiles.filter(
      (p) => p.profileId !== profile.profileId,
    );
    this.data.agentProfiles.push(profile);
    this.logEvent('profile_saved', {
      profileId: profile.profileId,
      target: profile.targetUrl,
    });
    await this.flush();
  }

  getAgentProfile(profileId: string): AgentProfile | undefined {
    return this.data.agentProfiles.find((p) => p.profileId === profileId);
  }

  // ─── Baseline persistence ─────────────────────────────

  async saveBaseline(scanId: string, label = ''): Promise<void> {
    this.data.baselines = this.data.baselines.filter(
      (b) => b.scanId !== scanId,
    );
    this.data.baselines.push({
      scanId,
      label,
      createdAt: new Date().toISOString(),
    });
    this.logEvent('baseline_set', { scanId, label });
    await this.flush();
  }

  getBaselines(limit = 20): Baseline[] {
    const sorted = [...this.data.baselines].sort(
      (a, b) =>
        new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
    );
    return sorted.slice(0, limit);
  }

  // ─── Response cache persistence ───────────────────────

  async saveCacheEntry(
    cacheKey: string,
    messages: Array<Record<string, unknown>>,
    model: string,
    responseText: string,
    responseTimeMs: number,
  ): Promise<void> {
    this.data.cache = this.data.cache.filter((c) => c.cacheKey !== cacheKey);
    this.data.cache.push({
      cacheKey,
      messages,
      model,
      responseText,
      responseTimeMs,
      createdAt: new Date().toISOString(),
      hitCount: 0,
    });
    await this.flush();
  }

  async getCacheEntry(cacheKey: string): Promise<CacheEntry | undefined> {
    const entry = this.data.cache.find((c) => c.cacheKey === cacheKey);
    if (!entry) return undefined;
    // Increment hit count
    entry.hitCount++;
    await this.flush();
    return entry;
  }

  // ─── Regression alerts ────────────────────────────────

  async saveRegressionAlerts(
    scanAId: string,
    scanBId: string,
    alerts: Array<{
      templateId: string;
      alertSeverity: string;
      changeType: string;
      description: string;
    }>,
  ): Promise<void> {
    for (const alert of alerts) {
      this.data.regressionAlerts.push({
        id: this.nextAlertId++,
        scanAId,
        scanBId,
        templateId: alert.templateId,
        alertSeverity: alert.alertSeverity,
        changeType: alert.changeType,
        description: alert.description,
        createdAt: new Date().toISOString(),
        acknowledged: false,
      });
    }
    this.logEvent('regression_alerts_saved', {
      scanAId,
      scanBId,
      count: alerts.length,
    });
    await this.flush();
  }

  listRegressionAlerts(limit = 50): RegressionAlert[] {
    const sorted = [...this.data.regressionAlerts].sort(
      (a, b) =>
        new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
    );
    return sorted.slice(0, limit);
  }

  async acknowledgeAlert(alertId: number): Promise<void> {
    const alert = this.data.regressionAlerts.find((a) => a.id === alertId);
    if (alert) {
      alert.acknowledged = true;
      await this.flush();
    }
  }

  // ─── Probe chain persistence ──────────────────────────

  async saveProbeChain(chain: Omit<ProbeChain, 'createdAt'>): Promise<void> {
    this.data.probeChains = this.data.probeChains.filter(
      (c) => c.chainId !== chain.chainId,
    );
    this.data.probeChains.push({
      ...chain,
      createdAt: new Date().toISOString(),
    });
    this.logEvent('probe_chain_saved', {
      chainId: chain.chainId,
      name: chain.name,
    });
    await this.flush();
  }

  getProbeChain(chainId: string): ProbeChain | undefined {
    return this.data.probeChains.find((c) => c.chainId === chainId);
  }

  listProbeChains(profileId?: string, limit = 50): ProbeChain[] {
    let chains = [...this.data.probeChains];
    if (profileId) {
      chains = chains.filter((c) => c.profileId === profileId);
    }
    chains.sort(
      (a, b) =>
        new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
    );
    return chains.slice(0, limit);
  }

  // ─── Events ───────────────────────────────────────────

  getEvents(limit = 100): EventRecord[] {
    const sorted = [...this.data.events].sort(
      (a, b) =>
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
    );
    return sorted.slice(0, limit);
  }

  // ─── Internal helpers ─────────────────────────────────

  private logEvent(
    eventType: string,
    data: Record<string, unknown>,
  ): void {
    this.data.events.push({
      timestamp: new Date().toISOString(),
      eventType,
      data,
    });
    this.dirty = true;
  }

  private async flush(): Promise<void> {
    this.dirty = true;
    await mkdir(dirname(this.storePath), { recursive: true });
    await writeFile(
      this.storePath,
      JSON.stringify(this.data, null, 2),
      'utf-8',
    );
    this.dirty = false;
  }

  /** Returns true if there are unsaved changes (for testing). */
  isDirty(): boolean {
    return this.dirty;
  }
}
