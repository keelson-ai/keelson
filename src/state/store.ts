/**
 * SQLite-backed persistence for scans, findings, campaigns, agent profiles,
 * baselines, cache entries, regression alerts, and probe chains.
 *
 * Uses better-sqlite3 for synchronous, single-file storage under `~/.keelson/`.
 */

import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

import Database from 'better-sqlite3';
import type { Database as DatabaseType, Statement } from 'better-sqlite3';

import { DEFAULT_DB_PATH, SCHEMA_SQL } from './schema.js';
import type {
  Baseline,
  CacheEntry,
  CampaignListEntry,
  EventRecord,
  PersistedCampaignResult,
  PersistedProbeChain,
  PersistedRegressionAlert,
  PersistedStatisticalFinding,
  PersistedTarget,
  ScanListEntry,
  StrategicLearning,
  TacticalLearning,
} from './types.js';
import type { AgentProfile } from '../prober/types.js';
import type { ScanResult } from '../types/index.js';
import { Verdict } from '../types/index.js';

// Re-export all types for backward compatibility
export type {
  Baseline,
  CacheEntry,
  CampaignListEntry,
  EventRecord,
  PersistedCampaignConfig,
  PersistedCampaignResult,
  PersistedEvidenceItem,
  PersistedProbeChain,
  PersistedProbeStep,
  PersistedRegressionAlert,
  PersistedStatisticalFinding,
  PersistedTarget,
  PersistedTrialResult,
  ScanListEntry,
  StrategicLearning,
  TacticalLearning,
} from './types.js';

// ─── Store Implementation ───────────────────────────────

export class Store {
  readonly dbPath: string;
  private db: DatabaseType;

  // Cached prepared statements
  private stmtUpsertScan: Statement;
  private stmtGetScan: Statement;
  private stmtListScans: Statement;
  private stmtUpsertCampaign: Statement;
  private stmtGetCampaign: Statement;
  private stmtListCampaigns: Statement;
  private stmtUpsertProfile: Statement;
  private stmtGetProfile: Statement;
  private stmtUpsertBaseline: Statement;
  private stmtListBaselines: Statement;
  private stmtUpsertCache: Statement;
  private stmtGetCache: Statement;
  private stmtIncrCacheHit: Statement;
  private stmtInsertAlert: Statement;
  private stmtListAlerts: Statement;
  private stmtAckAlert: Statement;
  private stmtUpsertChain: Statement;
  private stmtGetChain: Statement;
  private stmtListChains: Statement;
  private stmtListChainsByProfile: Statement;
  private stmtInsertEvent: Statement;
  private stmtListEvents: Statement;
  private stmtInsertTactical: Statement;
  private stmtUpsertStrategic: Statement;
  private stmtCountTable: Map<string, Statement>;

  private constructor(dbPath: string, db: DatabaseType) {
    this.dbPath = dbPath;
    this.db = db;

    // Prepare all statements
    this.stmtUpsertScan = db.prepare(
      `INSERT OR REPLACE INTO scans (scan_id, target, started_at, completed_at, findings, summary, memo)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    );
    this.stmtGetScan = db.prepare(`SELECT * FROM scans WHERE scan_id = ?`);
    this.stmtListScans = db.prepare(`SELECT * FROM scans ORDER BY started_at DESC LIMIT ?`);

    this.stmtUpsertCampaign = db.prepare(
      `INSERT OR REPLACE INTO campaigns (campaign_id, config, target, findings, started_at, finished_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    );
    this.stmtGetCampaign = db.prepare(`SELECT * FROM campaigns WHERE campaign_id = ?`);
    this.stmtListCampaigns = db.prepare(`SELECT * FROM campaigns ORDER BY started_at DESC LIMIT ?`);

    this.stmtUpsertProfile = db.prepare(
      `INSERT OR REPLACE INTO agent_profiles (profile_id, target_url, capabilities, created_at)
       VALUES (?, ?, ?, ?)`,
    );
    this.stmtGetProfile = db.prepare(`SELECT * FROM agent_profiles WHERE profile_id = ?`);

    this.stmtUpsertBaseline = db.prepare(
      `INSERT OR REPLACE INTO baselines (scan_id, label, created_at) VALUES (?, ?, ?)`,
    );
    this.stmtListBaselines = db.prepare(`SELECT * FROM baselines ORDER BY created_at DESC LIMIT ?`);

    this.stmtUpsertCache = db.prepare(
      `INSERT OR REPLACE INTO cache (cache_key, messages, model, response_text, response_time_ms, created_at, hit_count)
       VALUES (?, ?, ?, ?, ?, ?, 0)`,
    );
    this.stmtGetCache = db.prepare(`SELECT * FROM cache WHERE cache_key = ?`);
    this.stmtIncrCacheHit = db.prepare(`UPDATE cache SET hit_count = hit_count + 1 WHERE cache_key = ?`);

    this.stmtInsertAlert = db.prepare(
      `INSERT INTO regression_alerts (scan_a_id, scan_b_id, template_id, alert_severity, change_type, description, created_at, acknowledged)
       VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
    );
    this.stmtListAlerts = db.prepare(`SELECT * FROM regression_alerts ORDER BY created_at DESC LIMIT ?`);
    this.stmtAckAlert = db.prepare(`UPDATE regression_alerts SET acknowledged = 1 WHERE id = ?`);

    this.stmtUpsertChain = db.prepare(
      `INSERT OR REPLACE INTO probe_chains (chain_id, profile_id, name, capabilities, steps, severity, category, owasp, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    this.stmtGetChain = db.prepare(`SELECT * FROM probe_chains WHERE chain_id = ?`);
    this.stmtListChains = db.prepare(`SELECT * FROM probe_chains ORDER BY created_at DESC LIMIT ?`);
    this.stmtListChainsByProfile = db.prepare(
      `SELECT * FROM probe_chains WHERE profile_id = ? ORDER BY created_at DESC LIMIT ?`,
    );

    this.stmtInsertEvent = db.prepare(`INSERT INTO events (timestamp, event_type, data) VALUES (?, ?, ?)`);
    this.stmtListEvents = db.prepare(`SELECT * FROM events ORDER BY timestamp DESC LIMIT ?`);

    this.stmtInsertTactical = db.prepare(
      `INSERT INTO tactical_learnings (engagement_id, target_url, agent_type, technique, category, outcome, insight, novelty, turn_number, confidence, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    this.stmtUpsertStrategic = db.prepare(
      `INSERT INTO strategic_learnings (agent_type, technique, category, success_rate, engagement_count, insight, evidence_summary, confidence, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(agent_type, technique, category) DO UPDATE SET
         success_rate = excluded.success_rate,
         engagement_count = excluded.engagement_count,
         insight = excluded.insight,
         evidence_summary = excluded.evidence_summary,
         confidence = excluded.confidence,
         updated_at = excluded.updated_at`,
    );

    // Table count statements
    this.stmtCountTable = new Map();
    for (const table of [
      'scans',
      'campaigns',
      'agent_profiles',
      'baselines',
      'cache',
      'regression_alerts',
      'probe_chains',
      'events',
      'tactical_learnings',
      'strategic_learnings',
    ]) {
      this.stmtCountTable.set(table, db.prepare(`SELECT COUNT(*) as count FROM ${table}`));
    }
  }

  /** Create or open a store at the given path. */
  static open(dbPath?: string): Store {
    const path = dbPath ?? DEFAULT_DB_PATH;
    mkdirSync(dirname(path), { recursive: true });
    const db = new Database(path);
    db.pragma('journal_mode = WAL');
    db.exec(SCHEMA_SQL);
    return new Store(path, db);
  }

  // ─── Scan persistence ──────────────────────────────────

  saveScan(scan: ScanResult): void {
    this.stmtUpsertScan.run(
      scan.scanId,
      scan.target,
      scan.startedAt,
      scan.completedAt,
      JSON.stringify(scan.findings),
      JSON.stringify(scan.summary),
      scan.memo ? JSON.stringify(scan.memo) : null,
    );
    this.logEvent('scan_completed', {
      scanId: scan.scanId,
      target: scan.target,
    });
  }

  getScan(scanId: string): ScanResult | undefined {
    const row = this.stmtGetScan.get(scanId) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    return this.rowToScan(row);
  }

  listScans(limit = 20): ScanListEntry[] {
    const rows = this.stmtListScans.all(limit) as Array<Record<string, unknown>>;
    return rows.map((row) => {
      const summary = JSON.parse(row.summary as string) as { total: number; vulnerable: number; safe: number };
      return {
        scanId: row.scan_id as string,
        target: row.target as string,
        startedAt: row.started_at as string,
        completedAt: row.completed_at as string,
        total: summary.total,
        vulnerable: summary.vulnerable,
        safe: summary.safe,
      };
    });
  }

  // ─── Campaign persistence ─────────────────────────────

  saveCampaign(campaign: PersistedCampaignResult): void {
    this.stmtUpsertCampaign.run(
      campaign.campaignId,
      JSON.stringify(campaign.config),
      JSON.stringify(campaign.target),
      JSON.stringify(campaign.findings),
      campaign.startedAt,
      campaign.finishedAt ?? null,
    );
    this.logEvent('campaign_completed', {
      campaignId: campaign.campaignId,
      target: campaign.target.url,
    });
  }

  getCampaign(campaignId: string): PersistedCampaignResult | undefined {
    const row = this.stmtGetCampaign.get(campaignId) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    return this.rowToCampaign(row);
  }

  listCampaigns(limit = 20): CampaignListEntry[] {
    const rows = this.stmtListCampaigns.all(limit) as Array<Record<string, unknown>>;
    return rows.map((row) => {
      const target = JSON.parse(row.target as string) as PersistedTarget;
      const findings = JSON.parse(row.findings as string) as PersistedStatisticalFinding[];
      return {
        campaignId: row.campaign_id as string,
        targetUrl: target.url,
        startedAt: row.started_at as string,
        finishedAt: (row.finished_at as string | null) ?? null,
        totalProbes: findings.length,
        vulnerable: findings.filter((f) => f.verdict === Verdict.Vulnerable).length,
      };
    });
  }

  // ─── Agent profile persistence ────────────────────────

  saveAgentProfile(profile: AgentProfile): void {
    this.stmtUpsertProfile.run(
      profile.profileId,
      profile.targetUrl,
      JSON.stringify(profile.capabilities),
      profile.createdAt,
    );
    this.logEvent('profile_saved', {
      profileId: profile.profileId,
      target: profile.targetUrl,
    });
  }

  getAgentProfile(profileId: string): AgentProfile | undefined {
    const row = this.stmtGetProfile.get(profileId) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    return {
      profileId: row.profile_id as string,
      targetUrl: row.target_url as string,
      capabilities: JSON.parse(row.capabilities as string),
      createdAt: row.created_at as string,
    };
  }

  // ─── Baseline persistence ─────────────────────────────

  saveBaseline(scanId: string, label = ''): void {
    this.stmtUpsertBaseline.run(scanId, label, new Date().toISOString());
    this.logEvent('baseline_set', { scanId, label });
  }

  getBaselines(limit = 20): Baseline[] {
    const rows = this.stmtListBaselines.all(limit) as Array<Record<string, unknown>>;
    return rows.map((row) => ({
      scanId: row.scan_id as string,
      label: row.label as string,
      createdAt: row.created_at as string,
    }));
  }

  // ─── Response cache persistence ───────────────────────

  saveCacheEntry(
    cacheKey: string,
    messages: Array<Record<string, unknown>>,
    model: string,
    responseText: string,
    responseTimeMs: number,
  ): void {
    this.stmtUpsertCache.run(
      cacheKey,
      JSON.stringify(messages),
      model,
      responseText,
      responseTimeMs,
      new Date().toISOString(),
    );
  }

  getCacheEntry(cacheKey: string): CacheEntry | undefined {
    const row = this.stmtGetCache.get(cacheKey) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    // Increment hit count
    this.stmtIncrCacheHit.run(cacheKey);
    return {
      cacheKey: row.cache_key as string,
      messages: JSON.parse(row.messages as string),
      model: row.model as string,
      responseText: row.response_text as string,
      responseTimeMs: row.response_time_ms as number,
      createdAt: row.created_at as string,
      hitCount: (row.hit_count as number) + 1,
    };
  }

  // ─── Regression alerts ────────────────────────────────

  saveRegressionAlerts(
    scanAId: string,
    scanBId: string,
    alerts: Array<{
      templateId: string;
      alertSeverity: string;
      changeType: string;
      description: string;
    }>,
  ): void {
    const now = new Date().toISOString();
    const insertMany = this.db.transaction(() => {
      for (const alert of alerts) {
        this.stmtInsertAlert.run(
          scanAId,
          scanBId,
          alert.templateId,
          alert.alertSeverity,
          alert.changeType,
          alert.description,
          now,
        );
      }
    });
    insertMany();
    this.logEvent('regression_alerts_saved', {
      scanAId,
      scanBId,
      count: alerts.length,
    });
  }

  listRegressionAlerts(limit = 50): PersistedRegressionAlert[] {
    const rows = this.stmtListAlerts.all(limit) as Array<Record<string, unknown>>;
    return rows.map((row) => ({
      id: row.id as number,
      scanAId: row.scan_a_id as string,
      scanBId: row.scan_b_id as string,
      templateId: row.template_id as string,
      alertSeverity: row.alert_severity as string,
      changeType: row.change_type as string,
      description: row.description as string,
      createdAt: row.created_at as string,
      acknowledged: (row.acknowledged as number) === 1,
    }));
  }

  acknowledgeAlert(alertId: number): void {
    this.stmtAckAlert.run(alertId);
  }

  // ─── Probe chain persistence ──────────────────────────

  saveProbeChain(chain: Omit<PersistedProbeChain, 'createdAt'>): void {
    const now = new Date().toISOString();
    this.stmtUpsertChain.run(
      chain.chainId,
      chain.profileId ?? null,
      chain.name,
      JSON.stringify(chain.capabilities),
      JSON.stringify(chain.steps),
      chain.severity,
      chain.category,
      chain.owasp,
      now,
    );
    this.logEvent('probe_chain_saved', {
      chainId: chain.chainId,
      name: chain.name,
    });
  }

  getProbeChain(chainId: string): PersistedProbeChain | undefined {
    const row = this.stmtGetChain.get(chainId) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    return this.rowToChain(row);
  }

  listProbeChains(profileId?: string, limit = 50): PersistedProbeChain[] {
    const rows = profileId
      ? (this.stmtListChainsByProfile.all(profileId, limit) as Array<Record<string, unknown>>)
      : (this.stmtListChains.all(limit) as Array<Record<string, unknown>>);
    return rows.map((row) => this.rowToChain(row));
  }

  // ─── Events ───────────────────────────────────────────

  getEvents(limit = 100): EventRecord[] {
    const rows = this.stmtListEvents.all(limit) as Array<Record<string, unknown>>;
    return rows.map((row) => ({
      timestamp: row.timestamp as string,
      eventType: row.event_type as string,
      data: JSON.parse(row.data as string),
    }));
  }

  // ─── Tactical learnings ─────────────────────────────────

  saveTacticalLearning(learning: {
    engagementId: string;
    targetUrl: string;
    agentType?: string;
    technique: string;
    category?: string;
    outcome: string;
    insight: string;
    novelty?: string;
    turnNumber?: number;
    confidence?: number;
  }): void {
    const now = new Date().toISOString();
    this.stmtInsertTactical.run(
      learning.engagementId,
      learning.targetUrl,
      learning.agentType ?? null,
      learning.technique,
      learning.category ?? null,
      learning.outcome,
      learning.insight,
      learning.novelty ?? 'novel',
      learning.turnNumber ?? null,
      learning.confidence ?? 0.5,
      now,
    );
    this.logEvent('tactical_learning_saved', {
      engagementId: learning.engagementId,
      technique: learning.technique,
    });
  }

  listTacticalLearnings(opts: {
    targetUrl?: string;
    engagementId?: string;
    technique?: string;
    limit?: number;
  }): TacticalLearning[] {
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (opts.targetUrl) {
      conditions.push('target_url = ?');
      params.push(opts.targetUrl);
    }
    if (opts.engagementId) {
      conditions.push('engagement_id = ?');
      params.push(opts.engagementId);
    }
    if (opts.technique) {
      conditions.push('technique = ?');
      params.push(opts.technique);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = opts.limit ?? 20;
    params.push(limit);

    const rows = this.db
      .prepare(`SELECT * FROM tactical_learnings ${where} ORDER BY created_at DESC LIMIT ?`)
      .all(...params) as Array<Record<string, unknown>>;

    return rows.map((row) => ({
      id: row.id as number,
      engagementId: row.engagement_id as string,
      targetUrl: row.target_url as string,
      agentType: (row.agent_type as string | null) ?? null,
      technique: row.technique as string,
      category: (row.category as string | null) ?? null,
      outcome: row.outcome as string,
      insight: row.insight as string,
      novelty: row.novelty as string,
      turnNumber: (row.turn_number as number | null) ?? null,
      confidence: row.confidence as number,
      createdAt: row.created_at as string,
    }));
  }

  // ─── Strategic learnings ────────────────────────────────

  upsertStrategicLearning(learning: {
    agentType: string;
    technique: string;
    category?: string;
    successRate?: number;
    engagementCount?: number;
    insight: string;
    evidenceSummary?: string;
    confidence?: number;
  }): void {
    const now = new Date().toISOString();
    this.stmtUpsertStrategic.run(
      learning.agentType,
      learning.technique,
      learning.category ?? null,
      learning.successRate ?? null,
      learning.engagementCount ?? 1,
      learning.insight,
      learning.evidenceSummary ?? null,
      learning.confidence ?? 0.5,
      now,
      now,
    );
    this.logEvent('strategic_learning_upserted', {
      agentType: learning.agentType,
      technique: learning.technique,
    });
  }

  listStrategicLearnings(opts: {
    agentType?: string;
    technique?: string;
    category?: string;
    limit?: number;
  }): StrategicLearning[] {
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (opts.agentType) {
      conditions.push('agent_type = ?');
      params.push(opts.agentType);
    }
    if (opts.technique) {
      conditions.push('technique = ?');
      params.push(opts.technique);
    }
    if (opts.category) {
      conditions.push('category = ?');
      params.push(opts.category);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = opts.limit ?? 20;
    params.push(limit);

    const rows = this.db
      .prepare(`SELECT * FROM strategic_learnings ${where} ORDER BY updated_at DESC LIMIT ?`)
      .all(...params) as Array<Record<string, unknown>>;

    return rows.map((row) => ({
      id: row.id as number,
      agentType: row.agent_type as string,
      technique: row.technique as string,
      category: (row.category as string | null) ?? null,
      successRate: (row.success_rate as number | null) ?? null,
      engagementCount: row.engagement_count as number,
      insight: row.insight as string,
      evidenceSummary: (row.evidence_summary as string | null) ?? null,
      confidence: row.confidence as number,
      createdAt: row.created_at as string,
      updatedAt: row.updated_at as string,
    }));
  }

  // ─── Stats ────────────────────────────────────────────

  getStats(): Record<string, number> {
    const stats: Record<string, number> = {};
    for (const [table, stmt] of this.stmtCountTable) {
      const row = stmt.get() as { count: number };
      stats[table] = row.count;
    }
    return stats;
  }

  // ─── Lifecycle ────────────────────────────────────────

  close(): void {
    this.db.close();
  }

  // ─── Internal helpers ─────────────────────────────────

  private logEvent(eventType: string, data: Record<string, unknown>): void {
    this.stmtInsertEvent.run(new Date().toISOString(), eventType, JSON.stringify(data));
  }

  private rowToScan(row: Record<string, unknown>): ScanResult {
    return {
      scanId: row.scan_id as string,
      target: row.target as string,
      startedAt: row.started_at as string,
      completedAt: row.completed_at as string,
      findings: JSON.parse(row.findings as string),
      summary: JSON.parse(row.summary as string),
      memo: row.memo ? JSON.parse(row.memo as string) : undefined,
    };
  }

  private rowToCampaign(row: Record<string, unknown>): PersistedCampaignResult {
    return {
      campaignId: row.campaign_id as string,
      config: JSON.parse(row.config as string),
      target: JSON.parse(row.target as string),
      findings: JSON.parse(row.findings as string),
      startedAt: row.started_at as string,
      finishedAt: (row.finished_at as string | null) ?? null,
    };
  }

  private rowToChain(row: Record<string, unknown>): PersistedProbeChain {
    return {
      chainId: row.chain_id as string,
      profileId: (row.profile_id as string | null) ?? null,
      name: row.name as string,
      capabilities: JSON.parse(row.capabilities as string),
      steps: JSON.parse(row.steps as string),
      severity: row.severity as string,
      category: row.category as string,
      owasp: row.owasp as string,
      createdAt: row.created_at as string,
    };
  }
}
