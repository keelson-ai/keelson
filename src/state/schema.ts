/**
 * SQLite schema and default database path for the Keelson store.
 */

import { homedir } from 'node:os';
import { join } from 'node:path';

// ─── Default path ───────────────────────────────────────

export const DEFAULT_DB_PATH = join(homedir(), '.keelson', 'store.db');

// ─── SQL Schema ─────────────────────────────────────────

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS scans (
  scan_id TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  started_at TEXT NOT NULL,
  completed_at TEXT NOT NULL,
  findings TEXT NOT NULL,
  summary TEXT NOT NULL,
  memo TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);

CREATE TABLE IF NOT EXISTS campaigns (
  campaign_id TEXT PRIMARY KEY,
  config TEXT NOT NULL,
  target TEXT NOT NULL,
  findings TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_campaigns_started_at ON campaigns(started_at DESC);

CREATE TABLE IF NOT EXISTS agent_profiles (
  profile_id TEXT PRIMARY KEY,
  target_url TEXT NOT NULL,
  capabilities TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS baselines (
  scan_id TEXT PRIMARY KEY,
  label TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_baselines_created_at ON baselines(created_at DESC);

CREATE TABLE IF NOT EXISTS cache (
  cache_key TEXT PRIMARY KEY,
  messages TEXT NOT NULL,
  model TEXT NOT NULL,
  response_text TEXT NOT NULL,
  response_time_ms INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  hit_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS regression_alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_a_id TEXT NOT NULL,
  scan_b_id TEXT NOT NULL,
  template_id TEXT NOT NULL,
  alert_severity TEXT NOT NULL,
  change_type TEXT NOT NULL,
  description TEXT NOT NULL,
  created_at TEXT NOT NULL,
  acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON regression_alerts(created_at DESC);

CREATE TABLE IF NOT EXISTS probe_chains (
  chain_id TEXT PRIMARY KEY,
  profile_id TEXT,
  name TEXT NOT NULL,
  capabilities TEXT NOT NULL,
  steps TEXT NOT NULL,
  severity TEXT NOT NULL,
  category TEXT NOT NULL,
  owasp TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chains_profile ON probe_chains(profile_id);
CREATE INDEX IF NOT EXISTS idx_chains_created_at ON probe_chains(created_at DESC);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  event_type TEXT NOT NULL,
  data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
`;
