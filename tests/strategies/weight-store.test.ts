import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { FileWeightStore } from '../../src/strategies/weight-store.js';

describe('FileWeightStore', () => {
  let tmpDir: string;
  let filePath: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'keelson-weights-'));
    filePath = path.join(tmpDir, 'weights.json');
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('returns 0 weight for unknown intent', async () => {
    const store = new FileWeightStore(filePath);
    await store.load();
    expect(store.getWeight('GA-001', 'early_session')).toBe(0);
  });

  it('records outcomes and computes success rate', async () => {
    const store = new FileWeightStore(filePath);
    await store.load();

    store.recordOutcome('GA-001', 'early_session', true);
    store.recordOutcome('GA-001', 'early_session', true);
    store.recordOutcome('GA-001', 'early_session', false);

    // 3 attempts needed before weight is returned
    expect(store.getWeight('GA-001', 'early_session')).toBeCloseTo(0.667, 2);
  });

  it('persists and reloads from disk', async () => {
    const store1 = new FileWeightStore(filePath);
    await store1.load();
    store1.recordOutcome('GA-001', 'post_disclosure', true);
    store1.recordOutcome('GA-001', 'post_disclosure', true);
    store1.recordOutcome('GA-001', 'post_disclosure', true);
    await store1.flush();

    const store2 = new FileWeightStore(filePath);
    await store2.load();
    expect(store2.getWeight('GA-001', 'post_disclosure')).toBe(1.0);
  });

  it('handles missing file on load gracefully', async () => {
    const store = new FileWeightStore(path.join(tmpDir, 'nonexistent.json'));
    await store.load();
    expect(store.getWeight('GA-001', 'early_session')).toBe(0);
  });

  it('applies weight decay to entries older than 30 days', async () => {
    const store = new FileWeightStore(filePath);
    await store.load();

    // Create 4 attempts (above threshold)
    store.recordOutcome('GA-001', 'early_session', true);
    store.recordOutcome('GA-001', 'early_session', true);
    store.recordOutcome('GA-001', 'early_session', true);
    store.recordOutcome('GA-001', 'early_session', true);
    await store.flush();

    // Tamper with the file to set lastUpdated 31 days ago
    const data = JSON.parse(await fs.readFile(filePath, 'utf-8'));
    const oldDate = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString();
    for (const entry of data) {
      entry.lastUpdated = oldDate;
    }
    await fs.writeFile(filePath, JSON.stringify(data));

    const store2 = new FileWeightStore(filePath);
    await store2.load();
    // After decay: attempts halved (4 → 2), successes halved (4 → 2), but below threshold of 3
    expect(store2.getWeight('GA-001', 'early_session')).toBe(0);
  });

  it('tracks separate buckets independently', async () => {
    const store = new FileWeightStore(filePath);
    await store.load();

    store.recordOutcome('GA-001', 'early_session', true);
    store.recordOutcome('GA-001', 'early_session', true);
    store.recordOutcome('GA-001', 'early_session', true);
    store.recordOutcome('GA-001', 'post_refusal', false);
    store.recordOutcome('GA-001', 'post_refusal', false);
    store.recordOutcome('GA-001', 'post_refusal', false);

    expect(store.getWeight('GA-001', 'early_session')).toBe(1.0);
    expect(store.getWeight('GA-001', 'post_refusal')).toBe(0);
  });

  it('returns 0 for entries with fewer than 3 attempts', async () => {
    const store = new FileWeightStore(filePath);
    await store.load();

    store.recordOutcome('GA-001', 'early_session', true);
    store.recordOutcome('GA-001', 'early_session', true);

    expect(store.getWeight('GA-001', 'early_session')).toBe(0);
  });

  it('returns weight at exactly 3 attempts (threshold boundary)', async () => {
    const store = new FileWeightStore(filePath);
    await store.load();

    store.recordOutcome('GA-001', 'early_session', true);
    store.recordOutcome('GA-001', 'early_session', false);
    store.recordOutcome('GA-001', 'early_session', true);

    // Exactly 3 attempts — should return weight (not 0)
    expect(store.getWeight('GA-001', 'early_session')).toBeCloseTo(0.667, 2);
  });

  it('handles corrupted JSON file gracefully', async () => {
    await fs.writeFile(filePath, 'not valid json {{{');
    const store = new FileWeightStore(filePath);
    await store.load();
    expect(store.getWeight('GA-001', 'early_session')).toBe(0);
  });

  it('persists decay on load so crash-reload does not re-decay', async () => {
    const store = new FileWeightStore(filePath);
    await store.load();

    // Create 8 attempts
    for (let i = 0; i < 8; i++) {
      store.recordOutcome('GA-001', 'early_session', true);
    }
    await store.flush();

    // Tamper with file to set lastUpdated 31 days ago
    const data = JSON.parse(await fs.readFile(filePath, 'utf-8'));
    const oldDate = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString();
    for (const entry of data) {
      entry.lastUpdated = oldDate;
    }
    await fs.writeFile(filePath, JSON.stringify(data));

    // First load: decay fires (8 → 4), and should flush to disk
    const store2 = new FileWeightStore(filePath);
    await store2.load();

    // Second load: should NOT re-decay because lastUpdated was persisted
    const store3 = new FileWeightStore(filePath);
    await store3.load();

    // If decay re-applied, attempts would be 2 (below threshold → 0).
    // With fix, attempts stays at 4 → weight should be non-zero.
    expect(store3.getWeight('GA-001', 'early_session')).toBe(1.0);
  });

  it('creates directory when flushing to new path', async () => {
    const deepPath = path.join(tmpDir, 'nested', 'dir', 'weights.json');
    const store = new FileWeightStore(deepPath);
    await store.load();
    store.recordOutcome('GA-001', 'early_session', true);
    await store.flush();

    const content = await fs.readFile(deepPath, 'utf-8');
    expect(JSON.parse(content)).toHaveLength(1);
  });
});
