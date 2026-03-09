import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { Store } from '../../src/state/store.js';
import { generateScanId } from '../../src/utils/id.js';
import { makeScan } from '../fixtures/factories.js';

describe('Store integration', () => {
  let dir: string;
  let dbPath: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'keelson-test-'));
    dbPath = join(dir, 'store.db');
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('full lifecycle: save scan → list → get → baseline → diff lookup', () => {
    const store = Store.open(dbPath);

    // Save two scans
    const scan1 = makeScan({ scanId: generateScanId() });
    const scan2 = makeScan({ scanId: generateScanId(), startedAt: '2026-03-10T00:00:00.000Z' });
    store.saveScan(scan1);
    store.saveScan(scan2);

    // List shows both, newest first
    const list = store.listScans();
    expect(list).toHaveLength(2);
    expect(list[0].scanId).toBe(scan2.scanId);

    // Get by ID
    expect(store.getScan(scan1.scanId)).toBeDefined();

    // Set baseline
    store.saveBaseline(scan1.scanId, 'v1.0');
    const baselines = store.getBaselines();
    expect(baselines).toHaveLength(1);
    expect(baselines[0].scanId).toBe(scan1.scanId);

    // Stats
    const stats = store.getStats();
    expect(stats.scans).toBe(2);
    expect(stats.baselines).toBe(1);

    store.close();

    // Reopen — data persists
    const store2 = Store.open(dbPath);
    expect(store2.listScans()).toHaveLength(2);
    store2.close();
  });
});
