import * as fs from 'node:fs/promises';
import * as path from 'node:path';

import type { ContextBucket, WeightEntry, WeightStore } from './types.js';
import { getErrorMessage } from '../utils.js';

const DECAY_THRESHOLD_DAYS = 30;

export class FileWeightStore implements WeightStore {
  private entries: WeightEntry[] = [];
  private readonly filePath: string;

  constructor(filePath: string) {
    this.filePath = filePath;
  }

  async load(): Promise<void> {
    try {
      const raw = await fs.readFile(this.filePath, 'utf-8');
      this.entries = JSON.parse(raw) as WeightEntry[];
      const decayed = this.applyDecay();
      if (decayed) await this.flush();
    } catch (err: unknown) {
      console.error(`[weight-store] load failed from ${this.filePath}: ${getErrorMessage(err)}`);
      this.entries = [];
    }
  }

  async save(): Promise<void> {
    await this.flush();
  }

  getWeight(intentId: string, bucket: ContextBucket): number {
    const entry = this.findEntry(intentId, bucket);
    if (!entry || entry.attempts < 3) return 0;
    return entry.successRate;
  }

  recordOutcome(intentId: string, bucket: ContextBucket, success: boolean): void {
    let entry = this.findEntry(intentId, bucket);
    if (!entry) {
      entry = {
        intentId,
        contextBucket: bucket,
        attempts: 0,
        successes: 0,
        successRate: 0,
        lastUpdated: new Date().toISOString(),
      };
      this.entries.push(entry);
    }
    entry.attempts++;
    if (success) entry.successes++;
    entry.successRate = entry.successes / entry.attempts;
    entry.lastUpdated = new Date().toISOString();
  }

  async flush(): Promise<void> {
    const dir = path.dirname(this.filePath);
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(this.filePath, JSON.stringify(this.entries, null, 2));
  }

  private findEntry(intentId: string, bucket: ContextBucket): WeightEntry | undefined {
    return this.entries.find((e) => e.intentId === intentId && e.contextBucket === bucket);
  }

  private applyDecay(): boolean {
    const now = Date.now();
    let changed = false;
    for (const entry of this.entries) {
      const age = now - new Date(entry.lastUpdated).getTime();
      const days = age / (24 * 60 * 60 * 1000);
      if (days > DECAY_THRESHOLD_DAYS) {
        entry.attempts = Math.max(1, Math.floor(entry.attempts / 2));
        entry.successes = Math.max(0, Math.floor(entry.successes / 2));
        entry.successRate = entry.attempts > 0 ? entry.successes / entry.attempts : 0;
        entry.lastUpdated = new Date().toISOString();
        changed = true;
      }
    }
    return changed;
  }
}
