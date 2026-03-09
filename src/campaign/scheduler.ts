/**
 * Campaign scheduler -- foreground async loop with configurable timing.
 *
 * Ports _legacy/src/campaign/scheduler.py to TypeScript.
 */

import { runCampaign } from './runner.js';
import type { RunCampaignOptions } from './runner.js';
import type { Adapter, CampaignConfig, CampaignResult } from '../types/index.js';

// ─── Interval Parsing ───────────────────────────────────

const UNIT_MS: Record<string, number> = {
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
};

const INTERVAL_PATTERN = /(\d+)([smhd])/g;

/**
 * Parse a human-readable interval string into milliseconds.
 *
 * Supports: "30s", "5m", "1h", "2d", and compound forms like "2h30m".
 */
export function parseInterval(interval: string): number {
  const matches = [...interval.toLowerCase().matchAll(INTERVAL_PATTERN)];

  if (matches.length === 0) {
    throw new Error(
      `Invalid interval format: "${interval}". Use e.g. "30s", "5m", "1h", "2h30m", "1d".`,
    );
  }

  let totalMs = 0;
  for (const [, value, unit] of matches) {
    totalMs += Number(value) * UNIT_MS[unit];
  }

  return totalMs;
}

// ─── Scheduled Runner ───────────────────────────────────

export type OnCampaignCallback = (result: CampaignResult, runNumber: number) => void;

export interface ScheduledRunOptions extends RunCampaignOptions {
  /** Milliseconds between campaign runs. */
  intervalMs: number;
  /** Maximum number of runs. Omit or set undefined to run until aborted. */
  maxRuns?: number;
  /** AbortSignal for graceful shutdown. */
  signal?: AbortSignal;
  /** Called after each campaign completes. */
  onCampaign?: OnCampaignCallback;
}

/**
 * Run campaigns on a schedule.
 *
 * Executes `runCampaign` in a loop, sleeping `intervalMs` between runs.
 * Stops when `maxRuns` is reached or the `signal` is aborted.
 *
 * @returns All campaign results collected during the run.
 */
export async function runScheduled(
  target: string,
  adapter: Adapter,
  config: CampaignConfig,
  options: ScheduledRunOptions,
): Promise<CampaignResult[]> {
  const { intervalMs, maxRuns, signal, onCampaign, ...campaignOptions } = options;
  const results: CampaignResult[] = [];
  let runNumber = 0;

  while (maxRuns === undefined || runNumber < maxRuns) {
    if (signal?.aborted) break;

    runNumber++;
    const result = await runCampaign(target, adapter, config, campaignOptions);
    results.push(result);

    onCampaign?.(result, runNumber);

    if (maxRuns !== undefined && runNumber >= maxRuns) break;
    if (signal?.aborted) break;

    await delay(intervalMs, signal);
  }

  return results;
}

// ─── Helpers ────────────────────────────────────────────

/**
 * Promise-based delay that resolves after `ms` milliseconds or when the
 * AbortSignal fires, whichever comes first.
 */
function delay(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.resolve();

  return new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, ms);

    function onAbort(): void {
      clearTimeout(timer);
      cleanup();
      resolve();
    }

    function cleanup(): void {
      signal?.removeEventListener('abort', onAbort);
    }

    signal?.addEventListener('abort', onAbort, { once: true });
  });
}
