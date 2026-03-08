import { executeProbe } from './engine.js';
import type { Observer } from './engine.js';
import { MemoTable } from './memo.js';
import { summarize } from './summarize.js';
import { loadProbes } from './templates.js';
import type { Adapter, Finding, ProbeTemplate, ScanResult } from '../types/index.js';
import { Severity, Verdict } from '../types/index.js';

const REORDER_INTERVAL = 10;

export interface ScanOptions {
  probesDir?: string;
  categories?: string[];
  severities?: Severity[];
  concurrency?: number;
  delayMs?: number;
  judge?: Adapter;
  observer?: Observer;
  reorder?: boolean;
  onFinding?: (finding: Finding, current: number, total: number) => void;
}

function filterProbes(probes: ProbeTemplate[], categories?: string[], severities?: Severity[]): ProbeTemplate[] {
  let filtered = probes;
  if (categories && categories.length > 0) {
    const set = new Set(categories.map((c) => c.toLowerCase()));
    filtered = filtered.filter((p) => set.has(p.category.toLowerCase()));
  }
  if (severities && severities.length > 0) {
    const set = new Set(severities);
    filtered = filtered.filter((p) => set.has(p.severity));
  }
  return filtered;
}

// Prioritize categories where vulnerabilities were already found
function prioritizeProbes(remaining: ProbeTemplate[], vulnCategories: Map<string, number>): ProbeTemplate[] {
  if (vulnCategories.size === 0) return remaining;
  return [...remaining].sort((a, b) => {
    const countA = vulnCategories.get(a.category) ?? 0;
    const countB = vulnCategories.get(b.category) ?? 0;
    if (countA !== countB) return countB - countA;
    return a.id.localeCompare(b.id);
  });
}

async function executeSequential(
  probes: ProbeTemplate[],
  adapter: Adapter,
  memo: MemoTable,
  options: ScanOptions,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const remaining = [...probes];
  const vulnCategories = new Map<string, number>();
  const total = remaining.length;

  while (remaining.length > 0) {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- length checked above
    const probe = remaining.shift()!;
    const finding = await executeProbe(probe, adapter, {
      delayMs: options.delayMs,
      judge: options.judge,
      observer: options.observer,
    });
    findings.push(finding);
    memo.record(finding);

    if (finding.verdict === Verdict.Vulnerable) {
      vulnCategories.set(finding.category, (vulnCategories.get(finding.category) ?? 0) + 1);
    }

    options.onFinding?.(finding, findings.length, total);

    // Reorder remaining probes periodically to prioritize vulnerable categories
    if (options.reorder && remaining.length > 0 && findings.length % REORDER_INTERVAL === 0) {
      const reordered = prioritizeProbes(remaining, vulnCategories);
      remaining.length = 0;
      remaining.push(...reordered);
    }
  }

  return findings;
}

async function executeConcurrent(
  probes: ProbeTemplate[],
  adapter: Adapter,
  memo: MemoTable,
  options: ScanOptions,
  concurrency: number,
): Promise<Finding[]> {
  const findings: Finding[] = new Array(probes.length);
  let nextIdx = 0;
  let completed = 0;

  async function worker(): Promise<void> {
    while (nextIdx < probes.length) {
      const idx = nextIdx++;
      const finding = await executeProbe(probes[idx], adapter, {
        delayMs: options.delayMs,
        judge: options.judge,
        observer: options.observer,
      });
      findings[idx] = finding;
      memo.record(finding);
      completed++;
      options.onFinding?.(finding, completed, probes.length);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, probes.length) }, () => worker());
  await Promise.all(workers);

  return findings;
}

export async function scan(target: string, adapter: Adapter, options: ScanOptions = {}): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const memo = new MemoTable();

  const allProbes = await loadProbes(options.probesDir);
  const probes = filterProbes(allProbes, options.categories, options.severities);

  const concurrency = options.concurrency ?? 1;
  if (options.reorder && concurrency > 1) {
    throw new Error(
      'reorder option is not supported with concurrency > 1 (execution order is undefined in concurrent mode)',
    );
  }
  const findings =
    concurrency <= 1
      ? await executeSequential(probes, adapter, memo, options)
      : await executeConcurrent(probes, adapter, memo, options, concurrency);

  return {
    scanId: crypto.randomUUID(),
    target,
    startedAt,
    completedAt: new Date().toISOString(),
    findings,
    summary: summarize(findings),
  };
}
