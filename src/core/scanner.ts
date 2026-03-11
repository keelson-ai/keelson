import PQueue from 'p-queue';

import { executeProbe } from './engine.js';
import type { Observer } from './engine.js';
import { scannerLogger } from './logger.js';
import { MemoTable } from './memo.js';
import { errorFinding, sanitizeErrorMessage } from './scan-helpers.js';
import { summarize } from './summarize.js';
import { loadProbes } from './templates.js';
import type { Adapter, Finding, ProbeTemplate, ScanResult } from '../types/index.js';
import { ScoringMethod, Severity, Verdict } from '../types/index.js';
import { generateScanId } from '../utils/id.js';

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
  /** Reset adapter session between probes (required for browser-based adapters). */
  resetBetweenProbes?: boolean;
  /** Skip probes whose total payload exceeds this character limit. */
  maxPayloadLength?: number;
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

function probePayloadLength(probe: ProbeTemplate): number {
  return probe.turns.reduce((sum, t) => sum + t.content.length, 0);
}

function skippedFinding(probe: ProbeTemplate, reason: string): Finding {
  return {
    probeId: probe.id,
    probeName: probe.name,
    severity: probe.severity,
    category: probe.category,
    owaspId: probe.owaspId,
    verdict: Verdict.Inconclusive,
    confidence: 0,
    reasoning: `Skipped: ${reason}`,
    scoringMethod: ScoringMethod.Pattern,
    conversation: [],
    evidence: [],
    leakageSignals: [],
    timestamp: new Date().toISOString(),
  };
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

    if (options.resetBetweenProbes) {
      adapter.resetSession?.();
    }

    let finding: Finding;
    try {
      finding = await executeProbe(probe, adapter, {
        delayMs: options.delayMs,
        judge: options.judge,
        observer: options.observer,
      });
    } catch (err: unknown) {
      finding = errorFinding(probe, sanitizeErrorMessage(err));
    }
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
  let completed = 0;

  const queue = new PQueue({ concurrency });

  const tasks = probes.map((probe, idx) =>
    queue.add(async () => {
      let finding: Finding;
      try {
        finding = await executeProbe(probe, adapter, {
          delayMs: options.delayMs,
          judge: options.judge,
          observer: options.observer,
        });
      } catch (err: unknown) {
        finding = errorFinding(probe, sanitizeErrorMessage(err));
      }
      findings[idx] = finding;
      memo.record(finding);
      completed++;
      options.onFinding?.(finding, completed, probes.length);
      scannerLogger.debug({ probeId: probe.id, verdict: finding.verdict, completed }, 'Scan probe complete');
    }),
  );

  await Promise.all(tasks);
  return findings;
}

export async function scan(target: string, adapter: Adapter, options: ScanOptions = {}): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const memo = new MemoTable();

  const allProbes = await loadProbes(options.probesDir);
  const filtered = filterProbes(allProbes, options.categories, options.severities);

  // Separate probes that exceed the payload size limit
  const skippedFindings: Finding[] = [];
  let probes: ProbeTemplate[];
  if (options.maxPayloadLength) {
    const max = options.maxPayloadLength;
    probes = [];
    for (const p of filtered) {
      const len = probePayloadLength(p);
      if (len > max) {
        skippedFindings.push(skippedFinding(p, `payload ${len} chars exceeds limit of ${max}`));
      } else {
        probes.push(p);
      }
    }
  } else {
    probes = filtered;
  }

  const concurrency = options.concurrency ?? 1;
  if (options.reorder && concurrency > 1) {
    throw new Error(
      'reorder option is not supported with concurrency > 1 (execution order is undefined in concurrent mode)',
    );
  }
  if (options.resetBetweenProbes && concurrency > 1) {
    throw new Error(
      'resetBetweenProbes is not supported with concurrency > 1 (browser session reset requires sequential execution)',
    );
  }
  const executed =
    concurrency <= 1
      ? await executeSequential(probes, adapter, memo, options)
      : await executeConcurrent(probes, adapter, memo, options, concurrency);

  const findings = [...executed, ...skippedFindings];

  return {
    scanId: generateScanId(),
    target,
    startedAt,
    completedAt: new Date().toISOString(),
    findings,
    summary: summarize(findings),
    memo: memo.entries,
  };
}
