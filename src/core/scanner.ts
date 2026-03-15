import PQueue from 'p-queue';

import { harvestLeakedInfo, selectCrossfeedProbes, selectLeakageTargetedProbes } from './convergence.js';
import type { LeakedInfo } from './convergence.js';
import { EngagementController, loadEngagementProfile } from './engagement.js';
import type { EngagementCallbacks } from './engagement.js';
import { executeProbe } from './engine.js';
import type { Observer } from './engine.js';
import { scannerLogger } from './logger.js';
import { MemoTable } from './memo.js';
import { errorFinding, sanitizeErrorMessage } from './scan-helpers.js';
import { summarize } from './summarize.js';
import { loadProbes } from './templates.js';
import type { Adapter, EngagementProfile, Finding, ProbeTemplate, ScanResult } from '../types/index.js';
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
  /** Engagement profile ID or path. When set, probes are executed through the engagement controller. */
  engagement?: string;
  /** Pre-loaded engagement profile (takes precedence over engagement string). */
  engagementProfile?: EngagementProfile;
  /** When true and a judge is provided, refused probes are retried with reframed prompts. */
  reframeOnRefusal?: boolean;
  /** When true and a judge is provided, follow-up turns are generated dynamically based on responses. */
  adaptiveFollowUp?: boolean;
  /** Maximum adaptive follow-up turns per probe (default: 6). */
  maxAdaptiveTurns?: number;
  onFinding?: (finding: Finding, current: number, total: number) => void;
  /** Maximum convergence passes. When > 1, runs cross-category follow-up passes
   *  based on vulnerabilities found and leaked information harvested. Default: 1. */
  maxPasses?: number;
  /** Callback fired at the start/end of each convergence pass. */
  onPass?: (passNumber: number, description: string) => void;
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
        reframeOnRefusal: options.reframeOnRefusal,
        adaptiveFollowUp: options.adaptiveFollowUp,
        maxAdaptiveTurns: options.maxAdaptiveTurns,
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
          reframeOnRefusal: options.reframeOnRefusal,
          adaptiveFollowUp: options.adaptiveFollowUp,
          maxAdaptiveTurns: options.maxAdaptiveTurns,
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

const MAX_LEAKED_INFO = 200;

interface FollowUpContext {
  allProbes: ProbeTemplate[];
  adapter: Adapter;
  memo: MemoTable;
  options: ScanOptions;
  concurrency: number;
}

async function runFollowUpPasses(
  allFindings: Finding[],
  executedIds: Set<string>,
  maxPasses: number,
  ctx: FollowUpContext,
): Promise<void> {
  let leakedInfo: LeakedInfo[] = harvestLeakedInfo(allFindings);
  const vulnCount = allFindings.filter((f) => f.verdict === Verdict.Vulnerable).length;
  ctx.options.onPass?.(1, `Pass 1 complete: ${vulnCount} vulnerabilities, ${leakedInfo.length} leaked items`);

  for (let passNum = 2; passNum <= maxPasses; passNum++) {
    const vulnFindings = allFindings.filter((f) => f.verdict === Verdict.Vulnerable);
    if (vulnFindings.length === 0 && leakedInfo.length === 0) {
      ctx.options.onPass?.(passNum, 'Converged: no vulnerabilities or leakage to follow up');
      break;
    }

    const crossfeed = selectCrossfeedProbes(vulnFindings, ctx.allProbes, executedIds);
    const leakageTargeted = selectLeakageTargetedProbes(leakedInfo, ctx.allProbes, executedIds);

    const nextMap = new Map<string, ProbeTemplate>();
    for (const t of crossfeed) nextMap.set(t.id, t);
    for (const t of leakageTargeted) nextMap.set(t.id, t);
    const nextProbes = [...nextMap.values()];

    if (nextProbes.length === 0) {
      ctx.options.onPass?.(passNum, 'Converged: no new probes to run');
      break;
    }

    ctx.options.onPass?.(
      passNum,
      `Cross-feed pass: ${crossfeed.length} category-related + ${leakageTargeted.length} leakage-targeted = ${nextProbes.length} probes`,
    );

    const passFindings =
      ctx.concurrency <= 1
        ? await executeSequential(nextProbes, ctx.adapter, ctx.memo, ctx.options)
        : await executeConcurrent(nextProbes, ctx.adapter, ctx.memo, ctx.options, ctx.concurrency);

    allFindings.push(...passFindings);
    for (const f of passFindings) executedIds.add(f.probeId);

    // Harvest new leaked info (capped to prevent unbounded growth)
    const newLeaked = harvestLeakedInfo(passFindings);
    const existingContent = new Set(leakedInfo.map((l) => l.content));
    const genuinelyNew = newLeaked.filter((l) => !existingContent.has(l.content));
    const remaining = MAX_LEAKED_INFO - leakedInfo.length;
    leakedInfo = [...leakedInfo, ...genuinelyNew.slice(0, Math.max(0, remaining))];

    const newVulns = passFindings.filter((f) => f.verdict === Verdict.Vulnerable).length;
    ctx.options.onPass?.(
      passNum,
      `Pass ${passNum} complete: ${newVulns} new vulnerabilities, ${genuinelyNew.length} new leaked items`,
    );

    if (newVulns === 0 && genuinelyNew.length === 0) {
      ctx.options.onPass?.(passNum, 'Converged: no new findings in this pass');
      break;
    }
  }
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

  // Resolve engagement profile
  const engagementProfile =
    options.engagementProfile ?? (options.engagement ? await loadEngagementProfile(options.engagement) : undefined);

  if (engagementProfile) {
    // Execute through engagement controller (always sequential)
    const controller = new EngagementController(engagementProfile, adapter);
    const engagementCallbacks: EngagementCallbacks = {
      onSessionStart: (idx, total) =>
        scannerLogger.debug({ sessionIdx: idx, totalSessions: total }, 'Engagement session start'),
      onSuspicion: (pattern, action) => scannerLogger.info({ pattern, action }, 'Suspicion signal detected'),
      onFinding: (finding, current, total) => {
        memo.record(finding);
        options.onFinding?.(finding, current, total);
      },
    };

    const executed = await controller.run(
      probes,
      (probe) =>
        executeProbe(probe, adapter, {
          delayMs: options.delayMs,
          judge: options.judge,
          observer: options.observer,
          reframeOnRefusal: options.reframeOnRefusal,
          adaptiveFollowUp: options.adaptiveFollowUp,
          maxAdaptiveTurns: options.maxAdaptiveTurns,
        }),
      engagementCallbacks,
    );

    const findings = [...executed, ...skippedFindings];
    const executedIds = new Set(findings.map((f) => f.probeId));

    const maxPasses = options.maxPasses ?? 1;
    if (maxPasses > 1) {
      await runFollowUpPasses(findings, executedIds, maxPasses, {
        allProbes,
        adapter,
        memo,
        options,
        concurrency: options.concurrency ?? 1,
      });
    }

    return {
      scanId: generateScanId(),
      target,
      startedAt,
      completedAt: new Date().toISOString(),
      findings,
      summary: summarize(findings),
      memo: memo.entries,
      cumulativeDisclosure: memo.cumulativeDisclosure(),
    };
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

  const allFindings: Finding[] = [...executed, ...skippedFindings];
  const executedIds = new Set(allFindings.map((f) => f.probeId));

  const maxPasses = options.maxPasses ?? 1;
  if (maxPasses > 1) {
    await runFollowUpPasses(allFindings, executedIds, maxPasses, {
      allProbes,
      adapter,
      memo,
      options,
      concurrency,
    });
  }

  return {
    scanId: generateScanId(),
    target,
    startedAt,
    completedAt: new Date().toISOString(),
    findings: allFindings,
    summary: summarize(allFindings),
    memo: memo.entries,
    cumulativeDisclosure: memo.cumulativeDisclosure(),
  };
}
