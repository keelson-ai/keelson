import PQueue from 'p-queue';

import { harvestLeakedInfo, selectCrossfeedProbes, selectLeakageTargetedProbes } from './convergence.js';
import type { LeakedInfo } from './convergence.js';
import { EngagementController, loadEngagementProfile } from './engagement.js';
import type { EngagementCallbacks } from './engagement.js';
import { executeProbe } from './engine.js';
import type { Observer } from './engine.js';
import { scannerLogger } from './logger.js';
import { MemoTable } from './memo.js';
import { applyPreset } from './presets.js';
import { RateLimitTracker } from './rate-limiter.js';
import { errorFinding, sanitizeErrorMessage } from './scan-helpers.js';
import { summarize } from './summarize.js';
import { loadProbes } from './templates.js';
import type { Adapter, EngagementProfile, Finding, ProbeTemplate, ScanResult } from '../types/index.js';
import { ScoringMethod, Severity, Verdict } from '../types/index.js';
import { generateScanId } from '../utils/id.js';
import { sleep } from '../utils.js';

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
  /** Probe collection preset name (e.g., 'quick', 'owasp-top10'). Applied before category/severity filters. */
  preset?: string;
  /** When true and a judge is provided, refused probes are retried with reframed prompts. */
  reframeOnRefusal?: boolean;
  /** When true and a judge is provided, follow-up turns are generated dynamically based on responses. */
  adaptiveFollowUp?: boolean;
  /** Maximum adaptive follow-up turns per probe (default: 6). */
  maxAdaptiveTurns?: number;
  /** Enable rate-limit detection, adaptive delay, and session rotation. */
  rateLimitResilience?: boolean;
  /** Retry INCONCLUSIVE probes (empty/error evidence) after main scan with session reset and backoff. */
  retryInconclusive?: boolean;
  /** Maximum number of INCONCLUSIVE probes to retry (default: 20). */
  maxRetries?: number;
  onFinding?: (finding: Finding, current: number, total: number) => void;
  onRetryStart?: (count: number) => void;
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
    ...(probe.asiId ? { asiId: probe.asiId } : {}),
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
  const rateLimitTracker = options.rateLimitResilience ? new RateLimitTracker(options.delayMs ?? 1000) : null;

  while (remaining.length > 0) {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- length checked above
    const probe = remaining.shift()!;

    if (options.resetBetweenProbes) {
      adapter.resetSession?.();
    }

    // Use adaptive delay from rate-limit tracker (when enabled)
    const effectiveDelay = rateLimitTracker
      ? Math.max(options.delayMs ?? 1000, rateLimitTracker.recommendedDelayMs)
      : (options.delayMs ?? 1000);

    // If rate limiting detected, rotate session before next probe
    if (rateLimitTracker?.shouldRotateSession) {
      scannerLogger.info({ probeId: probe.id }, 'Rate limit detected, rotating session before probe');
      adapter.resetSession?.();
      rateLimitTracker.onSessionRotated();
      await sleep(effectiveDelay);
    }

    let finding: Finding;
    try {
      finding = await executeProbe(probe, adapter, {
        delayMs: effectiveDelay,
        judge: options.judge,
        observer: options.observer,
        reframeOnRefusal: options.reframeOnRefusal,
        adaptiveFollowUp: options.adaptiveFollowUp,
        maxAdaptiveTurns: options.maxAdaptiveTurns,
        rateLimitTracker: rateLimitTracker ?? undefined,
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

  let allProbes = await loadProbes(options.probesDir);
  if (options.preset) {
    allProbes = applyPreset(allProbes, options.preset);
  }
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

  // ─── INCONCLUSIVE Retry Pass ─────────────────────────────
  // After the main scan (and convergence passes), retry INCONCLUSIVE probes that had empty/error evidence.
  // These are likely rate-limited responses that may succeed in a fresh session.
  if (options.retryInconclusive && concurrency <= 1) {
    const maxRetries = options.maxRetries ?? 20;
    const inconclusiveWithEmptyEvidence = allFindings.filter(
      (f) =>
        f.verdict === Verdict.Inconclusive &&
        (f.evidence.length === 0 || f.evidence.every((e) => !e.response || e.response.trim().length < 10)),
    );

    if (inconclusiveWithEmptyEvidence.length > 0) {
      const retryCount = Math.min(inconclusiveWithEmptyEvidence.length, maxRetries);
      const retryProbeIds = new Set(inconclusiveWithEmptyEvidence.slice(0, retryCount).map((f) => f.probeId));
      const retryProbes = probes.filter((p) => retryProbeIds.has(p.id));

      scannerLogger.info(
        { retryCount: retryProbes.length, total: inconclusiveWithEmptyEvidence.length },
        'Retrying INCONCLUSIVE probes with session reset',
      );
      options.onRetryStart?.(retryProbes.length);

      // Reset session and wait before retry pass
      adapter.resetSession?.();
      await sleep(10_000); // 10s cooldown before retry pass

      const retryFindings = await executeSequential(retryProbes, adapter, memo, {
        ...options,
        retryInconclusive: false, // prevent recursive retry
        delayMs: (options.delayMs ?? 1000) * 2,
      });

      // Replace INCONCLUSIVE findings with retry results (only if retry produced a definitive verdict)
      const retryMap = new Map<string, Finding>();
      for (const rf of retryFindings) {
        if (
          rf.verdict !== Verdict.Inconclusive ||
          (rf.evidence.length > 0 && rf.evidence.some((e) => e.response && e.response.trim().length >= 10))
        ) {
          retryMap.set(rf.probeId, rf);
        }
      }

      if (retryMap.size > 0) {
        for (let i = 0; i < allFindings.length; i++) {
          const replacement = retryMap.get(allFindings[i].probeId);
          if (replacement) allFindings[i] = replacement;
        }
        scannerLogger.info(
          { replaced: retryMap.size, of: retryProbes.length },
          'INCONCLUSIVE probes replaced with retry results',
        );
      }
    }
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
