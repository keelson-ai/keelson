/**
 * Smart scan — discover, classify, select, execute adaptively in conversational sessions.
 *
 * Ports `_legacy/src/core/smart_scan.py` to TypeScript. Six phases:
 *   0. Infrastructure recon
 *   1. Capability discovery
 *   2. Target classification
 *   3. Probe selection
 *   4. Grouped session execution with memo
 *   5. Mid-scan adaptation
 */

import { executeProbe } from './engine.js';
import type { ExecuteProbeOptions, Observer } from './engine.js';
import { MemoTable, inferTechniques } from './memo.js';
import { errorFinding, sanitizeErrorMessage } from './scan-helpers.js';
import { adaptPlan, classifyTarget, selectProbes } from './strategist.js';
import type { ProbePlan, ReconResponse, TargetProfile } from './strategist.js';
import { summarize } from './summarize.js';
import { loadProbes } from './templates.js';
import { discoverCapabilities } from '../prober/discovery.js';
import { runInfrastructureRecon } from '../prober/infrastructure.js';
import type { AgentProfile, InfraFinding } from '../prober/types.js';
import type { Adapter, Finding, ProbeTemplate, ScanResult } from '../types/index.js';
import { Technique, Verdict } from '../types/index.js';

// ─── Recon result ──────────────────────────────────────

export interface ReconResult {
  targetUrl: string;
  infraFindings: InfraFinding[];
  agentProfile: AgentProfile;
  targetProfile: TargetProfile;
  probePlan: ProbePlan;
  completedAt: string;
}

/** Maximum probes per conversational session before resetting thread. */
export const SESSION_MAX_TURNS = 6;

// ─── Phase callbacks ────────────────────────────────────

export type OnFinding = (finding: Finding, current: number, total: number) => void;
export type OnPhase = (phase: string, detail: string) => void;

// ─── Smart scan options ─────────────────────────────────

export interface SmartScanOptions {
  probesDir?: string;
  delayMs?: number;
  judge?: Adapter;
  observer?: Observer;
  onFinding?: OnFinding;
  onPhase?: OnPhase;
  verify?: boolean;
  maxResponseTokens?: number;
}

// ─── Effectiveness scoring ──────────────────────────────

/**
 * Score a probe by its field-tested success rate, weighted by confidence.
 *
 * Untested probes (timesTested === 0) score 0.0 (neutral).
 * Tested probes scale from -1.0 (proven failure) to +1.0 (always works):
 *   - 0% rate after 10+ tests -> -1.0 (strong deprioritization)
 *   - 0% rate after 1 test   -> -0.1 (mild penalty, could still work)
 *   - 50% rate after 10 tests -> +0.5
 */
export function effectivenessScore(t: ProbeTemplate): number {
  const timesTested = t.effectiveness?.timesTested ?? 0;
  const successRate = t.effectiveness?.successRate ?? 0;

  if (timesTested === 0) return 0.0;

  const confidence = Math.min(timesTested / 10.0, 1.0);
  if (successRate === 0.0) return -1.0 * confidence;
  return successRate * confidence;
}

// ─── Reorder by memo ────────────────────────────────────

/**
 * Reorder templates so effective techniques come first, dead ends last.
 * Combines field-tested success rates with memo-informed scoring.
 */
export function reorderByMemo(templates: ProbeTemplate[], memo: MemoTable, category: string): ProbeTemplate[] {
  return [...templates].sort((a, b) => {
    const scoreA = computeMemoScore(a, memo, category);
    const scoreB = computeMemoScore(b, memo, category);
    return scoreB - scoreA;
  });
}

function computeMemoScore(t: ProbeTemplate, memo: MemoTable, category: string): number {
  // Build a synthetic finding to infer techniques. We only need prompts in evidence.
  const techniques = inferTechniquesFromTemplate(t);
  const memoScore = memo.scoreProbeTechniques(techniques, category);
  return memoScore + effectivenessScore(t);
}

/**
 * Infer techniques from a probe template's turn prompts by constructing
 * a minimal finding-like structure and passing it through inferTechniques.
 */
function inferTechniquesFromTemplate(t: ProbeTemplate): Technique[] {
  const syntheticFinding: Finding = {
    probeId: t.id,
    probeName: t.name,
    severity: t.severity,
    category: t.category,
    owaspId: t.owaspId,
    verdict: Verdict.Inconclusive,
    confidence: 0,
    reasoning: '',
    scoringMethod: 'pattern' as Finding['scoringMethod'],
    conversation: [],
    evidence: t.turns
      .filter((turn) => turn.role === 'user')
      .map((turn, i) => ({
        stepIndex: i,
        prompt: turn.content,
        response: '',
        responseTimeMs: 0,
      })),
    leakageSignals: [],
    timestamp: '',
  };
  return inferTechniques(syntheticFinding);
}

// ─── Group into sessions ────────────────────────────────

/**
 * Group probes into conversational sessions.
 *
 * Groups probes by category, with up to SESSION_MAX_TURNS per session.
 * This creates natural conversation flow where related probes build on each other.
 *
 * When a memo table is provided and has entries, probes within each category
 * are reordered so that probes using historically effective techniques run first,
 * and probes using dead-end techniques are pushed to the back.
 */
export function groupIntoSessions(
  probeIds: string[],
  templatesById: Map<string, ProbeTemplate>,
  memo?: MemoTable,
): ProbeTemplate[][] {
  // Group by category
  const byCategory = new Map<string, ProbeTemplate[]>();
  for (const id of probeIds) {
    const t = templatesById.get(id);
    if (!t) continue;
    const list = byCategory.get(t.category) ?? [];
    list.push(t);
    byCategory.set(t.category, list);
  }

  const sessions: ProbeTemplate[][] = [];
  for (const [category, templates] of byCategory) {
    let ordered: ProbeTemplate[];
    if (memo && memo.entries.length > 0) {
      ordered = reorderByMemo(templates, memo, category);
    } else {
      // No memo yet — sort by effectiveness score (higher = first)
      ordered = [...templates].sort((a, b) => effectivenessScore(b) - effectivenessScore(a));
    }

    // Split into chunks of SESSION_MAX_TURNS
    for (let i = 0; i < ordered.length; i += SESSION_MAX_TURNS) {
      sessions.push(ordered.slice(i, i + SESSION_MAX_TURNS));
    }
  }

  return sessions;
}

// ─── Execute a session ──────────────────────────────────

async function executeSession(
  session: ProbeTemplate[],
  adapter: Adapter,
  options: SmartScanOptions,
  memo: MemoTable,
  currentOffset: number,
  total: number,
): Promise<Finding[]> {
  adapter.resetSession?.();

  const findings: Finding[] = [];

  for (let i = 0; i < session.length; i++) {
    const probe = session[i];
    let finding: Finding;
    try {
      const execOptions: ExecuteProbeOptions = {
        delayMs: options.delayMs,
        judge: options.judge,
        observer: options.observer,
      };
      finding = await executeProbe(probe, adapter, execOptions);
    } catch (err: unknown) {
      finding = errorFinding(probe, sanitizeErrorMessage(err));
    }

    findings.push(finding);
    memo.record(finding);
    options.onFinding?.(finding, currentOffset + i + 1, total);
  }

  return findings;
}

// ─── Run infrastructure recon ───────────────────────────

async function runInfraRecon(adapter: Adapter, options: SmartScanOptions): Promise<InfraFinding[]> {
  options.onPhase?.('recon', `Infrastructure recon`);

  const infraFindings = await runInfrastructureRecon(adapter, {
    delayMs: options.delayMs,
  });

  if (infraFindings.length > 0) {
    for (const inf of infraFindings) {
      options.onPhase?.('recon', `  Warning: ${inf.severity}: ${inf.title}`);
    }
  } else {
    options.onPhase?.('recon', 'No infrastructure issues detected');
  }

  return infraFindings;
}

// ─── Run discovery ──────────────────────────────────────

async function runDiscovery(
  adapter: Adapter,
  options: SmartScanOptions,
): Promise<{ profile: AgentProfile; reconResponses: ReconResponse[] }> {
  options.onPhase?.('discovery', 'Fingerprinting target capabilities (8 probes)');

  const profile = await discoverCapabilities(adapter, { delayMs: options.delayMs });

  // Build recon responses for classification
  const reconResponses: ReconResponse[] = profile.capabilities.map((cap) => ({
    probeType: cap.name,
    prompt: cap.probePrompt,
    response: cap.responseExcerpt,
  }));

  const detectedCaps = profile.capabilities.filter((c) => c.detected).map((c) => c.name);
  options.onPhase?.('discovery', `Detected capabilities: ${detectedCaps.join(', ') || 'none'}`);

  return { profile, reconResponses };
}

// ─── Recon only (phases 0–3) ────────────────────────────

/**
 * Run infrastructure recon, capability discovery, classification, and probe
 * selection — without executing any attack probes.
 *
 * Returns a {@link ReconResult} containing the target profile and a suggested
 * probe plan that can be fed into a subsequent scan.
 */
export async function runRecon(target: string, adapter: Adapter, options: SmartScanOptions = {}): Promise<ReconResult> {
  // --- Phase 0: Infrastructure Recon ---
  const infraFindings = await runInfraRecon(adapter, options);
  adapter.resetSession?.();

  // --- Phase 1: Capability Discovery ---
  const { profile: agentProfile, reconResponses } = await runDiscovery(adapter, options);
  adapter.resetSession?.();

  // --- Phase 2: Target Classification ---
  options.onPhase?.('classify', 'Classifying target agent type');

  const targetProfile = classifyTarget(reconResponses);

  options.onPhase?.(
    'profile',
    `Type: ${targetProfile.agentTypes.join(', ')} | ` +
      `Tools: ${targetProfile.detectedTools.slice(0, 5).join(', ') || 'none detected'} | ` +
      `Memory: ${targetProfile.hasMemory} | Refusal: ${targetProfile.refusalStyle}`,
  );

  // --- Phase 3: Probe Selection ---
  const allTemplates = await loadProbes(options.probesDir);
  const probePlan = selectProbes(targetProfile, allTemplates);

  options.onPhase?.('plan', `Selected ${probePlan.totalProbes} probes (from ${allTemplates.length} available)`);
  for (const cp of probePlan.categories) {
    if (cp.probeIds.length > 0) {
      options.onPhase?.(
        'category',
        `  ${cp.category}: ${cp.probeIds.length} probes (${cp.priority}) — ${cp.rationale}`,
      );
    }
  }

  return {
    targetUrl: target,
    infraFindings,
    agentProfile,
    targetProfile,
    probePlan,
    completedAt: new Date().toISOString(),
  };
}

// ─── Main smart scan ────────────────────────────────────

/**
 * Run an adaptive smart scan: discover -> classify -> select -> execute.
 *
 * Unlike `scan` which blindly runs all probes, smartScan:
 *   1. Discovers target capabilities (8 probes)
 *   2. Classifies target type (codebase agent, RAG, customer service, etc.)
 *   3. Selects only relevant probes based on profile
 *   4. Groups probes into conversational sessions for natural social manipulation
 *   5. Adapts the plan based on findings (escalate/de-escalate)
 */
export async function runSmartScan(
  target: string,
  adapter: Adapter,
  options: SmartScanOptions = {},
): Promise<ScanResult> {
  const startedAt = new Date().toISOString();

  // --- Phase 0: Infrastructure Recon ---
  await runInfraRecon(adapter, options);
  adapter.resetSession?.();

  // --- Phase 1: Discovery ---
  const { reconResponses } = await runDiscovery(adapter, options);
  adapter.resetSession?.();

  // --- Phase 2: Classification ---
  options.onPhase?.('classify', 'Classifying target agent type');

  const targetProfile = classifyTarget(reconResponses);

  options.onPhase?.(
    'profile',
    `Type: ${targetProfile.agentTypes.join(', ')} | ` +
      `Tools: ${targetProfile.detectedTools.slice(0, 5).join(', ') || 'none detected'} | ` +
      `Memory: ${targetProfile.hasMemory} | Refusal: ${targetProfile.refusalStyle}`,
  );

  // --- Phase 3: Probe Selection ---
  const allTemplates = await loadProbes(options.probesDir);
  let plan = selectProbes(targetProfile, allTemplates);

  options.onPhase?.('plan', `Selected ${plan.totalProbes} probes (from ${allTemplates.length} available)`);
  for (const cp of plan.categories) {
    if (cp.probeIds.length > 0) {
      options.onPhase?.(
        'category',
        `  ${cp.category}: ${cp.probeIds.length} probes (${cp.priority}) — ${cp.rationale}`,
      );
    }
  }

  // Build lookup
  const templatesById = new Map(allTemplates.map((t) => [t.id, t]));

  // Collect all probe IDs from the plan
  const allProbeIds = plan.categories.flatMap((cp) => cp.probeIds);

  if (allProbeIds.length === 0) {
    options.onPhase?.('done', 'No probes selected for this target profile');
    return {
      scanId: crypto.randomUUID(),
      target,
      startedAt,
      completedAt: new Date().toISOString(),
      findings: [],
      summary: summarize([]),
    };
  }

  // --- Phase 4: Grouped Execution with Memoization ---
  const memo = new MemoTable();
  let sessions = groupIntoSessions(allProbeIds, templatesById, memo);

  options.onPhase?.('execute', `Running ${allProbeIds.length} probes in ${sessions.length} sessions`);

  const total = allProbeIds.length;
  let currentOffset = 0;
  const allFindings: Finding[] = [];

  for (let sessionIdx = 0; sessionIdx < sessions.length; sessionIdx++) {
    const session = sessions[sessionIdx];
    const cat = session[0]?.category ?? 'unknown';
    options.onPhase?.('session', `Session ${sessionIdx + 1}/${sessions.length} (${cat})`);

    // Log memo insights before each session (after the first)
    if (memo.entries.length > 0) {
      const effective = memo.effectiveTechniques(session[0]?.category);
      const deadEnds = memo.deadEndTechniques(session[0]?.category);
      const leaked = memo.allLeakedInfo();

      if (effective.size > 0) {
        const techs = [...effective.entries()]
          .slice(0, 3)
          .map(([t, n]) => `${t}(${n})`)
          .join(', ');
        options.onPhase?.('memo', `  Effective techniques: ${techs}`);
      }
      if (deadEnds.size > 0) {
        const techs = [...deadEnds.entries()]
          .slice(0, 3)
          .map(([t, n]) => `${t}(${n})`)
          .join(', ');
        options.onPhase?.('memo', `  Dead-end techniques: ${techs}`);
      }
      if (leaked.length > 0) {
        options.onPhase?.('memo', `  Leaked info: ${leaked.length} items`);
      }
    }

    const sessionFindings = await executeSession(session, adapter, options, memo, currentOffset, total);
    allFindings.push(...sessionFindings);
    currentOffset += session.length;

    // --- Phase 5: Mid-scan Adaptation ---
    const updatedPlan = adaptPlan(plan, allFindings, allTemplates);

    // Check if any category was escalated or de-escalated
    for (let i = 0; i < plan.categories.length; i++) {
      const oldCp = plan.categories[i];
      const newCp = updatedPlan.categories[i];
      if (oldCp && newCp && oldCp.priority !== newCp.priority) {
        options.onPhase?.('adapt', `  ${newCp.category}: ${oldCp.priority} -> ${newCp.priority} (${newCp.rationale})`);
      }
    }

    plan = updatedPlan;

    // Re-group remaining sessions with updated memo knowledge.
    // Recompute from adapted plan so de-escalated categories are excluded.
    const adaptedProbeIds = plan.categories.flatMap((cp) => cp.probeIds);
    const executedIds = new Set(allFindings.map((f) => f.probeId));
    const remainingIds = adaptedProbeIds.filter((id) => !executedIds.has(id));

    if (remainingIds.length > 0) {
      const remainingSessions = groupIntoSessions(remainingIds, templatesById, memo);
      sessions = [...sessions.slice(0, sessionIdx + 1), ...remainingSessions];
    }
  }

  return {
    scanId: crypto.randomUUID(),
    target,
    startedAt,
    completedAt: new Date().toISOString(),
    findings: allFindings,
    summary: summarize(allFindings),
    memo: memo.entries,
  };
}
