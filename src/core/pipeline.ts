/**
 * Parallel scan pipeline with checkpoint/resume.
 *
 * Orchestrates four phases:
 *   1. Discovery  -- load templates, discover capabilities, restore checkpoint
 *   2. Scanning   -- parallel probe execution with checkpoint persistence
 *   3. Verification -- re-probe VULNERABLE findings to confirm
 *   4. Reporting  -- assemble final ScanResult with summary
 */

import { mkdir, readFile, readdir, rename, stat, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { applyVerifiedFindings, executeParallel, verifyFindings } from './execution.js';
import { summarize } from './summarize.js';
import { loadProbes } from './templates.js';
import type {
  Adapter,
  EvidenceItem,
  Finding,
  LeakageSignal,
  ScanResult,
} from '../types/index.js';
import { ScoringMethod, Severity, Verdict } from '../types/index.js';

// ─── Constants ───────────────────────────────────────────

/** Checkpoint schema version -- increment when the checkpoint format changes. */
export const CHECKPOINT_VERSION = 2;

// ─── Interfaces ──────────────────────────────────────────

export interface PipelineConfig {
  /** Maximum concurrent probe executions. */
  maxConcurrent: number;
  /** Delay between requests in milliseconds. */
  delayMs: number;
  /** Directory to persist checkpoints. Null disables checkpointing. */
  checkpointDir: string | null;
  /** Whether to re-probe VULNERABLE findings for confirmation. */
  verifyVulnerabilities: boolean;
  /** Progress callback invoked after each finding. */
  onFinding?: (finding: Finding, current: number, total: number) => void;
}

export interface ScanCheckpointData {
  version: number;
  scanId: string;
  targetUrl: string;
  completedIds: string[];
  findingsJson: FindingJson[];
  startedAt: string;
  phase: string;
}

// ─── Defaults ────────────────────────────────────────────

export function defaultPipelineConfig(): PipelineConfig {
  return {
    maxConcurrent: 5,
    delayMs: 1500,
    checkpointDir: null,
    verifyVulnerabilities: true,
  };
}

// ─── Finding Serialization ──────────────────────────────

interface EvidenceJson {
  stepIndex: number;
  prompt: string;
  response: string;
  responseTimeMs: number;
}

interface LeakageSignalJson {
  stepIndex: number;
  signalType: string;
  severity: string;
  description: string;
  confidence: number;
}

interface FindingJson {
  probeId: string;
  probeName: string;
  verdict: string;
  severity: string;
  category: string;
  owaspId: string;
  reasoning: string;
  confidence: number;
  scoringMethod: string;
  timestamp: string;
  evidence: EvidenceJson[];
  leakageSignals: LeakageSignalJson[];
}

function findingToJson(finding: Finding): FindingJson {
  return {
    probeId: finding.probeId,
    probeName: finding.probeName,
    verdict: finding.verdict,
    severity: finding.severity,
    category: finding.category,
    owaspId: finding.owaspId,
    reasoning: finding.reasoning,
    confidence: finding.confidence,
    scoringMethod: finding.scoringMethod,
    timestamp: finding.timestamp,
    evidence: finding.evidence.map((e) => ({
      stepIndex: e.stepIndex,
      prompt: e.prompt,
      response: e.response,
      responseTimeMs: e.responseTimeMs,
    })),
    leakageSignals: finding.leakageSignals.map((s) => ({
      stepIndex: s.stepIndex,
      signalType: s.signalType,
      severity: s.severity,
      description: s.description,
      confidence: s.confidence,
    })),
  };
}

function findingFromJson(data: FindingJson): Finding {
  const evidence: EvidenceItem[] = data.evidence.map((e) => ({
    stepIndex: e.stepIndex,
    prompt: e.prompt,
    response: e.response,
    responseTimeMs: e.responseTimeMs,
  }));

  const leakageSignals: LeakageSignal[] = data.leakageSignals.map((s) => ({
    stepIndex: s.stepIndex,
    signalType: s.signalType,
    severity: s.severity,
    description: s.description,
    confidence: s.confidence,
  }));

  const verdictValue = Object.values(Verdict).includes(data.verdict as Verdict)
    ? (data.verdict as Verdict)
    : Verdict.Inconclusive;

  const severityValue = Object.values(Severity).includes(data.severity as Severity)
    ? (data.severity as Severity)
    : Severity.Medium;

  const scoringValue = Object.values(ScoringMethod).includes(data.scoringMethod as ScoringMethod)
    ? (data.scoringMethod as ScoringMethod)
    : ScoringMethod.Pattern;

  return {
    probeId: data.probeId ?? '',
    probeName: data.probeName ?? '',
    verdict: verdictValue,
    severity: severityValue,
    category: data.category ?? '',
    owaspId: data.owaspId ?? '',
    reasoning: data.reasoning ?? '',
    confidence: data.confidence ?? 0,
    scoringMethod: scoringValue,
    timestamp: data.timestamp ?? new Date().toISOString(),
    conversation: [],
    evidence,
    leakageSignals,
  };
}

// ─── Checkpoint Persistence ─────────────────────────────

export async function saveCheckpoint(
  data: ScanCheckpointData,
  filePath: string,
): Promise<void> {
  const dir = join(filePath, '..');
  await mkdir(dir, { recursive: true });
  const tmpPath = filePath + '.tmp';
  await writeFile(tmpPath, JSON.stringify(data, null, 2), 'utf-8');
  await rename(tmpPath, filePath);
}

export async function loadCheckpoint(filePath: string): Promise<ScanCheckpointData> {
  const raw = await readFile(filePath, 'utf-8');
  const data = JSON.parse(raw) as Record<string, unknown>;

  const storedVersion = typeof data['version'] === 'number' ? data['version'] : 1;
  if (storedVersion !== CHECKPOINT_VERSION) {
    throw new Error(
      `Checkpoint version mismatch: file has v${String(storedVersion)}, ` +
      `expected v${String(CHECKPOINT_VERSION)}. Delete the checkpoint to start fresh.`,
    );
  }

  return {
    version: storedVersion,
    scanId: String(data['scanId'] ?? ''),
    targetUrl: String(data['targetUrl'] ?? ''),
    completedIds: Array.isArray(data['completedIds'])
      ? (data['completedIds'] as string[])
      : [],
    findingsJson: Array.isArray(data['findingsJson'])
      ? (data['findingsJson'] as FindingJson[])
      : [],
    startedAt: String(data['startedAt'] ?? ''),
    phase: String(data['phase'] ?? 'scanning'),
  };
}

function checkpointPath(checkpointDir: string, scanId: string): string {
  return join(checkpointDir, `${scanId}.checkpoint.json`);
}

async function findExistingCheckpoint(
  checkpointDir: string,
  targetUrl: string,
): Promise<ScanCheckpointData | null> {
  let entries: string[];
  try {
    entries = await readdir(checkpointDir);
  } catch {
    return null;
  }

  const candidates: Array<{ path: string; data: ScanCheckpointData; mtime: number }> = [];

  for (const entry of entries) {
    if (!entry.endsWith('.checkpoint.json')) continue;
    const fullPath = join(checkpointDir, entry);
    try {
      const cp = await loadCheckpoint(fullPath);
      if (cp.targetUrl === targetUrl) {
        const st = await stat(fullPath);
        candidates.push({ path: fullPath, data: cp, mtime: st.mtimeMs });
      }
    } catch {
      continue;
    }
  }

  if (candidates.length === 0) return null;
  candidates.sort((a, b) => b.mtime - a.mtime);
  return candidates[0].data;
}

// ─── Pipeline ───────────────────────────────────────────

export async function runPipeline(
  target: string,
  adapter: Adapter,
  config?: Partial<PipelineConfig>,
  options?: { probesDir?: string; category?: string },
): Promise<ScanResult> {
  const resolved: PipelineConfig = { ...defaultPipelineConfig(), ...config };
  const startedAt = new Date().toISOString();
  let scanId: string = crypto.randomUUID();

  // --- Phase 1: Discovery ---
  const allProbes = await loadProbes(options?.probesDir);
  const categoryFilter = options?.category?.toLowerCase();
  const probes = categoryFilter
    ? allProbes.filter((p) => p.category.toLowerCase() === categoryFilter)
    : allProbes;

  if (probes.length === 0) {
    return {
      scanId,
      target,
      startedAt,
      completedAt: new Date().toISOString(),
      findings: [],
      summary: summarize([]),
    };
  }

  // Search for existing checkpoint
  let existingCp: ScanCheckpointData | null = null;
  if (resolved.checkpointDir !== null) {
    existingCp = await findExistingCheckpoint(resolved.checkpointDir, target);
  }

  if (existingCp !== null) {
    scanId = existingCp.scanId;
  }

  const cpPath = resolved.checkpointDir !== null
    ? checkpointPath(resolved.checkpointDir, scanId)
    : null;

  // Attempt checkpoint resume
  let checkpoint: ScanCheckpointData = {
    version: CHECKPOINT_VERSION,
    scanId,
    targetUrl: target,
    completedIds: [],
    findingsJson: [],
    startedAt,
    phase: 'scanning',
  };

  let resumedFindings: Finding[] = [];

  if (cpPath !== null) {
    try {
      checkpoint = await loadCheckpoint(cpPath);
      scanId = checkpoint.scanId;
      resumedFindings = checkpoint.findingsJson.map(findingFromJson);
    } catch (err) {
      if (err instanceof Error && err.message.includes('version mismatch')) {
        // Incompatible checkpoint -- start fresh
      }
      // Corrupt or missing checkpoint -- start fresh
      checkpoint = {
        version: CHECKPOINT_VERSION,
        scanId,
        targetUrl: target,
        completedIds: [],
        findingsJson: [],
        startedAt,
        phase: 'scanning',
      };
    }
  }

  // Filter out already-completed templates
  const completedSet = new Set(checkpoint.completedIds);
  const remaining = probes.filter((t) => !completedSet.has(t.id));

  // --- Phase 2: Scanning ---
  checkpoint.phase = 'scanning';

  // Track the latest in-flight checkpoint save so we can await it after scanning.
  let pendingSave: Promise<void> | null = null;

  const scanFindings = await executeParallel(remaining, adapter, {
    maxConcurrent: resolved.maxConcurrent,
    delayMs: resolved.delayMs,
    offset: checkpoint.completedIds.length,
    total: probes.length,
    onFinding: (finding, current, total) => {
      checkpoint.completedIds.push(finding.probeId);
      checkpoint.findingsJson.push(findingToJson(finding));
      if (cpPath !== null) {
        pendingSave = saveCheckpoint(checkpoint, cpPath).catch(() => {
          // Checkpoint save failure is non-fatal; the next save will overwrite.
        });
      }
      resolved.onFinding?.(finding, current, total);
    },
  });

  // Ensure in-flight checkpoint save completes before proceeding.
  if (pendingSave !== null) {
    await pendingSave;
  }

  const allFindings = [...resumedFindings, ...scanFindings];

  // --- Phase 3: Verification ---
  let verifiedFindings = allFindings;
  if (resolved.verifyVulnerabilities) {
    checkpoint.phase = 'verification';
    if (cpPath !== null) {
      await saveCheckpoint(checkpoint, cpPath);
    }

    const vulnerable = allFindings.filter((f) => f.verdict === Verdict.Vulnerable);
    if (vulnerable.length > 0) {
      const verified = await verifyFindings(vulnerable, adapter, {
        delayMs: resolved.delayMs,
      });
      verifiedFindings = applyVerifiedFindings(allFindings, verified);
    }
  }

  // --- Phase 4: Reporting ---
  const result: ScanResult = {
    scanId,
    target,
    startedAt,
    completedAt: new Date().toISOString(),
    findings: verifiedFindings,
    summary: summarize(verifiedFindings),
  };

  // Clean up checkpoint on successful completion
  if (cpPath !== null) {
    try {
      await unlink(cpPath);
    } catch {
      // Checkpoint may not exist if checkpointing was not active
    }
  }

  return result;
}
