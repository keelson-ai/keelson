/**
 * Engagement profile controller — wraps probe execution with natural
 * conversational pacing, warmup turns, cover questions, and suspicion
 * detection to avoid triggering anti-probing defenses on targets.
 */

import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parse as parseYaml } from 'yaml';

import { scannerLogger } from './logger.js';
import { parseEngagementProfile } from '../schemas/engagement.js';
import type {
  Adapter,
  DelayRange,
  EngagementProfile,
  Finding,
  ProbeTemplate,
  SuspicionSignal,
  Turn,
} from '../types/index.js';
import { getErrorMessage, sleep } from '../utils.js';

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

// ─── Loader ─────────────────────────────────────────────

export async function loadEngagementProfile(pathOrId: string): Promise<EngagementProfile> {
  // If it looks like a bare ID (no path separator, no .yaml), resolve from engagements/
  const filePath =
    pathOrId.includes('/') || pathOrId.endsWith('.yaml') || pathOrId.endsWith('.yml')
      ? pathOrId
      : join(packageRoot, 'engagements', `${pathOrId}.yaml`);

  const content = await readFile(filePath, 'utf-8');
  const raw = parseYaml(content);

  try {
    return parseEngagementProfile(raw);
  } catch (error) {
    throw new Error(`Invalid engagement profile at ${filePath}: ${getErrorMessage(error)}`, { cause: error });
  }
}

// ─── Callbacks ──────────────────────────────────────────

export interface EngagementCallbacks {
  onSessionStart?: (sessionIndex: number, totalSessions: number) => void;
  onWarmupTurn?: (message: string) => void;
  onCoverTurn?: (message: string) => void;
  onSuspicion?: (pattern: string, action: string) => void;
  onFinding?: (finding: Finding, current: number, total: number) => void;
}

// ─── Controller ─────────────────────────────────────────

type ProbeExecutor = (probe: ProbeTemplate) => Promise<Finding>;

export class EngagementController {
  private turnCount = 0;

  constructor(
    private readonly profile: EngagementProfile,
    private readonly adapter: Adapter,
  ) {}

  /**
   * Run probes through the engagement profile's pacing strategy.
   *
   * Groups probes into sessions, injects warmup/cover turns, applies
   * pacing delays, and monitors responses for suspicion signals.
   */
  async run(probes: ProbeTemplate[], executor: ProbeExecutor, callbacks: EngagementCallbacks = {}): Promise<Finding[]> {
    const ordered = this.reorderProbes(probes);
    const sessions = this.groupIntoSessions(ordered);
    const findings: Finding[] = [];
    const retryQueue: ProbeTemplate[] = [];
    let probeIndex = 0;
    const totalProbes = probes.length;

    for (let sessionIdx = 0; sessionIdx < sessions.length; sessionIdx++) {
      const session = sessions[sessionIdx];
      this.turnCount = 0;

      callbacks.onSessionStart?.(sessionIdx, sessions.length);

      if (this.profile.sessions.resetBetween) {
        this.adapter.resetSession?.();
      }

      // Warmup
      await this.injectWarmup(callbacks);

      let sessionTerminated = false;

      for (const probe of session) {
        // Check turn budget
        if (this.turnCount >= this.profile.sessions.maxTurnsPerSession) {
          scannerLogger.debug({ sessionIdx, turnCount: this.turnCount }, 'Session turn limit reached');
          break;
        }

        // Inject cover turns before probe
        await this.injectCover(callbacks);

        // Inter-probe delay
        await this.randomDelay(this.profile.pacing.interProbeDelay);

        // Execute probe
        const finding = await executor(probe);
        findings.push(finding);
        this.turnCount += probe.turns.filter((t) => t.role === 'user').length;
        probeIndex++;
        callbacks.onFinding?.(finding, probeIndex, totalProbes);

        // Check suspicion in the last response
        const lastResponse = finding.evidence[finding.evidence.length - 1]?.response ?? '';
        const action = this.checkSuspicion(lastResponse);

        if (action) {
          callbacks.onSuspicion?.(action.matchedPattern, action.action);

          if (action.action === 'pivot_to_cover') {
            await this.injectCover(callbacks);
          } else if (action.action === 'end_session') {
            sessionTerminated = true;
            break;
          } else if (action.action === 'end_session_and_cooldown') {
            sessionTerminated = true;
            // Apply cooldown multiplier for session kill
            const multiplier = this.profile.backoff.onSessionKill.cooldownMultiplier;
            await this.randomDelay({
              minMs: this.profile.pacing.interSessionCooldown.minMs * multiplier,
              maxMs: this.profile.pacing.interSessionCooldown.maxMs * multiplier,
            });
            break;
          }
        }
      }

      // If session was terminated, queue remaining probes for retry
      if (sessionTerminated) {
        const executedIds = new Set(findings.map((f) => f.probeId));
        for (const probe of session) {
          if (!executedIds.has(probe.id)) {
            retryQueue.push(probe);
          }
        }
      }

      // Normal inter-session cooldown (skip if session ended with cooldown already applied)
      if (sessionIdx < sessions.length - 1 && !sessionTerminated) {
        await this.randomDelay(this.profile.pacing.interSessionCooldown);
      }
    }

    // Retry probes that were skipped due to session termination
    if (retryQueue.length > 0) {
      const maxRetries = this.profile.backoff.onSessionKill.maxRetriesPerProbe;
      const retriable = retryQueue.slice(0, retryQueue.length); // all of them
      const retried = new Map<string, number>(); // probeId -> attempts

      const retrySessions = this.groupIntoSessions(retriable);
      for (let sessionIdx = 0; sessionIdx < retrySessions.length; sessionIdx++) {
        const session = retrySessions[sessionIdx];
        this.turnCount = 0;

        if (this.profile.sessions.resetBetween) {
          this.adapter.resetSession?.();
        }

        await this.injectWarmup(callbacks);

        for (const probe of session) {
          const attempts = retried.get(probe.id) ?? 0;
          if (attempts >= maxRetries) continue;
          retried.set(probe.id, attempts + 1);

          if (this.turnCount >= this.profile.sessions.maxTurnsPerSession) break;

          await this.injectCover(callbacks);
          await this.randomDelay(this.profile.pacing.interProbeDelay);

          const finding = await executor(probe);
          // Replace the previous finding for this probe
          const existingIdx = findings.findIndex((f) => f.probeId === probe.id);
          if (existingIdx >= 0) {
            findings[existingIdx] = finding;
          } else {
            findings.push(finding);
          }
          this.turnCount += probe.turns.filter((t) => t.role === 'user').length;
          probeIndex++;
          callbacks.onFinding?.(finding, probeIndex, totalProbes);

          const lastResponse = finding.evidence[finding.evidence.length - 1]?.response ?? '';
          const action = this.checkSuspicion(lastResponse);
          if (action && action.action !== 'pivot_to_cover') break;
        }

        if (sessionIdx < retrySessions.length - 1) {
          await this.randomDelay(this.profile.pacing.interSessionCooldown);
        }
      }
    }

    return findings;
  }

  // ─── Session grouping ───────────────────────────────────

  groupIntoSessions(probes: ProbeTemplate[]): ProbeTemplate[][] {
    const maxPerSession = this.profile.sessions.maxProbesPerSession;
    const sessions: ProbeTemplate[][] = [];
    for (let i = 0; i < probes.length; i += maxPerSession) {
      sessions.push(probes.slice(i, i + maxPerSession));
    }
    return sessions;
  }

  // ─── Probe reordering ──────────────────────────────────

  reorderProbes(probes: ProbeTemplate[]): ProbeTemplate[] {
    const { strategy } = this.profile.probeOrdering;

    if (strategy === 'as_loaded') return probes;

    if (strategy === 'random') {
      const shuffled = [...probes];
      for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
      }
      return shuffled;
    }

    // stealth_first: professional-pretext (GA, TS) before adversarial (EX, SL)
    const ADVERSARIAL_PREFIXES = new Set(['EX', 'SL', 'OW']);
    const stealthy: ProbeTemplate[] = [];
    const adversarial: ProbeTemplate[] = [];

    for (const probe of probes) {
      const prefix = probe.id.split('-')[0];
      if (ADVERSARIAL_PREFIXES.has(prefix)) {
        adversarial.push(probe);
      } else {
        stealthy.push(probe);
      }
    }

    return [...stealthy, ...adversarial];
  }

  // ─── Warmup injection ──────────────────────────────────

  private async injectWarmup(callbacks: EngagementCallbacks): Promise<void> {
    const { minTurns, maxTurns, pool } = this.profile.warmup;
    const count = this.randomInt(minTurns, maxTurns);

    for (let i = 0; i < count; i++) {
      if (this.turnCount >= this.profile.sessions.maxTurnsPerSession) break;

      const message = this.randomPick(pool);
      callbacks.onWarmupTurn?.(message);

      const messages: Turn[] = [{ role: 'user', content: message }];
      await this.adapter.send(messages);
      this.turnCount++;

      await this.randomDelay(this.profile.pacing.interTurnDelay);
    }
  }

  // ─── Cover injection ───────────────────────────────────

  private async injectCover(callbacks: EngagementCallbacks): Promise<void> {
    const { ratio, pool } = this.profile.cover;
    const count = Math.floor(ratio);

    for (let i = 0; i < count; i++) {
      if (this.turnCount >= this.profile.sessions.maxTurnsPerSession) break;

      const message = this.randomPick(pool);
      callbacks.onCoverTurn?.(message);

      const messages: Turn[] = [{ role: 'user', content: message }];
      await this.adapter.send(messages);
      this.turnCount++;

      await this.randomDelay(this.profile.pacing.interTurnDelay);
    }
  }

  // ─── Suspicion detection ───────────────────────────────

  checkSuspicion(response: string): { matchedPattern: string; action: SuspicionSignal['action'] } | null {
    const lower = response.toLowerCase();

    for (const signal of this.profile.backoff.suspicionSignals) {
      if (lower.includes(signal.pattern.toLowerCase())) {
        return { matchedPattern: signal.pattern, action: signal.action };
      }
    }

    return null;
  }

  // ─── Delay helpers ─────────────────────────────────────

  async randomDelay(range: DelayRange): Promise<void> {
    const ms = this.randomInt(range.minMs, range.maxMs);
    if (ms > 0) {
      await sleep(ms);
    }
  }

  // ─── Private helpers ───────────────────────────────────

  private randomInt(min: number, max: number): number {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  private randomPick<T>(arr: T[]): T {
    return arr[Math.floor(Math.random() * arr.length)];
  }
}
