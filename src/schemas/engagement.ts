import { z } from 'zod';

import type { DelayRange, EngagementProfile, SuspicionSignal } from '../types/index.js';

const delayRangeSchema = z.object({
  min_ms: z.number().int().min(0),
  max_ms: z.number().int().min(0),
});

const suspicionSignalSchema = z.object({
  pattern: z.string().min(1),
  action: z.enum(['pivot_to_cover', 'end_session', 'end_session_and_cooldown']),
});

export const engagementProfileSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  description: z.string().optional(),
  warmup: z.object({
    min_turns: z.number().int().min(0),
    max_turns: z.number().int().min(0),
    pool: z.array(z.string()).min(1),
  }),
  cover: z.object({
    ratio: z.number().min(0),
    placement: z.enum(['interleaved', 'before_each', 'after_each']),
    pool: z.array(z.string()).min(1),
  }),
  pacing: z.object({
    inter_turn_delay: delayRangeSchema,
    inter_probe_delay: delayRangeSchema,
    inter_session_cooldown: delayRangeSchema,
  }),
  sessions: z.object({
    max_probes_per_session: z.number().int().min(1),
    max_turns_per_session: z.number().int().min(1),
    reset_between: z.boolean(),
  }),
  probe_ordering: z.object({
    strategy: z.enum(['stealth_first', 'random', 'as_loaded']),
  }),
  backoff: z.object({
    suspicion_signals: z.array(suspicionSignalSchema),
    on_session_kill: z.object({
      cooldown_multiplier: z.number().min(1),
      max_retries_per_probe: z.number().int().min(0),
    }),
  }),
});

export type RawEngagementProfile = z.infer<typeof engagementProfileSchema>;

function parseDelayRange(raw: { min_ms: number; max_ms: number }): DelayRange {
  return { minMs: raw.min_ms, maxMs: raw.max_ms };
}

function parseSuspicionSignal(raw: { pattern: string; action: string }): SuspicionSignal {
  return { pattern: raw.pattern, action: raw.action as SuspicionSignal['action'] };
}

export function parseEngagementProfile(raw: unknown): EngagementProfile {
  const parsed = engagementProfileSchema.parse(raw);

  return {
    id: parsed.id,
    name: parsed.name,
    description: parsed.description,
    warmup: {
      minTurns: parsed.warmup.min_turns,
      maxTurns: parsed.warmup.max_turns,
      pool: parsed.warmup.pool,
    },
    cover: {
      ratio: parsed.cover.ratio,
      placement: parsed.cover.placement,
      pool: parsed.cover.pool,
    },
    pacing: {
      interTurnDelay: parseDelayRange(parsed.pacing.inter_turn_delay),
      interProbeDelay: parseDelayRange(parsed.pacing.inter_probe_delay),
      interSessionCooldown: parseDelayRange(parsed.pacing.inter_session_cooldown),
    },
    sessions: {
      maxProbesPerSession: parsed.sessions.max_probes_per_session,
      maxTurnsPerSession: parsed.sessions.max_turns_per_session,
      resetBetween: parsed.sessions.reset_between,
    },
    probeOrdering: {
      strategy: parsed.probe_ordering.strategy,
    },
    backoff: {
      suspicionSignals: parsed.backoff.suspicion_signals.map(parseSuspicionSignal),
      onSessionKill: {
        cooldownMultiplier: parsed.backoff.on_session_kill.cooldown_multiplier,
        maxRetriesPerProbe: parsed.backoff.on_session_kill.max_retries_per_probe,
      },
    },
  };
}
