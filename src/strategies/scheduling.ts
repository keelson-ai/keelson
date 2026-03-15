import { type MutationHistory, PROGRAMMATIC_MUTATIONS } from './types.js';
import { MutationType } from '../types/index.js';

/**
 * Round-robin mutation selection. Cycles through available mutations in order.
 */
export function roundRobin(history: MutationHistory[], available: MutationType[]): MutationType {
  if (available.length === 0) throw new Error('No mutations available');
  if (history.length === 0) return available[0];

  const lastUsed = history[history.length - 1].type;
  const idx = available.indexOf(lastUsed as MutationType);
  return available[(idx + 1) % available.length];
}

/**
 * Weighted mutation selection based on historical success rates.
 * Successful mutations get higher weights; untried mutations get an exploration bonus.
 */
export function weightedByHistory(history: MutationHistory[], available: MutationType[]): MutationType {
  if (available.length === 0) throw new Error('No mutations available');
  if (history.length === 0) return available[Math.floor(Math.random() * available.length)];

  // Calculate success rate per mutation
  const stats = new Map<string, { successes: number; total: number }>();
  for (const entry of history) {
    const s = stats.get(entry.type) ?? { successes: 0, total: 0 };
    s.total++;
    if (entry.success) s.successes++;
    stats.set(entry.type, s);
  }

  let maxSuccess = 0;
  for (const s of stats.values()) {
    const rate = s.successes / s.total;
    if (rate > maxSuccess) maxSuccess = rate;
  }

  // Weight: success rate, or exploration bonus for untried
  const weights = available.map((m) => {
    const s = stats.get(m);
    if (!s) return maxSuccess + 1; // exploration bonus
    return s.successes / s.total;
  });

  // Weighted random selection
  const totalWeight = weights.reduce((a, b) => a + b, 0);
  if (totalWeight === 0) return available[Math.floor(Math.random() * available.length)];

  let r = Math.random() * totalWeight;
  for (let i = 0; i < available.length; i++) {
    r -= weights[i];
    if (r <= 0) return available[i];
  }
  return available[available.length - 1];
}

/**
 * Determines whether mutations should be applied based on current success rate.
 * Sweet spot: between low (no signal) and high (already saturated) thresholds.
 */
export function shouldMutate(successRate: number, lowThreshold = 0.05, highThreshold = 0.8): boolean {
  return successRate > lowThreshold && successRate < highThreshold;
}

/**
 * All programmatic mutation types (no LLM needed).
 */
export const PROGRAMMATIC_TYPES: MutationType[] = [...PROGRAMMATIC_MUTATIONS] as MutationType[];

/**
 * All LLM-powered mutation types.
 */
export const LLM_TYPES: MutationType[] = [
  MutationType.Paraphrase,
  MutationType.RoleplayWrap,
  MutationType.GradualEscalation,
  MutationType.Translation,
  MutationType.ActorAttack,
];

/**
 * All 17 mutation types combined.
 */
export const ALL_MUTATIONS: MutationType[] = [...PROGRAMMATIC_TYPES, ...LLM_TYPES];
