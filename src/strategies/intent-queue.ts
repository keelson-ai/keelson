import { determineContextBucket } from './session-brief.js';
import type { ProbeIntent, SessionBrief, WeightStore } from './types.js';
import type { PhaseHint, ProbeTemplate } from '../types/index.js';

const PHASE_BASE_PRIORITY: Record<PhaseHint, number> = {
  recon: 100,
  extraction: 200,
  exploitation: 300,
};

export function probeToIntent(template: ProbeTemplate, phaseHint: PhaseHint): ProbeIntent {
  return {
    id: template.id,
    name: template.name,
    objective: template.objective,
    evaluation: template.evaluation,
    owaspId: template.owaspId,
    phaseHint,
    severity: template.severity,
    category: template.category,
    contextWeight: 0,
  };
}

export class IntentQueue {
  private remaining: ProbeIntent[];
  private completed = new Set<string>();
  private skippedPhases = new Set<PhaseHint>();
  private readonly weights?: WeightStore;

  constructor(intents: ProbeIntent[], weights?: WeightStore) {
    this.remaining = [...intents];
    this.weights = weights;
    this.sortByPriority();
  }

  hasNext(): boolean {
    return this.remaining.some((i) => !this.completed.has(i.id) && !this.skippedPhases.has(i.phaseHint));
  }

  next(_brief: SessionBrief): ProbeIntent | null {
    const available = this.remaining.filter((i) => !this.completed.has(i.id) && !this.skippedPhases.has(i.phaseHint));
    if (available.length === 0) return null;
    return available[0];
  }

  markComplete(intentId: string): void {
    this.completed.add(intentId);
  }

  skipCurrentPhase(phase: PhaseHint): void {
    this.skippedPhases.add(phase);
  }

  reorder(brief: SessionBrief): void {
    const bucket = determineContextBucket(brief);
    for (const intent of this.remaining) {
      intent.contextWeight = this.weights?.getWeight(intent.id, bucket) ?? 0;
    }
    this.sortByPriority();
  }

  private sortByPriority(): void {
    this.remaining.sort((a, b) => {
      const aPriority = PHASE_BASE_PRIORITY[a.phaseHint] - a.contextWeight * 50;
      const bPriority = PHASE_BASE_PRIORITY[b.phaseHint] - b.contextWeight * 50;
      return aPriority - bPriority;
    });
  }
}
