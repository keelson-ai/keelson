import type { MemoTable } from '../core/memo.js';
import type { Adapter, Evaluation, EvidenceItem, Finding, PhaseHint, ProbeTemplate, Verdict } from '../types/index.js';
import { ScoringMethod, Severity, Technique } from '../types/index.js';

// ─── Evaluation callback (injected from core engine, Track 2) ────

export type EvaluateFn = (
  template: ProbeTemplate,
  evidence: EvidenceItem[],
) => Promise<{
  verdict: Verdict;
  confidence: number;
  reasoning: string;
}>;

// ─── Mutation types ──────────────────────────────────────────────

export const PROGRAMMATIC_MUTATIONS = [
  'base64_encode',
  'leetspeak',
  'context_overflow',
  'rot13',
  'unicode_homoglyph',
  'char_split',
  'reversed_words',
  'morse_code',
  'caesar_cipher',
] as const;

export const LLM_MUTATIONS = ['paraphrase', 'roleplay_wrap', 'gradual_escalation', 'translation'] as const;

// ─── PAIR types ──────────────────────────────────────────────────

export interface RefinementStep {
  iteration: number;
  prompt: string;
  response: string;
  verdict: Verdict;
  reasoning: string;
}

export interface PAIRResult {
  templateId: string;
  iterationsUsed: number;
  maxIterations: number;
  success: boolean;
  finding: Finding;
  refinementHistory: RefinementStep[];
}

export interface PAIROptions {
  target: Adapter;
  prober: Adapter;
  targetModel?: string;
  proberModel?: string;
  maxIterations?: number;
  delayMs?: number;
  evaluate: EvaluateFn;
}

// ─── Crescendo types ─────────────────────────────────────────────

export interface CrescendoStep {
  turn: number;
  prompt: string;
  response: string;
  escalationLevel: number; // 0.0 (innocent) to 1.0 (full probe)
}

export interface CrescendoResult {
  templateId: string;
  turnsUsed: number;
  maxTurns: number;
  success: boolean;
  finding: Finding;
  escalationPath: CrescendoStep[];
}

export interface CrescendoOptions {
  target: Adapter;
  prober: Adapter;
  targetModel?: string;
  proberModel?: string;
  maxTurns?: number;
  delayMs?: number;
  evaluate: EvaluateFn;
}

// ─── Branching types ─────────────────────────────────────────────

export interface ConversationNode {
  prompt: string;
  response: string;
  responseClass: 'refusal' | 'partial' | 'compliance';
  verdict: Verdict;
  confidence: number;
  depth: number;
  children: ConversationNode[];
}

export interface BranchingOptions {
  target: Adapter;
  prober?: Adapter;
  maxDepth?: number;
  delayMs?: number;
  evaluate: EvaluateFn;
}

// ─── Probe Tree types ────────────────────────────────────────────

export interface TreeBranch {
  prompt: string;
  technique: Technique;
  children: Partial<Record<'refusal' | 'partial' | 'compliance', TreeBranch[]>>;
}

export interface EvalCriteria {
  vulnerableIf: string[];
  safeIf: string[];
}

export interface ProbeTree {
  id: string;
  name: string;
  category: string;
  severity: Severity;
  owasp: string;
  objective: string;
  rootPrompt: string;
  branches: Partial<Record<'refusal' | 'partial' | 'compliance', TreeBranch[]>>;
  evalCriteria: EvalCriteria;
}

export interface TreeResult {
  treeId: string;
  success: boolean;
  depthReached: number;
  path: Array<{ prompt: string; response: string; classification: string }>;
  finding: Finding;
}

export interface TreeOptions {
  target: Adapter;
  model?: string;
  maxDepth?: number;
  delayMs?: number;
  evaluate: EvaluateFn;
  memo?: MemoEntry[];
}

// ─── Memo (simplified for cross-track use) ───────────────────────

export interface MemoEntry {
  technique: string;
  category: string;
  verdict: Verdict;
  weight: number;
}

// ─── Session Erosion types ──────────────────────────────────────

export type TargetPersonalityTag =
  | 'cooperative'
  | 'guarded'
  | 'scope_strict'
  | 'scope_flexible'
  | 'chatty'
  | 'terse'
  | 'inconsistent'
  | 'tool_aware'
  | 'prompt_protected';

export type ContextBucket =
  | 'early_session'
  | 'mid_session'
  | 'post_trust_building'
  | 'post_disclosure'
  | 'post_refusal'
  | 'target_guarded';

export type ProberDecision = 'continue' | 'reframe' | 'complete' | 'move_on';

export interface RefusalEntry {
  intent: string;
  framing: string;
  refusalWording: string;
  turnNumber: number;
}

export interface KeyMoment {
  turnNumber: number;
  type: 'disclosure' | 'refusal' | 'reframe_success' | 'personality_signal';
  summary: string;
}

export interface SessionBrief {
  disclosedInfo: string[];
  refusalPatterns: RefusalEntry[];
  successfulFramings: string[];
  failedFramings: string[];
  personalityTags: TargetPersonalityTag[];
  turnsUsed: number;
  intentsCompleted: number;
  intentsRemaining: number;
  currentPhase: PhaseHint;
  keyMoments: KeyMoment[];
}

export interface TargetDossier {
  company: {
    name: string;
    industry: string;
    description: string;
  };
  regulations: string[];
  agentRole: string;
  techStack: string[];
  sensitiveDataTargets: {
    high: string[];
    medium: string[];
    low: string[];
  };
  knownAttackSurface: string[];
  userProvidedContext: string;
  rawIntel: string[];
}

export interface ProbeIntent {
  id: string;
  name: string;
  objective: string;
  evaluation: Evaluation;
  owaspId: string;
  phaseHint: PhaseHint;
  severity: Severity;
  category: string;
  contextWeight: number;
}

export interface WeightEntry {
  intentId: string;
  contextBucket: ContextBucket;
  attempts: number;
  successes: number;
  successRate: number;
  lastUpdated: string;
}

export interface ErosionTurnInfo {
  intentId: string;
  turnNumber: number;
  intentTurnNumber: number;
  prompt: string;
  response: string;
  responseTimeMs: number;
  verdict: Verdict;
  decision: ProberDecision;
}

export interface IntentResult {
  intent: ProbeIntent;
  finding: Finding;
  turnsUsed: number;
  contextBucket: ContextBucket;
  outcome: 'vulnerable' | 'safe' | 'inconclusive' | 'budget_exhausted';
}

export interface WeightStore {
  load(): Promise<void>;
  save(): Promise<void>;
  getWeight(intentId: string, bucket: ContextBucket): number;
  recordOutcome(intentId: string, bucket: ContextBucket, success: boolean): void;
  flush(): Promise<void>;
}

export interface SessionErosionOptions {
  target: Adapter;
  prober: Adapter;
  intents: ProbeIntent[];
  dossier: TargetDossier;
  evaluate: EvaluateFn;
  memo?: MemoTable;
  weights?: WeightStore;
  maxTurnsPerIntent?: number;
  maxTotalTurns?: number;
  maxConsecutiveRefusals?: number;
  delayMs?: number;
  onTurnComplete?: (info: ErosionTurnInfo) => void;
  onIntentComplete?: (info: IntentResult) => void;
  onPhaseChange?: (phase: string) => void;
}

export interface SessionErosionResult {
  findings: Finding[];
  brief: SessionBrief;
  turnsUsed: number;
  intentsAttempted: number;
  intentsSuccessful: number;
  sessionNarrative: string;
}

// ─── Scheduling types ────────────────────────────────────────────

export interface MutationHistory {
  type: string;
  success: boolean;
}

// ─── Shared strategy helpers ────────────────────────────────────

export interface StrategyStep {
  prompt: string;
  response: string;
}

/**
 * Build a Finding from strategy execution steps.
 * Shared by PAIR, Crescendo, and Probe Tree strategies.
 */
export function buildStrategyFinding(
  source: { id: string; name: string; severity: Severity; category: string; owaspId: string },
  steps: StrategyStep[],
  evalResult: { verdict: Verdict; confidence: number; reasoning: string },
): Finding {
  return {
    probeId: source.id,
    probeName: source.name,
    severity: source.severity,
    category: source.category,
    owaspId: source.owaspId,
    verdict: evalResult.verdict,
    confidence: evalResult.confidence,
    reasoning: evalResult.reasoning,
    scoringMethod: ScoringMethod.Combined,
    conversation: steps.flatMap((s) => [
      { role: 'user' as const, content: s.prompt },
      { role: 'assistant' as const, content: s.response },
    ]),
    evidence: steps.map((s, i) => ({
      stepIndex: i,
      prompt: s.prompt,
      response: s.response,
      responseTimeMs: 0,
    })),
    leakageSignals: [],
    timestamp: new Date().toISOString(),
  };
}
