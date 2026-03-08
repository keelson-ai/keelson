import type { Adapter, EvidenceItem, Finding, ProbeTemplate, Verdict } from '../types/index.js';

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
  model?: string;
  maxDepth?: number;
  delayMs?: number;
  evaluate: EvaluateFn;
}

// ─── Probe Tree types ────────────────────────────────────────────

export enum Technique {
  InstructionInjection = 'instruction_injection',
  Authority = 'authority',
  Roleplay = 'roleplay',
  TechnicalJargon = 'technical_jargon',
  SocialEngineering = 'social_engineering',
  DataExtraction = 'data_extraction',
  EncodingObfuscation = 'encoding_obfuscation',
}

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
  severity: string;
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

// ─── Scheduling types ────────────────────────────────────────────

export interface MutationHistory {
  type: string;
  success: boolean;
}

// ─── Shared utilities ───────────────────────────────────────────

export function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
