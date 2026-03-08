// ─── Enums ───────────────────────────────────────────────

export enum Severity {
  Critical = 'Critical',
  High = 'High',
  Medium = 'Medium',
  Low = 'Low',
}

export enum Verdict {
  Vulnerable = 'VULNERABLE',
  Safe = 'SAFE',
  Inconclusive = 'INCONCLUSIVE',
}

export enum Category {
  GoalAdherence = 'Goal Adherence',
  ToolSafety = 'Tool Safety',
  MemoryIntegrity = 'Memory Integrity',
  ContentSafety = 'Content Safety',
  AgenticSecurity = 'Agentic Security',
  PermissionBoundaries = 'Permission Boundaries',
  DelegationIntegrity = 'Delegation Integrity',
  ExecutionSafety = 'Execution Safety',
  SessionIsolation = 'Session Isolation',
  OutputWeaponization = 'Output Weaponization',
  MultiAgentSecurity = 'Multi-Agent Security',
  TemporalPersistence = 'Temporal Persistence',
  CognitiveArchitecture = 'Cognitive Architecture',
  ConversationalExfiltration = 'Conversational Exfiltration',
  SupplyChainLanguage = 'Supply Chain Language',
}

export enum MutationType {
  Base64Encode = 'base64_encode',
  Leetspeak = 'leetspeak',
  ContextOverflow = 'context_overflow',
  Paraphrase = 'paraphrase',
  RoleplayWrap = 'roleplay_wrap',
  GradualEscalation = 'gradual_escalation',
  Rot13 = 'rot13',
  UnicodeHomoglyph = 'unicode_homoglyph',
  CharSplit = 'char_split',
  ReversedWords = 'reversed_words',
  Translation = 'translation',
  MorseCode = 'morse_code',
  CaesarCipher = 'caesar_cipher',
}

export enum ScoringMethod {
  Pattern = 'pattern',
  LlmJudge = 'llm_judge',
  Combined = 'combined',
}

export enum ResponseClass {
  Refusal = 'refusal',
  Partial = 'partial',
  Compliance = 'compliance',
}

export enum ScanMode {
  Sequential = 'sequential',
  Pipeline = 'pipeline',
  Smart = 'smart',
  Convergence = 'convergence',
}

export enum ComplianceFramework {
  OwaspLlmTop10 = 'owasp-llm-top10',
  NistAiRmf = 'nist-ai-rmf',
  EuAiAct = 'eu-ai-act',
  Iso42001 = 'iso-42001',
  Soc2 = 'soc2',
  PciDssV4 = 'pci-dss-v4',
}

// ─── Core Data Interfaces ────────────────────────────────

export interface Turn {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface Evaluation {
  vulnerableIf: string[];
  safeIf: string[];
  inconclusiveIf: string[];
}

export interface Effectiveness {
  successRate: number;
  timesTested: number;
}

export interface ProbeTemplate {
  id: string;
  name: string;
  severity: Severity;
  category: string;
  owaspId: string;
  objective: string;
  turns: Turn[];
  evaluation: Evaluation;
  effectiveness?: Effectiveness;
  newSession?: boolean;
  note?: string;
  sourcePath?: string;
}

export interface EvidenceItem {
  stepIndex: number;
  prompt: string;
  response: string;
  responseTimeMs: number;
}

export interface LeakageSignal {
  stepIndex: number;
  signalType: string;
  severity: string;
  description: string;
  confidence: number;
}

export interface Finding {
  probeId: string;
  probeName: string;
  severity: Severity;
  category: string;
  owaspId: string;
  verdict: Verdict;
  confidence: number;
  reasoning: string;
  scoringMethod: ScoringMethod;
  conversation: Turn[];
  evidence: EvidenceItem[];
  leakageSignals: LeakageSignal[];
  timestamp: string;
}

export interface ScanSummary {
  total: number;
  vulnerable: number;
  safe: number;
  inconclusive: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<string, number>;
}

export interface ScanResult {
  scanId: string;
  target: string;
  startedAt: string;
  completedAt: string;
  findings: Finding[];
  summary: ScanSummary;
}

// ─── Adapter Interfaces ──────────────────────────────────

export interface AdapterConfig {
  type: string;
  baseUrl: string;
  apiKey?: string;
  model?: string;
  headers?: Record<string, string>;
  timeout?: number;
  retryAttempts?: number;
  retryDelay?: number;
}

export interface AdapterResponse {
  content: string;
  raw: unknown;
  latencyMs: number;
}

export interface Adapter {
  send(messages: Turn[]): Promise<AdapterResponse>;
  healthCheck(): Promise<boolean>;
}

// ─── Strategy Interfaces ─────────────────────────────────

export interface MutatedProbe {
  originalId: string;
  mutationType: MutationType;
  mutatedPrompt: string;
  mutationDescription: string;
}

export interface StrategyResult {
  findings: Finding[];
  probesExecuted: number;
  mutationsApplied: number;
}

// ─── Detection / Judging ─────────────────────────────────

export interface DetectionResult {
  verdict: Verdict;
  confidence: number;
  reasoning: string;
  method: ScoringMethod;
}

// ─── Scan Configuration ──────────────────────────────────

export interface JudgeConfig {
  provider: string;
  model: string;
  apiKey: string;
}

export interface ScanConfig {
  target: AdapterConfig;
  categories?: string[];
  severities?: Severity[];
  mode: ScanMode;
  concurrency?: number;
  delayMs?: number;
  judge?: JudgeConfig;
}
