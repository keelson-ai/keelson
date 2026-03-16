// ─── Enums ───────────────────────────────────────────────

export enum Severity {
  Critical = 'Critical',
  High = 'High',
  Medium = 'Medium',
  Low = 'Low',
}

export const SEVERITY_ORDER: Record<string, number> = {
  [Severity.Critical]: 0,
  [Severity.High]: 1,
  [Severity.Medium]: 2,
  [Severity.Low]: 3,
};

export enum Verdict {
  Vulnerable = 'VULNERABLE',
  Safe = 'SAFE',
  Inconclusive = 'INCONCLUSIVE',
}

export enum Category {
  GoalAdherence = 'Goal Adherence',
  ToolSafety = 'Tool Safety',
  BusinessLogic = 'Business Logic',
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
  ArtPrompt = 'art_prompt',
  AsciiSmuggling = 'ascii_smuggling',
  ManyShot = 'many_shot',
  ActorAttack = 'actor_attack',
}

export enum ComplianceFramework {
  OwaspLlmTop10 = 'owasp-llm-top10',
  NistAiRmf = 'nist-ai-rmf',
  EuAiAct = 'eu-ai-act',
  Iso42001 = 'iso-42001',
  Soc2 = 'soc2',
  PciDssV4 = 'pci-dss-v4',
}

export enum ScoringMethod {
  Pattern = 'pattern',
  LlmJudge = 'llm_judge',
  Combined = 'combined',
}

export enum Technique {
  Authority = 'authority',
  Roleplay = 'roleplay',
  TechnicalJargon = 'technical_jargon',
  SocialEngineering = 'social_engineering',
  MultiTurnEscalation = 'multi_turn_escalation',
  EncodingObfuscation = 'encoding_obfuscation',
  ContextOverflow = 'context_overflow',
  InstructionInjection = 'instruction_injection',
  DataExtraction = 'data_extraction',
  ToolInvocation = 'tool_invocation',
}

export enum ResponseClass {
  Refusal = 'refusal',
  Partial = 'partial',
  Compliance = 'compliance',
}

export type PhaseHint = 'recon' | 'extraction' | 'exploitation';

export enum ScanMode {
  Sequential = 'sequential',
  Pipeline = 'pipeline',
  Smart = 'smart',
}

export enum ScanTier {
  Fast = 'fast',
  Deep = 'deep',
  Continuous = 'continuous',
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
  asiId?: string;
  objective: string;
  turns: Turn[];
  evaluation: Evaluation;
  effectiveness?: Effectiveness;
  newSession?: boolean;
  note?: string;
  remediation?: string;
  sourcePath?: string;
}

export interface EvidenceItem {
  stepIndex: number;
  prompt: string;
  response: string;
  responseTimeMs: number;
  /** True when the adapter timed out waiting for a response. */
  timedOut?: boolean;
}

export interface LeakageSignal {
  stepIndex: number;
  signalType: string;
  severity: string;
  description: string;
  confidence: number;
}

export type DossierItemType =
  | 'capability'
  | 'tool'
  | 'entity'
  | 'workflow'
  | 'auth_boundary'
  | 'escalation_path'
  | 'public_fact'
  | 'private_indicator';

export type DossierEvidenceSource = 'capability_probe' | 'infra_probe' | 'agent_response' | 'scan_finding';

export interface DossierEvidence {
  source: DossierEvidenceSource;
  id: string;
  prompt: string;
  response: string;
  confidence: number;
}

export interface DossierItem {
  type: DossierItemType;
  name: string;
  confidence: number;
  verified: boolean;
  public: boolean;
  tags: string[];
  evidence: DossierEvidence[];
}

export interface CoverageGap {
  id: string;
  kind: Exclude<DossierItemType, 'public_fact' | 'private_indicator'>;
  name: string;
  reason: string;
  suggestedCategories: string[];
}

export interface TargetDossier {
  target: string;
  verifiedCapabilities: DossierItem[];
  tools: DossierItem[];
  entities: DossierItem[];
  workflows: DossierItem[];
  authBoundaries: DossierItem[];
  escalationPaths: DossierItem[];
  publicFacts: DossierItem[];
  privateIndicators: DossierItem[];
  baselineFacts: string[];
  summary: string[];
}

export type AttackGraphNodeType =
  | 'tool'
  | 'entity'
  | 'workflow'
  | 'auth_boundary'
  | 'escalation_path'
  | 'leaked_artifact';

export interface AttackGraphNode {
  id: string;
  type: AttackGraphNodeType;
  label: string;
  relatedCategories: string[];
  sourceIds: string[];
  public?: boolean;
}

export interface AttackGraphEdge {
  from: string;
  to: string;
  relation: string;
  strength: number;
}

export interface AttackChainSummary {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
}

export interface FindingTrigger {
  kind: 'probe' | 'finding' | 'coverage_gap' | 'attack_graph';
  id: string;
  reason: string;
  pivot?: string;
}

export type FindingBlastRadius = 'single_response' | 'single_tool' | 'workflow' | 'cross_boundary' | 'systemic';
export type FindingReproducibility = 'deterministic' | 'likely_reproducible' | 'possibly_stochastic';
export type FindingSpecificity = 'target_specific' | 'likely_public' | 'generic_example' | 'hallucination_risk';

export interface Finding {
  probeId: string;
  probeName: string;
  severity: Severity;
  category: string;
  owaspId: string;
  asiId?: string;
  verdict: Verdict;
  confidence: number;
  reasoning: string;
  scoringMethod: ScoringMethod;
  conversation: Turn[];
  evidence: EvidenceItem[];
  leakageSignals: LeakageSignal[];
  remediation?: string;
  timestamp: string;
  /** Tactical learning extracted during detection (only present on VULNERABLE findings). */
  learning?: DetectedLearning;
  triggeredBy?: FindingTrigger;
  blastRadius?: FindingBlastRadius;
  reproducibility?: FindingReproducibility;
  specificity?: FindingSpecificity;
}

export interface ScanSummary {
  total: number;
  vulnerable: number;
  safe: number;
  inconclusive: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<string, number>;
}

export interface DisclosureInventory {
  toolNames: string[];
  urls: string[];
  envVars: string[];
  paths: string[];
}

export interface CumulativeDisclosureResult {
  severity: Severity;
  description: string;
  inventory: DisclosureInventory;
  totalItems: number;
  filledCategories: number;
}

export interface ConversationMemo {
  probeId: string;
  category: string;
  techniques: Technique[];
  outcome: string;
  verdict: Verdict;
  leakedInfo: string[];
}

export interface ScanResult {
  scanId: string;
  target: string;
  startedAt: string;
  completedAt: string;
  findings: Finding[];
  summary: ScanSummary;
  memo?: ConversationMemo[];
  cumulativeDisclosure?: CumulativeDisclosureResult;
  dossier?: TargetDossier;
  coverageGaps?: CoverageGap[];
  attackChain?: AttackChainSummary;
}

// ─── Diff / Comparison Interfaces ───────────────────────

export type ChangeType = 'regression' | 'improvement' | 'new' | 'removed' | 'rate_increase' | 'new_vulnerable';

export interface ScanDiffItem {
  probeId: string;
  probeName: string;
  oldVerdict: Verdict | null;
  newVerdict: Verdict | null;
  changeType: ChangeType;
}

export interface ScanDiff {
  scanAId: string;
  scanBId: string;
  items: ScanDiffItem[];
}

export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface RegressionAlert {
  probeId: string;
  alertSeverity: AlertSeverity;
  changeType: ChangeType;
  description: string;
  oldVerdict: Verdict | null;
  newVerdict: Verdict | null;
  probeSeverity: Severity | null;
}

export interface TrialResult {
  trialIndex: number;
  verdict: Verdict;
  evidence: EvidenceItem[];
  reasoning: string;
  responseTimeMs: number;
}

export interface StatisticalFinding {
  probeId: string;
  probeName: string;
  severity: Severity;
  category: string;
  owaspId: string;
  asiId?: string;
  trials: TrialResult[];
  successRate: number;
  ciLower: number;
  ciUpper: number;
  verdict: Verdict;
}

export interface ConcurrencyConfig {
  maxConcurrentTrials: number;
  earlyTerminationThreshold: number;
}

export interface CampaignConfig {
  name: string;
  trialsPerProbe: number;
  confidenceLevel: number;
  delayBetweenTrials: number;
  delayBetweenProbes: number;
  category?: string;
  probeIds: string[];
  targetUrl: string;
  apiKey: string;
  model: string;
  concurrency: ConcurrencyConfig;
}

export interface CampaignResult {
  campaignId: string;
  config: CampaignConfig;
  target: string;
  findings: StatisticalFinding[];
  startedAt: string;
  completedAt: string | null;
}

// ─── Engagement Profile ─────────────────────────────────

export interface DelayRange {
  minMs: number;
  maxMs: number;
}

export interface SuspicionSignal {
  pattern: string;
  action: 'pivot_to_cover' | 'end_session' | 'end_session_and_cooldown';
}

export interface EngagementProfile {
  id: string;
  name: string;
  description?: string;
  warmup: {
    minTurns: number;
    maxTurns: number;
    pool: string[];
  };
  cover: {
    ratio: number;
    placement: 'interleaved' | 'before_each' | 'after_each';
    pool: string[];
  };
  pacing: {
    interTurnDelay: DelayRange;
    interProbeDelay: DelayRange;
    interSessionCooldown: DelayRange;
  };
  sessions: {
    maxProbesPerSession: number;
    maxTurnsPerSession: number;
    resetBetween: boolean;
  };
  probeOrdering: {
    strategy: 'stealth_first' | 'random' | 'as_loaded';
  };
  backoff: {
    suspicionSignals: SuspicionSignal[];
    onSessionKill: {
      cooldownMultiplier: number;
      maxRetriesPerProbe: number;
    };
  };
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
  // LangGraph-specific
  assistantId?: string;
  // MCP-specific
  toolName?: string;
  // SiteGPT-specific
  chatbotId?: string;
  // LangChain-specific
  inputKey?: string;
  outputKey?: string;
  // Intercom-specific
  intercomPollMs?: number;
  intercomMaxPollAttempts?: number;
  // Browser-specific
  chatInputSelector?: string;
  chatSubmitSelector?: string;
  chatResponseSelector?: string;
  browserHeadless?: boolean;
  browserResponseStabilityMs?: number;
  /** JS snippet to run in page before chat interaction (e.g. dismiss cookie banner) */
  browserPreInteraction?: string;
  /** CSS selector for the chat launcher button to click before auto-detection. */
  browserLauncherSelector?: string;
  /** Create a fresh browser context (clear cookies/storage) before each send call.
   *  Useful for targets with server-side session persistence (e.g. Forethought Solve). */
  browserFreshContextPerSend?: boolean;
  /** Enable adaptive timeout: on timeout, retry the send with a doubled timeout (up to 2x).
   *  Default: false. */
  browserAdaptiveTimeout?: boolean;
  // Payload size limit (browser widgets often have character limits)
  maxPayloadLength?: number;
}

export interface AdapterResponse {
  content: string;
  raw: unknown;
  latencyMs: number;
  /** True when the response was cut short by a timeout (partial or empty content). */
  timedOut?: boolean;
}

export interface Adapter {
  send(messages: Turn[]): Promise<AdapterResponse>;
  healthCheck(): Promise<boolean>;
  resetSession?(): void;
  close?(): Promise<void>;
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

/** Learning extracted by the judge during detection (lightweight, pre-persistence shape). */
export interface DetectedLearning {
  technique: string;
  insight: string;
  novelty: 'novel' | 'confirming' | 'contradicting';
}

export interface DetectionResult {
  verdict: Verdict;
  confidence: number;
  reasoning: string;
  method: ScoringMethod;
  learning?: DetectedLearning;
  blastRadius?: FindingBlastRadius;
  reproducibility?: FindingReproducibility;
  specificity?: FindingSpecificity;
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
