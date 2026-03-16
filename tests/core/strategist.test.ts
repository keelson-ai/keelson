import { describe, expect, it } from 'vitest';

import { AgentType, Priority, adaptPlan, classifyTarget, selectProbes } from '../../src/core/strategist.js';
import type { ReconResponse, TargetProfile } from '../../src/core/strategist.js';
import type { Finding, ProbeTemplate, TargetDossier } from '../../src/types/index.js';
import { ScoringMethod, Severity, Verdict } from '../../src/types/index.js';

function makeRecon(probeType: string, response: string): ReconResponse {
  return { probeType, prompt: 'test', response };
}

function makeProfile(overrides: Partial<TargetProfile> = {}): TargetProfile {
  return {
    agentTypes: [AgentType.GeneralChat],
    detectedTools: [],
    hasMemory: false,
    hasWriteAccess: false,
    refusalStyle: 'unknown',
    ...overrides,
  };
}

function makeProbe(id: string, category: string, severity: Severity = Severity.High): ProbeTemplate {
  return {
    id,
    name: `Probe ${id}`,
    severity,
    category,
    owaspId: 'LLM01',
    objective: 'Test',
    turns: [{ role: 'user', content: 'test' }],
    evaluation: { vulnerableIf: ['test'], safeIf: ['test'], inconclusiveIf: [] },
  };
}

function makeFinding(category: string, verdict: Verdict): Finding {
  return {
    probeId: 'T-001',
    probeName: 'Test',
    severity: Severity.High,
    category,
    owaspId: 'LLM01',
    verdict,
    confidence: 0.8,
    reasoning: 'test',
    scoringMethod: ScoringMethod.Pattern,
    conversation: [],
    evidence: [{ stepIndex: 0, prompt: 'test', response: 'test', responseTimeMs: 100 }],
    leakageSignals: [],
    timestamp: new Date().toISOString(),
  };
}

function makeDossier(): TargetDossier {
  return {
    target: 'http://target',
    verifiedCapabilities: [],
    tools: [],
    entities: [],
    workflows: [
      {
        type: 'workflow',
        name: 'refunds',
        confidence: 0.9,
        verified: true,
        public: false,
        tags: ['refund', 'billing'],
        evidence: [],
      },
    ],
    authBoundaries: [
      {
        type: 'auth_boundary',
        name: 'account_verification',
        confidence: 0.8,
        verified: true,
        public: false,
        tags: ['account', 'verification'],
        evidence: [],
      },
    ],
    escalationPaths: [],
    publicFacts: [],
    privateIndicators: [],
    baselineFacts: [],
    summary: ['Workflows: refunds', 'Auth boundaries: account_verification'],
  };
}

describe('classifyTarget', () => {
  it('detects codebase agent', () => {
    const profile = classifyTarget([makeRecon('tools', 'I can search code in the repository and read files.')]);
    expect(profile.agentTypes).toContain(AgentType.CodebaseAgent);
  });

  it('detects RAG agent', () => {
    const profile = classifyTarget([
      makeRecon('tools', 'I retrieve documents from a knowledge base using vector embeddings.'),
    ]);
    expect(profile.agentTypes).toContain(AgentType.RagAgent);
  });

  it('detects customer service agent', () => {
    const profile = classifyTarget([
      makeRecon('tools', 'I help with billing, account management, and refund requests.'),
    ]);
    expect(profile.agentTypes).toContain(AgentType.CustomerService);
  });

  it('detects tool-rich agent from 3+ tool names', () => {
    const profile = classifyTarget([
      makeRecon('tools', 'I have `read_file`, `write_file`, and `execute_command` available.'),
    ]);
    expect(profile.agentTypes).toContain(AgentType.ToolRich);
    expect(profile.detectedTools).toEqual(['read_file', 'write_file', 'execute_command']);
  });

  it('detects memory capability', () => {
    const profile = classifyTarget([makeRecon('memory', 'Yes, I remember our previous conversation history.')]);
    expect(profile.hasMemory).toBe(true);
  });

  it('excludes negated memory', () => {
    const profile = classifyTarget([makeRecon('memory', "I don't remember any previous conversations.")]);
    expect(profile.hasMemory).toBe(false);
  });

  it('detects rigid refusal style', () => {
    const profile = classifyTarget([makeRecon('error', 'That is not allowed by policy.')]);
    expect(profile.refusalStyle).toBe('rigid');
  });

  it('detects leaky refusal style', () => {
    const profile = classifyTarget([
      makeRecon('tools', 'I cannot help with that, but I have `read_file` and `write_file` available.'),
    ]);
    expect(profile.refusalStyle).toBe('leaky');
  });

  it('defaults to general chat when no patterns match', () => {
    const profile = classifyTarget([makeRecon('tools', 'Hello, how can I help?')]);
    expect(profile.agentTypes).toEqual([AgentType.GeneralChat]);
  });
});

describe('selectProbes', () => {
  const templates = [
    makeProbe('GA-001', 'goal_adherence', Severity.High),
    makeProbe('GA-002', 'goal_adherence', Severity.Medium),
    makeProbe('TS-001', 'tool_safety', Severity.Critical),
    makeProbe('TS-002', 'tool_safety', Severity.High),
    makeProbe('MI-001', 'memory_integrity', Severity.High),
    makeProbe('SI-001', 'session_isolation', Severity.Medium),
    makeProbe('PB-001', 'permission_boundaries', Severity.High),
  ];

  it('always includes goal_adherence as HIGH', () => {
    const plan = selectProbes(makeProfile(), templates);
    const ga = plan.categories.find((c) => c.category === 'goal_adherence');
    expect(ga?.priority).toBe(Priority.High);
    expect(ga?.probeIds).toEqual(['GA-001', 'GA-002']);
  });

  it('assigns HIGH priority for tool-rich profile', () => {
    const plan = selectProbes(makeProfile({ agentTypes: [AgentType.ToolRich] }), templates);
    const ts = plan.categories.find((c) => c.category === 'tool_safety');
    expect(ts?.priority).toBe(Priority.High);
  });

  it('limits LOW priority categories to 3 probes', () => {
    const manyProbes = Array.from({ length: 10 }, (_, i) =>
      makeProbe(`EX-${String(i + 1).padStart(3, '0')}`, 'execution_safety', Severity.Medium),
    );
    const plan = selectProbes(makeProfile(), [...templates, ...manyProbes]);
    const es = plan.categories.find((c) => c.category === 'execution_safety');
    expect(es?.priority).toBe(Priority.Low);
    expect(es?.probeIds).toHaveLength(3);
  });

  it('skips session_isolation when no memory', () => {
    const plan = selectProbes(makeProfile({ hasMemory: false }), templates);
    const si = plan.categories.find((c) => c.category === 'session_isolation');
    expect(si?.priority).toBe(Priority.Skip);
    expect(si?.probeIds).toHaveLength(0);
  });

  it('promotes category with recon vulnerability', () => {
    const findings = [makeFinding('memory_integrity', Verdict.Vulnerable)];
    const plan = selectProbes(makeProfile(), templates, findings);
    const mi = plan.categories.find((c) => c.category === 'memory_integrity');
    expect(mi?.priority).toBe(Priority.High);
  });

  it('reports correct totalProbes', () => {
    const plan = selectProbes(makeProfile({ agentTypes: [AgentType.ToolRich] }), templates);
    expect(plan.totalProbes).toBe(plan.categories.reduce((s, c) => s + c.probeIds.length, 0));
  });

  it('promotes business_logic for grounded support workflows', () => {
    const plan = selectProbes(makeDossier(), [...templates, makeProbe('BL-001', 'business_logic')]);
    const bl = plan.categories.find((c) => c.category === 'business_logic');
    expect(bl?.priority).toBe(Priority.High);
    expect(plan.coverageGaps.length).toBeGreaterThan(0);
  });
});

describe('adaptPlan', () => {
  function makePlan(categories: Array<{ category: string; priority: Priority; probeIds: string[] }>) {
    return {
      profile: makeProfile(),
      categories: categories.map((c) => ({ ...c, rationale: 'test' })),
      totalProbes: categories.reduce((s, c) => s + c.probeIds.length, 0),
      coverageGaps: [],
    };
  }

  it('escalates category with 3+ vulnerabilities to HIGH', () => {
    const plan = makePlan([{ category: 'tool_safety', priority: Priority.Medium, probeIds: ['TS-001'] }]);
    const findings = [
      makeFinding('tool_safety', Verdict.Vulnerable),
      makeFinding('tool_safety', Verdict.Vulnerable),
      makeFinding('tool_safety', Verdict.Vulnerable),
    ];
    const adapted = adaptPlan(plan, findings);
    expect(adapted.categories[0].priority).toBe(Priority.High);
  });

  it('de-escalates category with 3+ consecutive SAFEs (non-HIGH)', () => {
    const plan = makePlan([{ category: 'memory_integrity', priority: Priority.Medium, probeIds: ['MI-001'] }]);
    const findings = [
      makeFinding('memory_integrity', Verdict.Safe),
      makeFinding('memory_integrity', Verdict.Safe),
      makeFinding('memory_integrity', Verdict.Safe),
    ];
    const adapted = adaptPlan(plan, findings);
    expect(adapted.categories[0].priority).toBe(Priority.Skip);
    expect(adapted.categories[0].probeIds).toHaveLength(0);
  });

  it('does not de-escalate HIGH priority', () => {
    const plan = makePlan([{ category: 'goal_adherence', priority: Priority.High, probeIds: ['GA-001'] }]);
    const findings = [
      makeFinding('goal_adherence', Verdict.Safe),
      makeFinding('goal_adherence', Verdict.Safe),
      makeFinding('goal_adherence', Verdict.Safe),
      makeFinding('goal_adherence', Verdict.Safe),
      makeFinding('goal_adherence', Verdict.Safe),
    ];
    const adapted = adaptPlan(plan, findings);
    expect(adapted.categories[0].priority).toBe(Priority.High);
  });

  it('does not change plan when no signals', () => {
    const plan = makePlan([{ category: 'tool_safety', priority: Priority.Medium, probeIds: ['TS-001'] }]);
    const adapted = adaptPlan(plan, []);
    expect(adapted.categories[0].priority).toBe(Priority.Medium);
  });
});
