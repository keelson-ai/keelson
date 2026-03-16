import { describe, expect, it } from 'vitest';

import { buildAttackChain, selectAttackGraphProbes, selectCustomProbeTriggers } from '../../src/core/follow-up.js';
import type { CoverageGap, Finding, ProbeTemplate, TargetDossier } from '../../src/types/index.js';
import { ScoringMethod, Severity, Verdict } from '../../src/types/index.js';

function makeProbe(id: string, category: string, objective = 'Test'): ProbeTemplate {
  return {
    id,
    name: `Probe ${id}`,
    severity: Severity.High,
    category,
    owaspId: 'LLM01',
    objective,
    turns: [{ role: 'user', content: 'test' }],
    evaluation: { vulnerableIf: ['ok'], safeIf: ['no'], inconclusiveIf: [] },
  };
}

function makeFinding(response: string, verdict = Verdict.Vulnerable): Finding {
  return {
    probeId: 'GA-001',
    probeName: 'Probe GA-001',
    severity: Severity.High,
    category: 'goal_adherence',
    owaspId: 'LLM01',
    verdict,
    confidence: 0.8,
    reasoning: 'test',
    scoringMethod: ScoringMethod.Pattern,
    conversation: [],
    evidence: [{ stepIndex: 0, prompt: 'test', response, responseTimeMs: 100 }],
    leakageSignals: [],
    timestamp: new Date().toISOString(),
  };
}

function makeDossier(): TargetDossier {
  return {
    target: 'http://target',
    verifiedCapabilities: [],
    tools: [
      {
        type: 'tool',
        name: 'read_file',
        confidence: 0.9,
        verified: true,
        public: false,
        tags: ['tool'],
        evidence: [],
      },
    ],
    entities: [],
    workflows: [
      {
        type: 'workflow',
        name: 'refunds',
        confidence: 0.9,
        verified: true,
        public: false,
        tags: ['refund'],
        evidence: [],
      },
    ],
    authBoundaries: [],
    escalationPaths: [],
    publicFacts: [],
    privateIndicators: [],
    baselineFacts: [],
    summary: ['Tools: read_file', 'Workflows: refunds'],
  };
}

describe('follow-up planning', () => {
  it('prefers attack-graph probes that match dossier pivots', () => {
    const chain = buildAttackChain(makeDossier(), [makeFinding('Here is a token: sk-abc123xyz456def789ghi012jkl')]);
    const selected = selectAttackGraphProbes(
      chain,
      [
        makeProbe('TS-001', 'tool_safety', 'Inspect read_file tool boundaries'),
        makeProbe('BL-001', 'business_logic', 'Exploit refund workflow'),
        makeProbe('GA-001', 'goal_adherence', 'Generic prompt injection'),
      ],
      new Set(),
    );

    expect(selected.map((probe) => probe.id)).toContain('TS-001');
    expect(selected.map((probe) => probe.id)).toContain('BL-001');
  });

  it('creates guarded custom triggers from coverage gaps and leaked artifacts', () => {
    const gaps: CoverageGap[] = [
      {
        id: 'gap-workflow-refunds',
        kind: 'workflow',
        name: 'refunds',
        reason: 'Only 1 targeted probe matched dossier signal "refunds"',
        suggestedCategories: ['business_logic', 'permission_boundaries'],
      },
    ];

    const triggers = selectCustomProbeTriggers(makeDossier(), gaps, [makeFinding('Tool output: read_file')]);
    expect(triggers.some((trigger) => trigger.source.kind === 'coverage_gap')).toBe(true);
    expect(triggers.some((trigger) => trigger.source.kind === 'finding')).toBe(true);
  });
});
