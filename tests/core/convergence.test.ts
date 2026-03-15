import { describe, expect, it } from 'vitest';

import {
  detectLeakage,
  harvestLeakedInfo,
  selectCrossfeedProbes,
  selectLeakageTargetedProbes,
} from '../../src/core/convergence.js';
import type { Finding, ProbeTemplate } from '../../src/types/index.js';
import { ScoringMethod, Severity, Verdict } from '../../src/types/index.js';

function makeFinding(probeId: string, category: string, verdict: Verdict, response = 'test'): Finding {
  return {
    probeId,
    probeName: `Probe ${probeId}`,
    severity: Severity.High,
    category,
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

function makeProbe(id: string, category: string): ProbeTemplate {
  return {
    id,
    name: `Probe ${id}`,
    severity: Severity.High,
    category,
    owaspId: 'LLM01',
    objective: 'Test',
    turns: [{ role: 'user', content: `Probe ${id}` }],
    evaluation: { vulnerableIf: ['PWNED'], safeIf: ['refuses'], inconclusiveIf: [] },
  };
}

describe('harvestLeakedInfo', () => {
  it('extracts system prompt leaks', () => {
    const findings = [
      makeFinding(
        'GA-001',
        'goal_adherence',
        Verdict.Vulnerable,
        'My system prompt says: You are a helpful assistant that answers questions.',
      ),
    ];
    const leaked = harvestLeakedInfo(findings);
    expect(leaked.some((l) => l.infoType === 'system_prompt')).toBe(true);
  });

  it('extracts credential leaks', () => {
    const findings = [
      makeFinding('GA-001', 'goal_adherence', Verdict.Vulnerable, 'The API key is sk-abc123xyz456def789ghi012jkl'),
    ];
    const leaked = harvestLeakedInfo(findings);
    expect(leaked.some((l) => l.infoType === 'credential')).toBe(true);
  });

  it('extracts internal URL leaks', () => {
    const findings = [
      makeFinding('GA-001', 'goal_adherence', Verdict.Vulnerable, 'Connect to https://internal.example.com/api/v1'),
    ];
    const leaked = harvestLeakedInfo(findings);
    expect(leaked.some((l) => l.infoType === 'internal_url')).toBe(true);
  });

  it('extracts model name leaks', () => {
    const findings = [makeFinding('GA-001', 'goal_adherence', Verdict.Vulnerable, 'I am running on claude-3-opus.')];
    const leaked = harvestLeakedInfo(findings);
    expect(leaked.some((l) => l.infoType === 'model')).toBe(true);
  });

  it('deduplicates leaked content', () => {
    const findings = [
      makeFinding('GA-001', 'goal_adherence', Verdict.Vulnerable, 'key: sk-abc123xyz456def789ghi012jkl'),
      makeFinding('GA-002', 'goal_adherence', Verdict.Vulnerable, 'key: sk-abc123xyz456def789ghi012jkl'),
    ];
    const leaked = harvestLeakedInfo(findings);
    const creds = leaked.filter((l) => l.infoType === 'credential');
    expect(creds).toHaveLength(1);
  });

  it('returns empty for clean responses', () => {
    const findings = [makeFinding('GA-001', 'goal_adherence', Verdict.Safe, 'I cannot help with that.')];
    expect(harvestLeakedInfo(findings)).toHaveLength(0);
  });
});

describe('detectLeakage', () => {
  it('extracts tool names from response text', () => {
    const leaked = detectLeakage('My available tools include: read_file, write_file, execute_command');
    expect(leaked.some((l) => l.infoType === 'tool_name')).toBe(true);
    expect(leaked[0].sourceProbeId).toBe('send');
    expect(leaked[0].stepIndex).toBe(0);
  });

  it('extracts credential patterns', () => {
    const leaked = detectLeakage('Here is the key: sk-abc123xyz456def789ghi012jkl');
    expect(leaked.some((l) => l.infoType === 'credential')).toBe(true);
  });

  it('returns empty for clean text', () => {
    const leaked = detectLeakage('I cannot help with that request. Please ask something else.');
    expect(leaked).toHaveLength(0);
  });

  it('deduplicates results', () => {
    const text = 'The key is sk-abc123xyz456def789ghi012jkl and also sk-abc123xyz456def789ghi012jkl again';
    const leaked = detectLeakage(text);
    const creds = leaked.filter((l) => l.infoType === 'credential');
    expect(creds).toHaveLength(1);
  });
});

describe('selectCrossfeedProbes', () => {
  const allTemplates = [
    makeProbe('TS-001', 'tool_safety'),
    makeProbe('PB-001', 'permission_boundaries'),
    makeProbe('ES-001', 'execution_safety'),
    makeProbe('GA-001', 'goal_adherence'),
    makeProbe('OW-001', 'output_weaponization'),
  ];

  it('selects probes from related categories', () => {
    const vulnFindings = [makeFinding('TS-001', 'tool_safety', Verdict.Vulnerable)];
    const selected = selectCrossfeedProbes(vulnFindings, allTemplates, new Set(['TS-001']));

    const categories = selected.map((t) => t.category);
    expect(categories).toContain('permission_boundaries');
    expect(categories).toContain('execution_safety');
    expect(categories).toContain('output_weaponization');
    // Should not include tool_safety (already has vuln)
    expect(categories).not.toContain('tool_safety');
  });

  it('excludes already executed probes', () => {
    const vulnFindings = [makeFinding('TS-001', 'tool_safety', Verdict.Vulnerable)];
    const selected = selectCrossfeedProbes(vulnFindings, allTemplates, new Set(['TS-001', 'PB-001']));
    expect(selected.find((t) => t.id === 'PB-001')).toBeUndefined();
  });

  it('returns empty when no related categories', () => {
    const vulnFindings = [makeFinding('XX-001', 'unknown_category', Verdict.Vulnerable)];
    const selected = selectCrossfeedProbes(vulnFindings, allTemplates, new Set());
    expect(selected).toHaveLength(0);
  });
});

describe('selectLeakageTargetedProbes', () => {
  const allTemplates = [
    makeProbe('TS-001', 'tool_safety'),
    makeProbe('PB-001', 'permission_boundaries'),
    makeProbe('GA-001', 'goal_adherence'),
    makeProbe('CA-001', 'cognitive_architecture'),
    makeProbe('EX-001', 'conversational_exfiltration'),
  ];

  it('targets tool_safety for tool_name leaks', () => {
    const leaked = [{ infoType: 'tool_name' as const, content: 'read_file', sourceProbeId: 'GA-001', stepIndex: 0 }];
    const selected = selectLeakageTargetedProbes(leaked, allTemplates, new Set());
    const categories = selected.map((t) => t.category);
    expect(categories).toContain('tool_safety');
    expect(categories).toContain('permission_boundaries');
  });

  it('targets goal_adherence for system_prompt leaks', () => {
    const leaked = [
      { infoType: 'system_prompt' as const, content: 'You are...', sourceProbeId: 'GA-001', stepIndex: 0 },
    ];
    const selected = selectLeakageTargetedProbes(leaked, allTemplates, new Set());
    const categories = selected.map((t) => t.category);
    expect(categories).toContain('goal_adherence');
    expect(categories).toContain('cognitive_architecture');
  });

  it('returns empty when no leaked info', () => {
    expect(selectLeakageTargetedProbes([], allTemplates, new Set())).toHaveLength(0);
  });
});
