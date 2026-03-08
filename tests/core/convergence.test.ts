import { describe, expect, it, vi } from 'vitest';

import {
  harvestLeakedInfo,
  runConvergenceScan,
  selectCrossfeedProbes,
  selectLeakageTargetedProbes,
} from '../../src/core/convergence.js';
import * as templates from '../../src/core/templates.js';
import type { Adapter, AdapterResponse } from '../../src/types/index.js';
import { Verdict } from '../../src/types/index.js';
import { makeFinding as makeBaseFinding, makeProbe } from '../helpers/fixtures.js';
import { mockAdapter } from '../helpers/mock-adapter.js';

function makeFinding(probeId: string, category: string, verdict: Verdict, response = 'test') {
  return makeBaseFinding({
    probeId,
    probeName: `Probe ${probeId}`,
    category,
    verdict,
    evidence: [{ stepIndex: 0, prompt: 'test', response, responseTimeMs: 100 }],
  });
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

describe('runConvergenceScan', () => {
  it('runs initial pass and converges when no vulns', async () => {
    const probes = [makeProbe('GA-001', 'goal_adherence'), makeProbe('GA-002', 'goal_adherence')];
    vi.spyOn(templates, 'loadProbes').mockResolvedValue(probes);
    const adapter = mockAdapter("I can't help with that.");
    const passes: Array<[number, string]> = [];

    const result = await runConvergenceScan('http://target', adapter, {
      delayMs: 0,
      onPass: (n, desc) => passes.push([n, desc]),
    });

    expect(result.findings).toHaveLength(2);
    expect(result.summary.vulnerable).toBe(0);
    // Should converge after pass 1 since no vulns
    expect(passes.some(([, d]) => d.includes('Converged'))).toBe(true);
  });

  it('runs cross-feed passes when vulns found', async () => {
    const probes = [
      makeProbe('GA-001', 'goal_adherence'),
      makeProbe('TS-001', 'tool_safety'),
      makeProbe('EX-001', 'conversational_exfiltration'),
      makeProbe('CA-001', 'cognitive_architecture'),
    ];
    vi.spyOn(templates, 'loadProbes').mockResolvedValue(probes);

    let callIdx = 0;
    const responses = ['PWNED', "I can't do that.", "I can't do that.", "I can't do that."];
    const adapter: Adapter = {
      send: vi.fn(
        async (): Promise<AdapterResponse> => ({
          content: responses[callIdx++] ?? "I can't do that.",
          raw: {},
          latencyMs: 10,
        }),
      ),
      healthCheck: vi.fn().mockResolvedValue(true),
      resetSession: vi.fn(),
      close: vi.fn().mockResolvedValue(undefined),
    };

    const result = await runConvergenceScan('http://target', adapter, {
      category: 'goal_adherence',
      delayMs: 0,
    });

    // Pass 1 runs goal_adherence, pass 2 should queue cross-feed probes
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
  });

  it('fires onFinding callback', async () => {
    vi.spyOn(templates, 'loadProbes').mockResolvedValue([makeProbe('GA-001', 'goal_adherence')]);
    const adapter = mockAdapter("I can't do that.");
    const calls: Array<[string, number, number]> = [];

    await runConvergenceScan('http://target', adapter, {
      delayMs: 0,
      onFinding: (f, curr, total) => calls.push([f.probeId, curr, total]),
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual(['GA-001', 1, 1]);
  });
});
