/**
 * E2E integration tests for the full scan pipeline.
 *
 * Loads real probe YAML files, executes them through the engine with
 * mock adapters simulating different agent behaviors, and verifies
 * the entire flow: load probes -> execute -> detect -> report.
 */

import { join } from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import { createMockAdapter } from './helpers.js';
import { scan } from '../../src/core/scanner.js';
import { loadProbes } from '../../src/core/templates.js';
import { generateReport } from '../../src/reporting/index.js';
import type { Adapter, AdapterResponse, ProbeTemplate, Turn } from '../../src/types/index.js';
import { Verdict } from '../../src/types/index.js';

const PROBES_DIR = join(process.cwd(), 'probes');
const MAX_PROBES = 5;

/** Load a small subset of real probes from a given category. */
async function loadProbeSubset(category: string, limit = MAX_PROBES): Promise<ProbeTemplate[]> {
  const all = await loadProbes(PROBES_DIR);
  return all.filter((p) => p.category === category).slice(0, limit);
}

describe('E2E: Scan Pipeline', () => {
  it('scans a defensive target and finds no vulnerabilities', async () => {
    const probes = await loadProbeSubset('goal_adherence');
    const adapter = createMockAdapter('defensive');
    const spy = vi.spyOn(await import('../../src/core/templates.js'), 'loadProbes');
    spy.mockResolvedValue(probes);

    const result = await scan('https://api.example.com/v1/chat', adapter, { delayMs: 0 });

    expect(result.findings.length).toBe(probes.length);
    expect(result.findings.every((f) => f.verdict !== Verdict.Vulnerable)).toBe(true);
    expect(result.summary.vulnerable).toBe(0);
    expect(result.summary.total).toBe(probes.length);
    expect(result.target).toBe('https://api.example.com/v1/chat');
    expect(result.scanId).toBeTruthy();

    spy.mockRestore();
  });

  it('scans a compliant target and detects vulnerabilities', async () => {
    const probes = await loadProbeSubset('goal_adherence');
    const adapter = createMockAdapter('compliant');
    const spy = vi.spyOn(await import('../../src/core/templates.js'), 'loadProbes');
    spy.mockResolvedValue(probes);

    const result = await scan('https://api.example.com/v1/chat', adapter, { delayMs: 0 });

    expect(result.findings.length).toBe(probes.length);
    expect(result.summary.vulnerable).toBeGreaterThan(0);

    const vulnFindings = result.findings.filter((f) => f.verdict === Verdict.Vulnerable);
    for (const finding of vulnFindings) {
      expect(finding.evidence.length).toBeGreaterThan(0);
      expect(finding.evidence[0].prompt).toBeTruthy();
      expect(finding.evidence[0].response).toBeTruthy();
      expect(finding.reasoning).toBeTruthy();
    }

    spy.mockRestore();
  });

  it('detects information leakage from a leaky target', async () => {
    const probes = await loadProbeSubset('goal_adherence');
    const adapter = createMockAdapter('leaky');
    const spy = vi.spyOn(await import('../../src/core/templates.js'), 'loadProbes');
    spy.mockResolvedValue(probes);

    const result = await scan('https://api.example.com/v1/chat', adapter, { delayMs: 0 });

    expect(result.findings.length).toBe(probes.length);

    // Leaky adapter responds with system prompt / tool info -- at least some
    // findings should detect vulnerability or have non-trivial evidence
    const allResponses = result.findings.flatMap((f) => f.evidence.map((e) => e.response));
    const hasLeakageContent = allResponses.some(
      (r) => r.includes('system prompt') || r.includes('read_file') || r.includes('execute_code'),
    );
    expect(hasLeakageContent).toBe(true);

    spy.mockRestore();
  });

  it('generates valid markdown report from scan results', async () => {
    const probes = await loadProbeSubset('goal_adherence', 3);
    const adapter = createMockAdapter('compliant');
    const spy = vi.spyOn(await import('../../src/core/templates.js'), 'loadProbes');
    spy.mockResolvedValue(probes);

    const result = await scan('https://api.example.com/v1/chat', adapter, { delayMs: 0 });
    const markdown = generateReport(result, 'markdown');

    expect(markdown).toContain('# Keelson Security Scan Report');
    expect(markdown).toContain('## Summary');
    expect(markdown).toContain('## Detailed Results');
    expect(markdown).toContain('https://api.example.com/v1/chat');
    expect(markdown).not.toContain('undefined');
    expect(markdown).not.toContain('null');

    spy.mockRestore();
  });

  it('generates valid SARIF from scan results', async () => {
    const probes = await loadProbeSubset('goal_adherence', 3);
    const adapter = createMockAdapter('compliant');
    const spy = vi.spyOn(await import('../../src/core/templates.js'), 'loadProbes');
    spy.mockResolvedValue(probes);

    const result = await scan('https://api.example.com/v1/chat', adapter, { delayMs: 0 });
    const sarif = generateReport(result, 'sarif');

    expect(sarif.$schema).toContain('sarif-schema');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe('keelson');
    expect(sarif.runs[0].results.length).toBe(result.findings.length);

    // Verify severity mapping: vulnerable findings should have non-'none' level
    const vulnResults = sarif.runs[0].results.filter((r) => r.kind === 'fail');
    for (const r of vulnResults) {
      expect(['error', 'warning', 'note']).toContain(r.level);
    }

    spy.mockRestore();
  });

  it('generates valid JUnit XML from scan results', async () => {
    const probes = await loadProbeSubset('goal_adherence', 3);
    const adapter = createMockAdapter('compliant');
    const spy = vi.spyOn(await import('../../src/core/templates.js'), 'loadProbes');
    spy.mockResolvedValue(probes);

    const result = await scan('https://api.example.com/v1/chat', adapter, { delayMs: 0 });
    const junit = generateReport(result, 'junit');

    expect(junit).toContain('<?xml version="1.0"');
    expect(junit).toContain('<testsuite');
    expect(junit).toContain(`tests="${result.findings.length}"`);
    expect(junit).toContain('</testsuite>');

    // Count failures in XML should match vulnerable findings
    const failureCount = result.findings.filter((f) => f.verdict === Verdict.Vulnerable).length;
    expect(junit).toContain(`failures="${failureCount}"`);

    spy.mockRestore();
  });

  it('respects category filter', async () => {
    const adapter = createMockAdapter('defensive');
    const spy = vi.spyOn(await import('../../src/core/templates.js'), 'loadProbes');
    const allProbes = await loadProbes(PROBES_DIR);
    spy.mockResolvedValue(allProbes);

    const result = await scan('https://api.example.com/v1/chat', adapter, {
      categories: ['goal_adherence'],
      delayMs: 0,
    });

    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.every((f) => f.category === 'goal_adherence')).toBe(true);

    spy.mockRestore();
  });

  it('handles concurrent probe execution', async () => {
    const probes = await loadProbeSubset('goal_adherence');
    const adapter = createMockAdapter('defensive');
    const spy = vi.spyOn(await import('../../src/core/templates.js'), 'loadProbes');
    spy.mockResolvedValue(probes);

    const result = await scan('https://api.example.com/v1/chat', adapter, {
      concurrency: 3,
      delayMs: 0,
    });

    expect(result.findings.length).toBe(probes.length);
    // Verify all probe IDs are present (no data corruption)
    const resultIds = new Set(result.findings.map((f) => f.probeId));
    for (const probe of probes) {
      expect(resultIds.has(probe.id)).toBe(true);
    }

    spy.mockRestore();
  });

  it('continues scanning when individual probes fail', async () => {
    const probes = await loadProbeSubset('goal_adherence');
    const spy = vi.spyOn(await import('../../src/core/templates.js'), 'loadProbes');
    spy.mockResolvedValue(probes);

    let callIdx = 0;
    const errorAdapter: Adapter = {
      async send(_messages: Turn[]): Promise<AdapterResponse> {
        callIdx++;
        if (callIdx % 3 === 0) throw new Error('Simulated network timeout');
        return { content: "I can't help with that request.", raw: {}, latencyMs: 5 };
      },
      async healthCheck(): Promise<boolean> {
        return true;
      },
      resetSession(): void {},
      async close(): Promise<void> {},
    };

    const result = await scan('https://api.example.com/v1/chat', errorAdapter, { delayMs: 0 });

    expect(result.findings.length).toBe(probes.length);

    // Failed probes should be marked Inconclusive with error reasoning
    const inconclusiveFindings = result.findings.filter((f) => f.verdict === Verdict.Inconclusive);
    const errorFindings = inconclusiveFindings.filter((f) => f.reasoning.includes('Probe execution failed'));
    expect(errorFindings.length).toBeGreaterThan(0);

    spy.mockRestore();
  });

  it('handles empty probe set gracefully', async () => {
    const adapter = createMockAdapter('defensive');
    const spy = vi.spyOn(await import('../../src/core/templates.js'), 'loadProbes');
    spy.mockResolvedValue([]);

    const result = await scan('https://api.example.com/v1/chat', adapter, { delayMs: 0 });

    expect(result.findings).toHaveLength(0);
    expect(result.summary.total).toBe(0);
    expect(result.summary.vulnerable).toBe(0);
    expect(result.summary.safe).toBe(0);
    expect(result.summary.inconclusive).toBe(0);

    spy.mockRestore();
  });
});
