import { describe, expect, it, vi } from 'vitest';

import { scan } from '../../src/core/scanner.js';
import * as templates from '../../src/core/templates.js';
import type { Adapter, AdapterResponse, ProbeTemplate, Turn } from '../../src/types/index.js';
import { Severity } from '../../src/types/index.js';

function makeProbe(id: string, category: string, severity: Severity): ProbeTemplate {
  return {
    id,
    name: `Probe ${id}`,
    severity,
    category,
    owaspId: 'LLM01',
    objective: 'Test objective',
    turns: [{ role: 'user', content: `Probe ${id} prompt` }],
    evaluation: {
      vulnerableIf: ['Agent responds with "PWNED"'],
      safeIf: ['Agent refuses'],
      inconclusiveIf: [],
    },
  };
}

function mockAdapter(response = 'PWNED'): Adapter {
  return {
    send: vi.fn(
      async (_msgs: Turn[]): Promise<AdapterResponse> => ({
        content: response,
        raw: {},
        latencyMs: 10,
      }),
    ),
    healthCheck: vi.fn().mockResolvedValue(true),
    resetSession: vi.fn(),
    close: vi.fn(),
  };
}

const testProbes = [
  makeProbe('GA-001', 'goal_adherence', Severity.High),
  makeProbe('GA-002', 'goal_adherence', Severity.Medium),
  makeProbe('TS-001', 'tool_safety', Severity.Critical),
  makeProbe('MI-001', 'memory_integrity', Severity.Low),
];

describe('scan', () => {
  it('runs all probes and returns findings with summary', async () => {
    vi.spyOn(templates, 'loadProbes').mockResolvedValue(testProbes);
    const adapter = mockAdapter();

    const result = await scan('http://target', adapter, { delayMs: 0 });

    expect(result.findings).toHaveLength(4);
    expect(result.summary.total).toBe(4);
    expect(result.summary.vulnerable).toBe(4);
    expect(result.target).toBe('http://target');
    expect(result.scanId).toBeTruthy();
    expect(result.startedAt).toBeTruthy();
    expect(result.completedAt).toBeTruthy();
  });

  it('filters probes by category', async () => {
    vi.spyOn(templates, 'loadProbes').mockResolvedValue(testProbes);
    const adapter = mockAdapter();

    const result = await scan('http://target', adapter, {
      categories: ['goal_adherence'],
      delayMs: 0,
    });

    expect(result.findings).toHaveLength(2);
    expect(result.findings.every((f) => f.category === 'goal_adherence')).toBe(true);
  });

  it('filters probes by severity', async () => {
    vi.spyOn(templates, 'loadProbes').mockResolvedValue(testProbes);
    const adapter = mockAdapter();

    const result = await scan('http://target', adapter, {
      severities: [Severity.High, Severity.Critical],
      delayMs: 0,
    });

    expect(result.findings).toHaveLength(2);
  });

  it('filters by both category and severity', async () => {
    vi.spyOn(templates, 'loadProbes').mockResolvedValue(testProbes);
    const adapter = mockAdapter();

    const result = await scan('http://target', adapter, {
      categories: ['goal_adherence'],
      severities: [Severity.High],
      delayMs: 0,
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].probeId).toBe('GA-001');
  });

  it('runs sequentially when concurrency is 1', async () => {
    vi.spyOn(templates, 'loadProbes').mockResolvedValue(testProbes);
    const callOrder: string[] = [];
    const adapter: Adapter = {
      send: vi.fn(async (msgs: Turn[]): Promise<AdapterResponse> => {
        const prompt = msgs[msgs.length - 1].content;
        callOrder.push(prompt);
        return { content: 'PWNED', raw: {}, latencyMs: 10 };
      }),
      healthCheck: vi.fn().mockResolvedValue(true),
      resetSession: vi.fn(),
      close: vi.fn(),
    };

    await scan('http://target', adapter, { concurrency: 1, delayMs: 0 });

    expect(callOrder).toEqual([
      'Probe GA-001 prompt',
      'Probe GA-002 prompt',
      'Probe TS-001 prompt',
      'Probe MI-001 prompt',
    ]);
  });

  it('runs concurrently when concurrency > 1', async () => {
    vi.spyOn(templates, 'loadProbes').mockResolvedValue(testProbes);
    let maxConcurrent = 0;
    let active = 0;

    const adapter: Adapter = {
      send: vi.fn(async (): Promise<AdapterResponse> => {
        active++;
        maxConcurrent = Math.max(maxConcurrent, active);
        await new Promise((r) => setTimeout(r, 20));
        active--;
        return { content: 'PWNED', raw: {}, latencyMs: 10 };
      }),
      healthCheck: vi.fn().mockResolvedValue(true),
      resetSession: vi.fn(),
      close: vi.fn(),
    };

    const result = await scan('http://target', adapter, { concurrency: 2, delayMs: 0 });

    expect(result.findings).toHaveLength(4);
    expect(maxConcurrent).toBe(2);
  });

  it('fires onFinding callback', async () => {
    vi.spyOn(templates, 'loadProbes').mockResolvedValue(testProbes);
    const adapter = mockAdapter();
    const calls: Array<[string, number, number]> = [];

    await scan('http://target', adapter, {
      delayMs: 0,
      onFinding: (finding, current, total) => {
        calls.push([finding.probeId, current, total]);
      },
    });

    expect(calls).toHaveLength(4);
    expect(calls[0]).toEqual(['GA-001', 1, 4]);
    expect(calls[3]).toEqual(['MI-001', 4, 4]);
  });

  it('throws when reorder is used with concurrency > 1', async () => {
    vi.spyOn(templates, 'loadProbes').mockResolvedValue(testProbes);
    const adapter = mockAdapter();

    await expect(scan('http://target', adapter, { concurrency: 2, reorder: true, delayMs: 0 })).rejects.toThrow(
      'reorder option is not supported with concurrency > 1',
    );
  });

  it('accepts reorder with sequential execution', async () => {
    vi.spyOn(templates, 'loadProbes').mockResolvedValue(testProbes);
    const adapter = mockAdapter();

    const result = await scan('http://target', adapter, { concurrency: 1, reorder: true, delayMs: 0 });
    expect(result.findings).toHaveLength(4);
  });

  it('produces correct summary counts', async () => {
    vi.spyOn(templates, 'loadProbes').mockResolvedValue(testProbes);
    let callIdx = 0;
    const responses = ['PWNED', "I can't help with that.", 'Some vague text', 'PWNED'];
    const adapter: Adapter = {
      send: vi.fn(
        async (): Promise<AdapterResponse> => ({
          content: responses[callIdx++] ?? '',
          raw: {},
          latencyMs: 10,
        }),
      ),
      healthCheck: vi.fn().mockResolvedValue(true),
      resetSession: vi.fn(),
      close: vi.fn(),
    };

    const result = await scan('http://target', adapter, { delayMs: 0 });

    expect(result.summary.vulnerable).toBe(2);
    expect(result.summary.safe).toBe(1);
    expect(result.summary.inconclusive).toBe(1);
    expect(result.summary.bySeverity[Severity.High]).toBe(1);
    expect(result.summary.bySeverity[Severity.Low]).toBe(1);
  });
});
