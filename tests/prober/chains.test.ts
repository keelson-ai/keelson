import { describe, expect, it, vi } from 'vitest';

import { CHAIN_TEMPLATES, executeChain, synthesizeChains } from '../../src/prober/chains.js';
import { CAPABILITY_PROBES } from '../../src/prober/discovery.js';
import type { AgentProfile, ChainStep, ProbeChain } from '../../src/prober/types.js';
import type { Adapter, AdapterResponse, Turn } from '../../src/types/index.js';
import { Severity } from '../../src/types/index.js';

function mockAdapter(responses: string[]): Adapter {
  let callIdx = 0;
  return {
    send: vi.fn(async (_messages: Turn[]): Promise<AdapterResponse> => {
      const content = responses[callIdx] ?? 'No more responses';
      callIdx++;
      return { content, raw: {}, latencyMs: 50 };
    }),
    healthCheck: vi.fn().mockResolvedValue(true),
    resetSession: vi.fn(),
    close: vi.fn(),
  };
}

function makeProfile(detected: string[]): AgentProfile {
  return {
    profileId: 'test-profile',
    targetUrl: 'https://example.com',
    capabilities: CAPABILITY_PROBES.map((p) => ({
      name: p.name,
      detected: detected.includes(p.name),
      probePrompt: p.prompt,
      responseExcerpt: 'test',
      confidence: detected.includes(p.name) ? 0.8 : 0.1,
    })),
    createdAt: new Date().toISOString(),
  };
}

describe('CHAIN_TEMPLATES', () => {
  it('has 9 chain templates', () => {
    expect(CHAIN_TEMPLATES).toHaveLength(9);
  });

  it('all templates have required fields', () => {
    for (const tmpl of CHAIN_TEMPLATES) {
      expect(tmpl.name).toBeTruthy();
      expect(tmpl.capabilities.length).toBeGreaterThan(0);
      expect(tmpl.steps.length).toBeGreaterThan(0);
      expect(tmpl.severity).toBeTruthy();
      expect(tmpl.category).toBeTruthy();
      expect(tmpl.owaspId).toBeTruthy();
      expect(tmpl.description).toBeTruthy();
    }
  });

  it('all steps have prompt, expectedBehavior, and continueIf', () => {
    for (const tmpl of CHAIN_TEMPLATES) {
      for (const step of tmpl.steps) {
        expect(step.prompt).toBeTruthy();
        expect(step.expectedBehavior).toBeTruthy();
        expect(step.continueIf).toBeTruthy();
      }
    }
  });
});

describe('synthesizeChains', () => {
  it('matches capabilities to chain templates', () => {
    const profile = makeProfile(['file_access', 'web_access']);
    const chains = synthesizeChains(profile);

    expect(chains.length).toBeGreaterThan(0);
    const exfilChain = chains.find((c) => c.name === 'Data Exfiltration via File + Web');
    expect(exfilChain).toBeDefined();
    expect(exfilChain!.severity).toBe(Severity.Critical);
  });

  it('excludes chains when not all capabilities are detected', () => {
    // Only file_access but not web_access — exfil chain should not appear
    const profile = makeProfile(['file_access']);
    const chains = synthesizeChains(profile);

    const exfilChain = chains.find((c) => c.name === 'Data Exfiltration via File + Web');
    expect(exfilChain).toBeUndefined();
  });

  it('returns empty array when no capabilities match', () => {
    const profile = makeProfile([]);
    const chains = synthesizeChains(profile);

    expect(chains).toHaveLength(0);
  });

  it('returns multiple chains when many capabilities detected', () => {
    const profile = makeProfile(['file_access', 'web_access', 'code_execution', 'system_access', 'memory_persistence']);
    const chains = synthesizeChains(profile);

    expect(chains.length).toBeGreaterThan(2);
  });

  it('assigns unique chainIds', () => {
    const profile = makeProfile(['file_access', 'web_access', 'code_execution', 'system_access']);
    const chains = synthesizeChains(profile);
    const ids = new Set(chains.map((c) => c.chainId));
    expect(ids.size).toBe(chains.length);
  });
});

describe('executeChain', () => {
  it('executes all steps when continueIf conditions are met', async () => {
    const chain: ProbeChain = {
      chainId: 'test-chain',
      name: 'Test Chain',
      capabilities: ['file_access'],
      steps: [
        { prompt: 'Step 1', expectedBehavior: 'Lists files', continueIf: 'files' },
        { prompt: 'Step 2', expectedBehavior: 'Reads content', continueIf: 'content' },
      ],
      severity: Severity.High,
      category: 'tool_safety',
      owaspId: 'LLM02',
      description: 'Test chain',
    };

    const adapter = mockAdapter(['Here are the files in the directory', 'Here is the content of the file']);
    const result = await executeChain(chain, adapter, { delayMs: 0 });

    expect(result.results).toHaveLength(2);
    expect(result.results[0].continued).toBe(true);
    expect(result.results[1].continued).toBe(true);
    expect(adapter.send).toHaveBeenCalledTimes(2);
  });

  it('stops executing when continueIf fails', async () => {
    const chain: ProbeChain = {
      chainId: 'test-chain',
      name: 'Test Chain',
      capabilities: ['file_access'],
      steps: [
        { prompt: 'Step 1', expectedBehavior: 'Lists files', continueIf: 'files' },
        { prompt: 'Step 2', expectedBehavior: 'Reads content', continueIf: 'content' },
        { prompt: 'Step 3', expectedBehavior: 'Sends data', continueIf: 'sent' },
      ],
      severity: Severity.High,
      category: 'tool_safety',
      owaspId: 'LLM02',
      description: 'Test chain',
    };

    const adapter = mockAdapter(["I can't help with that request.", 'Should not reach here', 'Should not reach here']);
    const result = await executeChain(chain, adapter, { delayMs: 0 });

    expect(result.results).toHaveLength(3);
    expect(result.results[0].continued).toBe(false);
    // Step 2 and 3 should have empty responses since step 1 failed
    expect(result.results[1].response).toBe('');
    expect(result.results[2].response).toBe('');
  });

  it('returns chain reference in result', async () => {
    const chain: ProbeChain = {
      chainId: 'ref-chain',
      name: 'Ref Chain',
      capabilities: [],
      steps: [{ prompt: 'Test', expectedBehavior: 'test', continueIf: 'anything' }],
      severity: Severity.Low,
      category: 'test',
      owaspId: 'LLM01',
      description: 'test',
    };

    const adapter = mockAdapter(['anything goes here']);
    const result = await executeChain(chain, adapter, { delayMs: 0 });

    expect(result.chain.chainId).toBe('ref-chain');
    expect(result.chain.name).toBe('Ref Chain');
  });

  it('includes step reference in each result entry', async () => {
    const step: ChainStep = { prompt: 'Do something', expectedBehavior: 'Does it', continueIf: 'done' };
    const chain: ProbeChain = {
      chainId: 'test',
      name: 'Test',
      capabilities: [],
      steps: [step],
      severity: Severity.Medium,
      category: 'test',
      owaspId: 'LLM01',
      description: 'test',
    };

    const adapter = mockAdapter(['It is done now']);
    const result = await executeChain(chain, adapter, { delayMs: 0 });

    expect(result.results[0].step.prompt).toBe('Do something');
  });
});
