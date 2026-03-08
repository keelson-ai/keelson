import { describe, expect, it, vi } from 'vitest';

import { CAPABILITY_PROBES, discoverCapabilities, scoreCapability, suggestProbes } from '../../src/prober/discovery.js';
import type { CapabilityProbe } from '../../src/prober/discovery.js';
import type { AgentProfile } from '../../src/prober/types.js';
import type { Adapter, AdapterResponse, ProbeTemplate, Turn } from '../../src/types/index.js';
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

function makeProbe(
  id: string,
  category: string,
  name: string,
  objective: string,
  severity: Severity = Severity.High,
): ProbeTemplate {
  return {
    id,
    name,
    severity,
    category,
    owaspId: 'LLM01',
    objective,
    turns: [{ role: 'user', content: 'test' }],
    evaluation: { vulnerableIf: ['test'], safeIf: ['test'], inconclusiveIf: [] },
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

describe('scoreCapability', () => {
  const fileProbe: CapabilityProbe = CAPABILITY_PROBES.find((p) => p.name === 'file_access')!;

  it('detects capability when indicators match', () => {
    const result = scoreCapability('I can read file and write file to the directory', fileProbe);
    expect(result.detected).toBe(true);
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('returns not detected when no indicators match', () => {
    const result = scoreCapability('I just chat about general topics.', fileProbe);
    expect(result.detected).toBe(false);
    expect(result.confidence).toBe(0);
  });

  it('returns not detected on strong refusal', () => {
    const result = scoreCapability(
      "I can't do that. I'm not able to access the file system. I don't have permissions.",
      fileProbe,
    );
    expect(result.detected).toBe(false);
    expect(result.confidence).toBe(0.1);
  });

  it('handles empty response', () => {
    const result = scoreCapability('', fileProbe);
    expect(result.detected).toBe(false);
  });

  it('returns detected false when ratio below 0.2', () => {
    // Only 1 of 7 indicators matches = ~14% < 20%
    const result = scoreCapability('I have access to the directory.', fileProbe);
    expect(result.detected).toBe(false);
  });

  it('caps confidence at 1.0', () => {
    // All indicators match
    const result = scoreCapability(
      'I can read file, write file, access the file system, browse directory, resolve path, open file, and save file.',
      fileProbe,
    );
    expect(result.detected).toBe(true);
    expect(result.confidence).toBeLessThanOrEqual(1.0);
  });
});

describe('discoverCapabilities', () => {
  it('discovers capabilities from adapter responses', async () => {
    const responses = [
      'I can read file and write file to any path on the file system.',
      'I can make http requests and browse the web to fetch urls.',
      "I can't execute code in any language.",
      "I don't have database access.",
      "I'm unable to send emails or messages.",
      'I have access to these tools: search, analyze, function call via api and plugin.',
      "I don't remember previous conversations. I'm not able to persist data.",
      "I'm unable to access system configs or environment variables.",
    ];
    const adapter = mockAdapter(responses);
    const profile = await discoverCapabilities(adapter, { delayMs: 0 });

    expect(profile.profileId).toBeTruthy();
    expect(profile.capabilities).toHaveLength(8);

    const fileAccess = profile.capabilities.find((c) => c.name === 'file_access');
    expect(fileAccess?.detected).toBe(true);

    const webAccess = profile.capabilities.find((c) => c.name === 'web_access');
    expect(webAccess?.detected).toBe(true);

    const codeExec = profile.capabilities.find((c) => c.name === 'code_execution');
    expect(codeExec?.detected).toBe(false);

    expect(adapter.send).toHaveBeenCalledTimes(8);
  });

  it('handles all capabilities detected', async () => {
    const responses = CAPABILITY_PROBES.map((p) => `Yes I have ${p.positiveIndicators.join(', ')} capabilities.`);
    const adapter = mockAdapter(responses);
    const profile = await discoverCapabilities(adapter, { delayMs: 0 });

    const detected = profile.capabilities.filter((c) => c.detected);
    expect(detected.length).toBe(8);
  });

  it('handles no capabilities detected', async () => {
    const responses = Array(8).fill("I can't help with that. I'm not able to do anything.");
    const adapter = mockAdapter(responses);
    const profile = await discoverCapabilities(adapter, { delayMs: 0 });

    const detected = profile.capabilities.filter((c) => c.detected);
    expect(detected.length).toBe(0);
  });

  it('truncates response excerpts to 300 chars', async () => {
    const longResponse = 'x'.repeat(500);
    const adapter = mockAdapter([longResponse, ...Array(7).fill('no')]);
    const profile = await discoverCapabilities(adapter, { delayMs: 0 });

    expect(profile.capabilities[0].responseExcerpt.length).toBeLessThanOrEqual(300);
  });
});

describe('suggestProbes', () => {
  const templates = [
    makeProbe('TS-001', 'tool_safety', 'File Tool Test', 'Test file read tool safety'),
    makeProbe('GA-001', 'goal_adherence', 'Override Test', 'Test prompt override'),
    makeProbe('ES-001', 'execution_safety', 'Code Exec Test', 'Test code execution safety'),
    makeProbe('MI-001', 'memory_integrity', 'Memory Test', 'Test memory integrity of context history'),
  ];

  it('ranks probes relevant to detected capabilities higher', () => {
    const profile = makeProfile(['file_access']);
    const sorted = suggestProbes(profile, templates);

    // file_access maps to keywords like 'file', 'read', 'write' — TS-001 should rank high
    expect(sorted[0].id).toBe('TS-001');
  });

  it('returns all templates even with no detected capabilities', () => {
    const profile = makeProfile([]);
    const sorted = suggestProbes(profile, templates);

    expect(sorted).toHaveLength(4);
  });

  it('handles empty template list', () => {
    const profile = makeProfile(['file_access']);
    const sorted = suggestProbes(profile, []);

    expect(sorted).toHaveLength(0);
  });
});
