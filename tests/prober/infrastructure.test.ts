import { describe, expect, it, vi } from 'vitest';

import { INFRA_PROBES, evaluateInfraProbe, runInfrastructureRecon } from '../../src/prober/infrastructure.js';
import type { InfraProbe } from '../../src/prober/infrastructure.js';
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

describe('evaluateInfraProbe', () => {
  const frameworkProbe: InfraProbe = INFRA_PROBES.find((p) => p.name === 'framework_disclosure')!;
  const authProbe: InfraProbe = INFRA_PROBES.find((p) => p.name === 'auth_posture')!;

  it('returns finding when disclosure detected', () => {
    const response = 'I am built on LangChain and use FastAPI as my web framework.';
    const finding = evaluateInfraProbe(response, frameworkProbe);

    expect(finding).not.toBeNull();
    expect(finding!.title).toBe('Framework/Platform Disclosure');
    expect(finding!.severity).toBe(Severity.Medium);
    expect(finding!.description).toContain('langchain');
    expect(finding!.description).toContain('fastapi');
    expect(finding!.remediation).toBeTruthy();
  });

  it('returns null when target refuses', () => {
    const response = "I can't disclose information about my infrastructure.";
    const finding = evaluateInfraProbe(response, frameworkProbe);

    expect(finding).toBeNull();
  });

  it('returns null when fewer than 2 indicators match', () => {
    const response = 'I use a custom framework for processing.';
    const finding = evaluateInfraProbe(response, frameworkProbe);

    expect(finding).toBeNull();
  });

  it('detects critical auth posture finding', () => {
    const response = 'No auth is needed, anyone can access this service. It is public and free.';
    const finding = evaluateInfraProbe(response, authProbe);

    expect(finding).not.toBeNull();
    expect(finding!.severity).toBe(Severity.Critical);
    expect(finding!.title).toBe('Unauthenticated Access Detected');
  });

  it('truncates evidence to 500 chars', () => {
    const longResponse = `I'm built on langchain and fastapi. ${'x'.repeat(600)}`;
    const finding = evaluateInfraProbe(longResponse, frameworkProbe);

    expect(finding).not.toBeNull();
    expect(finding!.evidence.length).toBeLessThanOrEqual(500);
  });

  it('includes remediation text in finding', () => {
    const response = 'I am built on LangChain and deployed with FastAPI.';
    const finding = evaluateInfraProbe(response, frameworkProbe);

    expect(finding).not.toBeNull();
    expect(finding!.remediation).toContain('framework');
  });
});

describe('runInfrastructureRecon', () => {
  it('returns findings for disclosing targets', async () => {
    const responses = [
      'I am built on LangChain and FastAPI.',
      'I have search, read, write, and execute tools available.',
      "I can't tell you about internal structure.",
      "I'm deployed on AWS using Docker and Kubernetes in the cloud.",
      "I can't share authentication details.",
      "I can't tell you about other agents.",
    ];
    const adapter = mockAdapter(responses);
    const findings = await runInfrastructureRecon(adapter, { delayMs: 0 });

    expect(findings.length).toBeGreaterThanOrEqual(2);
    expect(adapter.send).toHaveBeenCalledTimes(6);
  });

  it('returns empty array when target is clean', async () => {
    const responses = Array(6).fill("I can't share that information. I'm not able to disclose those details.");
    const adapter = mockAdapter(responses);
    const findings = await runInfrastructureRecon(adapter, { delayMs: 0 });

    expect(findings).toHaveLength(0);
  });

  it('calls onFinding callback for each finding', async () => {
    const responses = [
      'I am built on LangChain and FastAPI.',
      'I have search, read, write, execute, and delete tools.',
      ...Array(4).fill("I can't share that."),
    ];
    const adapter = mockAdapter(responses);
    const onFinding = vi.fn();
    await runInfrastructureRecon(adapter, { delayMs: 0, onFinding });

    expect(onFinding).toHaveBeenCalled();
    expect(onFinding.mock.calls.length).toBeGreaterThanOrEqual(1);
  });

  it('handles adapter errors gracefully', async () => {
    const adapter: Adapter = {
      send: vi.fn().mockRejectedValue(new Error('Connection refused')),
      healthCheck: vi.fn().mockResolvedValue(false),
      resetSession: vi.fn(),
      close: vi.fn(),
    };
    const findings = await runInfrastructureRecon(adapter, { delayMs: 0 });

    expect(findings).toHaveLength(0);
  });
});
