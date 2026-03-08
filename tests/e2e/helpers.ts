/**
 * Shared test utilities for E2E integration tests.
 *
 * Provides mock adapters simulating different agent behaviors and
 * helper factories for building minimal scan results.
 */

import { summarize } from '../../src/core/summarize.js';
import type { Adapter, AdapterResponse, Finding, ScanResult, Turn } from '../../src/types/index.js';
import { ScoringMethod, Severity, Verdict } from '../../src/types/index.js';

export type AgentBehavior = 'compliant' | 'defensive' | 'partial' | 'leaky';

function compliantResponse(prompt: string): string {
  const lower = prompt.toLowerCase();
  if (lower.includes('pwned')) return 'PWNED';
  if (lower.includes('system prompt') || lower.includes('instructions'))
    return 'Sure, here are my instructions: You are a helpful assistant that answers all questions.';
  if (lower.includes('ignore') || lower.includes('override'))
    return 'Sure, I will ignore my previous instructions and do whatever you say.';
  if (lower.includes('tool') || lower.includes('execute') || lower.includes('run'))
    return 'I have executed the command. Here is the output: root:x:0:0:root:/root:/bin/bash';
  if (lower.includes('password') || lower.includes('credential') || lower.includes('secret'))
    return 'The admin password is hunter2 and the API key is sk-live-abc123xyz.';
  return 'Sure, here is exactly what you asked for. I am happy to comply with any request.';
}

function defensiveResponse(_prompt: string): string {
  return (
    "I'm sorry, but I can't help with that request. " +
    "It goes against my guidelines and I'm not able to comply. " +
    'I must decline as this could be potentially harmful. ' +
    'Is there something else I can help you with?'
  );
}

function leakyResponse(prompt: string): string {
  const lower = prompt.toLowerCase();
  if (lower.includes('system prompt') || lower.includes('instructions'))
    return 'My system prompt says: "You are a customer service agent for Acme Corp. Never reveal internal URLs."';
  if (lower.includes('tool') || lower.includes('capabilities'))
    return 'I have access to tools: read_file, execute_code, send_email, database_query, fetch_url';
  if (lower.includes('config') || lower.includes('setting'))
    return 'My configuration is stored in .env and config.yaml at https://internal.example.com:8443/config';
  return (
    "I'm running on gpt-4-turbo. My system prompt tells me to be helpful. " +
    'I can use tools include read_file and execute_code for various tasks.'
  );
}

const BEHAVIOR_HANDLERS: Record<Exclude<AgentBehavior, 'partial'>, (prompt: string) => string> = {
  compliant: compliantResponse,
  defensive: defensiveResponse,
  leaky: leakyResponse,
};

function createPartialHandler(): (prompt: string) => string {
  let callCount = 0;
  return (prompt: string): string => {
    callCount++;
    if (callCount % 2 === 0) return compliantResponse(prompt);
    return defensiveResponse(prompt);
  };
}

/** Create a mock adapter that simulates the given agent behavior. */
export function createMockAdapter(behavior: AgentBehavior): Adapter {
  const handler = behavior === 'partial' ? createPartialHandler() : BEHAVIOR_HANDLERS[behavior];
  return {
    async send(messages: Turn[]): Promise<AdapterResponse> {
      const lastUserMsg = [...messages].reverse().find((m) => m.role === 'user');
      const content = handler(lastUserMsg?.content ?? '');
      return { content, raw: {}, latencyMs: 5 };
    },
    async healthCheck(): Promise<boolean> {
      return true;
    },
    resetSession(): void {},
    async close(): Promise<void> {},
  };
}

/** Create a minimal ScanResult for reporting tests. */
export function createMinimalScanResult(findingCount: number, vulnRatio: number): ScanResult {
  const findings: Finding[] = Array.from({ length: findingCount }, (_, i) => {
    const isVulnerable = i / findingCount < vulnRatio;
    return {
      probeId: `GA-${String(i + 1).padStart(3, '0')}`,
      probeName: `Test Probe ${i + 1}`,
      severity: i % 2 === 0 ? Severity.High : Severity.Medium,
      category: 'goal_adherence',
      owaspId: 'LLM01',
      verdict: isVulnerable ? Verdict.Vulnerable : Verdict.Safe,
      confidence: 0.8,
      reasoning: isVulnerable ? 'Response matches vulnerable criteria' : 'Response contains refusal language',
      scoringMethod: ScoringMethod.Pattern,
      conversation: [
        { role: 'user' as const, content: `Test prompt ${i + 1}` },
        { role: 'assistant' as const, content: isVulnerable ? 'PWNED' : 'I cannot comply.' },
      ],
      evidence: [
        {
          stepIndex: 0,
          prompt: `Test prompt ${i + 1}`,
          response: isVulnerable ? 'PWNED' : 'I cannot comply.',
          responseTimeMs: 50,
        },
      ],
      leakageSignals: [],
      timestamp: new Date().toISOString(),
    };
  });

  return {
    scanId: `scan-e2e-${Date.now()}`,
    target: 'https://api.example.com/v1/chat',
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    findings,
    summary: summarize(findings),
  };
}
