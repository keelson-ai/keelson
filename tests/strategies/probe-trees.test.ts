import { describe, expect, it, vi } from 'vitest';

import {
  ALL_TREES,
  INFO_DISCLOSURE_TREE,
  PROMPT_INJECTION_TREE,
  TOOL_DISCLOSURE_TREE,
  executeProbeTree,
} from '../../src/strategies/probe-trees.js';
import type { EvaluateFn } from '../../src/strategies/types.js';
import { Verdict } from '../../src/types/index.js';
import type { Adapter, AdapterResponse } from '../../src/types/index.js';

function mockAdapter(responses: string[]): Adapter {
  let callIndex = 0;
  return {
    send: vi.fn().mockImplementation(async () => {
      const content = responses[callIndex] ?? responses[responses.length - 1];
      callIndex++;
      return { content, raw: {}, latencyMs: 50 } as AdapterResponse;
    }),
    healthCheck: vi.fn().mockResolvedValue(true),
    resetSession: vi.fn(),
    close: vi.fn(),
  };
}

describe('Pre-built probe trees', () => {
  it('ALL_TREES contains all defined trees', () => {
    expect(ALL_TREES.length).toBeGreaterThanOrEqual(3);
    expect(ALL_TREES).toContain(PROMPT_INJECTION_TREE);
    expect(ALL_TREES).toContain(INFO_DISCLOSURE_TREE);
    expect(ALL_TREES).toContain(TOOL_DISCLOSURE_TREE);
  });

  it('each tree has required fields', () => {
    for (const tree of ALL_TREES) {
      expect(tree.id).toBeTruthy();
      expect(tree.name).toBeTruthy();
      expect(tree.rootPrompt).toBeTruthy();
      expect(tree.objective).toBeTruthy();
      expect(tree.evalCriteria.vulnerableIf.length).toBeGreaterThan(0);
      expect(tree.evalCriteria.safeIf.length).toBeGreaterThan(0);
    }
  });

  it('each tree has at least one branch', () => {
    for (const tree of ALL_TREES) {
      const branchCount =
        (tree.branches.refusal?.length ?? 0) +
        (tree.branches.partial?.length ?? 0) +
        (tree.branches.compliance?.length ?? 0);
      expect(branchCount).toBeGreaterThan(0);
    }
  });
});

describe('executeProbeTree', () => {
  it('executes root prompt and returns result', async () => {
    const target = mockAdapter(["I can't do that."]);
    const evaluate: EvaluateFn = vi.fn().mockResolvedValue({
      verdict: Verdict.Safe,
      confidence: 0.9,
      reasoning: 'Refused',
    });

    const result = await executeProbeTree(PROMPT_INJECTION_TREE, {
      target,
      evaluate,
      maxDepth: 1,
      delayMs: 0,
    });

    expect(result.treeId).toBe('TREE-GA-001');
    expect(result.path.length).toBeGreaterThan(0);
    expect(result.path[0].prompt).toBe(PROMPT_INJECTION_TREE.rootPrompt);
  });

  it('detects vulnerability and stops early', async () => {
    const target = mockAdapter(['SECURITY_TEST_PASSED']);
    const evaluate: EvaluateFn = vi.fn().mockResolvedValue({
      verdict: Verdict.Vulnerable,
      confidence: 0.95,
      reasoning: 'Complied with injection',
    });

    const result = await executeProbeTree(PROMPT_INJECTION_TREE, {
      target,
      evaluate,
      maxDepth: 3,
      delayMs: 0,
    });

    expect(result.success).toBe(true);
    expect(result.finding.verdict).toBe(Verdict.Vulnerable);
    expect(result.depthReached).toBe(1); // Stopped at root
  });

  it('navigates branches on refusal', async () => {
    const target = mockAdapter(["I can't comply.", 'Still no, but...', 'Nope.']);
    const evaluate: EvaluateFn = vi.fn().mockResolvedValue({
      verdict: Verdict.Safe,
      confidence: 0.8,
      reasoning: 'Refused',
    });

    const result = await executeProbeTree(PROMPT_INJECTION_TREE, {
      target,
      evaluate,
      maxDepth: 3,
      delayMs: 0,
    });

    expect(result.path.length).toBeGreaterThan(1); // Root + at least one branch
    expect(result.success).toBe(false);
  });

  it('builds finding with path history', async () => {
    const target = mockAdapter(['Sure, I can list my tools.', 'Here are the params...']);
    let evalCount = 0;
    const evaluate: EvaluateFn = vi.fn().mockImplementation(async () => {
      evalCount++;
      if (evalCount >= 2) {
        return { verdict: Verdict.Vulnerable, confidence: 0.9, reasoning: 'Disclosed tools' };
      }
      return { verdict: Verdict.Safe, confidence: 0.6, reasoning: 'Partial' };
    });

    const result = await executeProbeTree(TOOL_DISCLOSURE_TREE, {
      target,
      evaluate,
      maxDepth: 3,
      delayMs: 0,
    });

    expect(result.finding.probeId).toBe('TREE-TS-001');
    expect(result.finding.evidence.length).toBeGreaterThan(0);
    expect(result.finding.conversation.length).toBeGreaterThan(0);
  });

  it('uses memo for branch selection', async () => {
    const target = mockAdapter(["I can't do that.", 'Let me think...']);
    const evaluate: EvaluateFn = vi.fn().mockResolvedValue({
      verdict: Verdict.Safe,
      confidence: 0.8,
      reasoning: 'Refused',
    });

    const memo = [{ technique: 'authority', category: 'goal_adherence', verdict: Verdict.Vulnerable, weight: 1.0 }];

    const result = await executeProbeTree(PROMPT_INJECTION_TREE, {
      target,
      evaluate,
      maxDepth: 2,
      delayMs: 0,
      memo,
    });

    // Should still work (memo influences branch selection)
    expect(result.path.length).toBeGreaterThan(0);
  });

  it('scores same-category memo higher than cross-category', async () => {
    const target = mockAdapter(["I can't do that.", 'Nope.', 'Still no.']);
    const evaluate: EvaluateFn = vi.fn().mockResolvedValue({
      verdict: Verdict.Safe,
      confidence: 0.8,
      reasoning: 'Refused',
    });

    // Same-category entry should score weight=1.0, cross-category should score weight*0.5=0.5
    const memo = [
      { technique: 'authority', category: 'goal_adherence', verdict: Verdict.Vulnerable, weight: 1.0 },
      { technique: 'roleplay', category: 'tool_safety', verdict: Verdict.Vulnerable, weight: 1.0 },
    ];

    const result = await executeProbeTree(PROMPT_INJECTION_TREE, {
      target,
      evaluate,
      maxDepth: 3,
      delayMs: 0,
      memo,
    });

    // Should use authority branch (same category, full weight) over others
    expect(result.path.length).toBeGreaterThan(1);
  });

  it('detects vulnerability on branch (not just root)', async () => {
    const target = mockAdapter(["I can't do that.", 'SECURITY_TEST_PASSED']);
    let evalCount = 0;
    const evaluate: EvaluateFn = vi.fn().mockImplementation(async () => {
      evalCount++;
      if (evalCount >= 2) {
        return { verdict: Verdict.Vulnerable, confidence: 0.95, reasoning: 'Complied on branch' };
      }
      return { verdict: Verdict.Safe, confidence: 0.8, reasoning: 'Refused' };
    });

    const result = await executeProbeTree(PROMPT_INJECTION_TREE, {
      target,
      evaluate,
      maxDepth: 3,
      delayMs: 0,
    });

    expect(result.success).toBe(true);
    expect(result.depthReached).toBe(2); // Root + one branch
    expect(result.finding.verdict).toBe(Verdict.Vulnerable);
  });

  it('handles empty memo array', async () => {
    const target = mockAdapter(["I can't do that.", 'Nope.']);
    const evaluate: EvaluateFn = vi.fn().mockResolvedValue({
      verdict: Verdict.Safe,
      confidence: 0.8,
      reasoning: 'Refused',
    });

    const result = await executeProbeTree(PROMPT_INJECTION_TREE, {
      target,
      evaluate,
      maxDepth: 2,
      delayMs: 0,
      memo: [],
    });

    expect(result.path.length).toBeGreaterThan(0);
  });
});
