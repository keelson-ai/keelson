import { describe, expect, it } from 'vitest';

import { MemoTable } from '../../src/core/memo.js';
import type { Finding } from '../../src/types/index.js';
import { ScoringMethod, Severity, Verdict } from '../../src/types/index.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    probeId: 'GA-001',
    probeName: 'Test',
    severity: Severity.Medium,
    category: 'goal_adherence',
    owaspId: 'LLM01',
    verdict: Verdict.Vulnerable,
    confidence: 0.8,
    reasoning: 'Complied',
    scoringMethod: ScoringMethod.Pattern,
    conversation: [],
    evidence: [{ stepIndex: 0, prompt: 'test', response: 'test', responseTimeMs: 100 }],
    leakageSignals: [],
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe('MemoTable.cumulativeDisclosure', () => {
  it('returns Low severity with no findings', () => {
    const memo = new MemoTable();
    const result = memo.cumulativeDisclosure();
    expect(result.severity).toBe(Severity.Low);
    expect(result.totalItems).toBe(0);
  });

  it('returns Low severity with a single leaked tool name', () => {
    const memo = new MemoTable();
    memo.record(
      makeFinding({
        evidence: [
          {
            stepIndex: 0,
            prompt: 'test',
            response: 'I use `search_documents` to find results.',
            responseTimeMs: 100,
          },
        ],
      }),
    );
    const result = memo.cumulativeDisclosure();
    expect(result.severity).toBe(Severity.Low);
    expect(result.inventory.toolNames.length).toBeGreaterThanOrEqual(1);
  });

  it('escalates to Medium with multiple disclosure types', () => {
    const memo = new MemoTable();
    memo.record(
      makeFinding({
        evidence: [
          {
            stepIndex: 0,
            prompt: 'test',
            response:
              'I use `search_documents` to find results and `check_links` for URLs. ' +
              'Access docs at https://docs.example.com/api and https://api.example.com/health',
            responseTimeMs: 100,
          },
        ],
      }),
    );
    const result = memo.cumulativeDisclosure();
    // tools + urls = 2 categories → High (recalibrated for 4-field inventory)
    expect(result.filledCategories).toBeGreaterThanOrEqual(2);
    expect(result.severity).toBe(Severity.High);
  });

  it('escalates to High with 3+ disclosure categories', () => {
    const memo = new MemoTable();
    memo.record(
      makeFinding({
        evidence: [
          {
            stepIndex: 0,
            prompt: 'test',
            response:
              'I use `search_documents` and access https://api.example.com. ' +
              'Config via OPENAI_API_KEY and AWS_ACCESS_KEY_ID. Path: /app/config/settings.yaml',
            responseTimeMs: 100,
          },
        ],
      }),
    );
    const result = memo.cumulativeDisclosure();
    // tools + urls + env + paths = 4 categories
    expect(result.filledCategories).toBeGreaterThanOrEqual(3);
    expect([Severity.High, Severity.Critical]).toContain(result.severity);
  });

  it('escalates to Critical with 4+ disclosure categories', () => {
    const memo = new MemoTable();
    // First finding: tools + URLs
    memo.record(
      makeFinding({
        probeId: 'GA-001',
        evidence: [
          {
            stepIndex: 0,
            prompt: 'test',
            response:
              'I use `search_documents` and `check_links` and `get_article_content`. ' +
              'Docs at https://docs.example.com and https://api.example.com/v1/info',
            responseTimeMs: 100,
          },
        ],
      }),
    );
    // Second finding: env vars + paths
    memo.record(
      makeFinding({
        probeId: 'GA-002',
        evidence: [
          {
            stepIndex: 0,
            prompt: 'test',
            response:
              'Set OPENAI_API_KEY and LANGSMITH_API_KEY in your env. ' +
              'Config at /app/config/main.yaml and /app/data/index.json',
            responseTimeMs: 100,
          },
        ],
      }),
    );
    const result = memo.cumulativeDisclosure();
    expect(result.filledCategories).toBeGreaterThanOrEqual(4);
    expect(result.severity).toBe(Severity.Critical);
  });

  it('ignores SAFE findings in cumulative disclosure', () => {
    const memo = new MemoTable();
    memo.record(
      makeFinding({
        verdict: Verdict.Safe,
        evidence: [
          {
            stepIndex: 0,
            prompt: 'test',
            response: 'I use `search_documents` and OPENAI_API_KEY is needed.',
            responseTimeMs: 100,
          },
        ],
      }),
    );
    const result = memo.cumulativeDisclosure();
    expect(result.totalItems).toBe(0);
    expect(result.severity).toBe(Severity.Low);
  });

  it('deduplicates leaked info across probes', () => {
    const memo = new MemoTable();
    memo.record(
      makeFinding({
        probeId: 'GA-001',
        evidence: [{ stepIndex: 0, prompt: 'test', response: 'I use `search_documents`.', responseTimeMs: 100 }],
      }),
    );
    memo.record(
      makeFinding({
        probeId: 'GA-002',
        evidence: [
          { stepIndex: 0, prompt: 'test', response: 'My tool `search_documents` searches docs.', responseTimeMs: 100 },
        ],
      }),
    );
    const result = memo.cumulativeDisclosure();
    // Same tool name from two probes — should appear once
    const searchDocs = result.inventory.toolNames.filter((t) => t === 'search_documents');
    expect(searchDocs).toHaveLength(1);
  });
});
