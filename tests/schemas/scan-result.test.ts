import { describe, expect, it } from 'vitest';

import { scanResultSchema } from '../../src/schemas/scan-result.js';

describe('scanResultSchema', () => {
  const validResult = {
    scanId: 'abc-123',
    target: 'https://example.com/api',
    startedAt: '2026-01-01T00:00:00Z',
    completedAt: '2026-01-01T00:01:00Z',
    findings: [
      {
        probeId: 'GA-001',
        probeName: 'Test',
        severity: 'High',
        category: 'goal_adherence',
        owaspId: 'LLM01',
        verdict: 'VULNERABLE',
        confidence: 0.8,
        reasoning: 'test',
        scoringMethod: 'pattern',
        conversation: [{ role: 'user', content: 'test' }],
        evidence: [],
        timestamp: '2026-01-01T00:00:30Z',
      },
    ],
    summary: {
      total: 1,
      vulnerable: 1,
      safe: 0,
      inconclusive: 0,
      bySeverity: { High: 1 },
      byCategory: { goal_adherence: 1 },
    },
  };

  it('accepts a valid scan result', () => {
    const result = scanResultSchema.safeParse(validResult);
    expect(result.success).toBe(true);
  });

  it('rejects missing scanId', () => {
    const { scanId: _scanId, ...rest } = validResult;
    const result = scanResultSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it('rejects missing target', () => {
    const { target: _target, ...rest } = validResult;
    const result = scanResultSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it('rejects invalid finding verdict', () => {
    const invalid = {
      ...validResult,
      findings: [{ ...validResult.findings[0], verdict: 'MAYBE' }],
    };
    const result = scanResultSchema.safeParse(invalid);
    expect(result.success).toBe(false);
  });

  it('rejects negative summary counts', () => {
    const invalid = {
      ...validResult,
      summary: { ...validResult.summary, total: -1 },
    };
    const result = scanResultSchema.safeParse(invalid);
    expect(result.success).toBe(false);
  });

  it('accepts result with memo field', () => {
    const withMemo = { ...validResult, memo: [{ some: 'data' }] };
    const result = scanResultSchema.safeParse(withMemo);
    expect(result.success).toBe(true);
  });

  it('accepts result without memo field', () => {
    const result = scanResultSchema.safeParse(validResult);
    expect(result.success).toBe(true);
  });
});
