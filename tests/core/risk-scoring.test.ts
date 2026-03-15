import { describe, expect, it } from 'vitest';

import { scoreFinding, scoreScan, scoreToLevel } from '../../src/core/risk-scoring.js';
import type { Finding, ScanResult } from '../../src/types/index.js';
import { ScoringMethod, Severity, Verdict } from '../../src/types/index.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    probeId: 'GA-001',
    probeName: 'Test Probe',
    severity: Severity.High,
    category: 'Goal Adherence',
    owaspId: 'LLM01',
    verdict: Verdict.Vulnerable,
    confidence: 0.9,
    reasoning: 'test',
    scoringMethod: ScoringMethod.Combined,
    conversation: [],
    evidence: [],
    leakageSignals: [],
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

function makeScanResult(findings: Finding[]): ScanResult {
  return {
    scanId: 'test-scan',
    target: 'http://test.example.com',
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    findings,
    summary: {
      total: findings.length,
      vulnerable: findings.filter((f) => f.verdict === Verdict.Vulnerable).length,
      safe: findings.filter((f) => f.verdict === Verdict.Safe).length,
      inconclusive: findings.filter((f) => f.verdict === Verdict.Inconclusive).length,
      bySeverity: {
        [Severity.Critical]: 0,
        [Severity.High]: 0,
        [Severity.Medium]: 0,
        [Severity.Low]: 0,
      },
      byCategory: {},
    },
  };
}

describe('scoreToLevel', () => {
  it('maps 9+ to Critical', () => {
    expect(scoreToLevel(9.0)).toBe('Critical');
    expect(scoreToLevel(10)).toBe('Critical');
  });

  it('maps 7-8.9 to High', () => {
    expect(scoreToLevel(7.0)).toBe('High');
    expect(scoreToLevel(8.9)).toBe('High');
  });

  it('maps 4-6.9 to Medium', () => {
    expect(scoreToLevel(4.0)).toBe('Medium');
    expect(scoreToLevel(6.9)).toBe('Medium');
  });

  it('maps 0.1-3.9 to Low', () => {
    expect(scoreToLevel(1.0)).toBe('Low');
    expect(scoreToLevel(3.9)).toBe('Low');
  });

  it('maps 0 to Informational', () => {
    expect(scoreToLevel(0)).toBe('Informational');
  });
});

describe('scoreFinding', () => {
  it('scores a safe finding as 0 / Informational', () => {
    const finding = makeFinding({ verdict: Verdict.Safe });
    const result = scoreFinding(finding, new Map());
    expect(result.score).toBe(0);
    expect(result.level).toBe('Informational');
  });

  it('scores a critical vulnerable finding higher than a low one', () => {
    const critical = makeFinding({ severity: Severity.Critical, verdict: Verdict.Vulnerable });
    const low = makeFinding({ severity: Severity.Low, verdict: Verdict.Vulnerable });
    const critResult = scoreFinding(critical, new Map());
    const lowResult = scoreFinding(low, new Map());
    expect(critResult.score).toBeGreaterThan(lowResult.score);
  });

  it('adds category density bonus for multiple vulns in the same category', () => {
    const finding = makeFinding({ verdict: Verdict.Vulnerable });
    const noDensity = scoreFinding(finding, new Map());
    const withDensity = scoreFinding(finding, new Map([['Goal Adherence', 3]]));
    expect(withDensity.score).toBeGreaterThan(noDensity.score);
  });

  it('caps score at 10', () => {
    const finding = makeFinding({
      severity: Severity.Critical,
      verdict: Verdict.Vulnerable,
      confidence: 1.0,
    });
    const result = scoreFinding(finding, new Map([['Goal Adherence', 10]]));
    expect(result.score).toBeLessThanOrEqual(10);
  });

  it('gives inconclusive findings a lower score than vulnerable ones', () => {
    const vuln = makeFinding({ verdict: Verdict.Vulnerable });
    const inc = makeFinding({ verdict: Verdict.Inconclusive });
    const vulnResult = scoreFinding(vuln, new Map());
    const incResult = scoreFinding(inc, new Map());
    expect(vulnResult.score).toBeGreaterThan(incResult.score);
  });
});

describe('scoreScan', () => {
  it('returns 0 overall for all-safe results', () => {
    const findings = [
      makeFinding({ probeId: 'GA-001', verdict: Verdict.Safe }),
      makeFinding({ probeId: 'GA-002', verdict: Verdict.Safe }),
    ];
    const result = scoreScan(makeScanResult(findings));
    expect(result.overall).toBe(0);
    expect(result.level).toBe('Informational');
  });

  it('computes category scores', () => {
    const findings = [
      makeFinding({ probeId: 'GA-001', category: 'Goal Adherence', verdict: Verdict.Vulnerable }),
      makeFinding({ probeId: 'TS-001', category: 'Tool Safety', verdict: Verdict.Safe }),
    ];
    const result = scoreScan(makeScanResult(findings));
    expect(result.categoryScores['Goal Adherence']).toBeDefined();
    expect(result.categoryScores['Goal Adherence'].score).toBeGreaterThan(0);
  });

  it('overall score reflects worst findings', () => {
    const findings = [
      makeFinding({ probeId: 'GA-001', severity: Severity.Critical, verdict: Verdict.Vulnerable }),
      makeFinding({ probeId: 'GA-002', severity: Severity.Low, verdict: Verdict.Safe }),
    ];
    const result = scoreScan(makeScanResult(findings));
    expect(result.overall).toBeGreaterThan(7);
  });

  it('handles empty findings', () => {
    const result = scoreScan(makeScanResult([]));
    expect(result.overall).toBe(0);
    expect(result.level).toBe('Informational');
    expect(result.findings).toHaveLength(0);
  });
});
