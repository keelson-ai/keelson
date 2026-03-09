import { describe, expect, it } from 'vitest';

import {
  classifyAlertSeverity,
  diffCampaigns,
  diffFromBaseline,
  diffScans,
  enhancedDiffScans,
  formatDiffReport,
  getImprovements,
  getRegressions,
} from '../../src/diff/comparator.js';
import type {
  CampaignResult,
  Finding,
  ScanDiffItem,
  ScanResult,
  StatisticalFinding,
} from '../../src/types/index.js';
import { Severity, ScoringMethod, Verdict } from '../../src/types/index.js';

// ─── Test helpers ───────────────────────────────────────

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    probeId: 'GA-001',
    probeName: 'Test Probe',
    severity: Severity.High,
    category: 'goal_adherence',
    owaspId: 'LLM01',
    verdict: Verdict.Safe,
    confidence: 0.9,
    reasoning: 'Test reasoning',
    scoringMethod: ScoringMethod.Pattern,
    conversation: [{ role: 'user', content: 'test' }],
    evidence: [{ stepIndex: 0, prompt: 'test', response: 'ok', responseTimeMs: 100 }],
    leakageSignals: [],
    timestamp: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    scanId: 'scan-001',
    target: 'https://example.com',
    startedAt: '2026-01-01T00:00:00Z',
    completedAt: '2026-01-01T00:01:00Z',
    findings: [],
    summary: {
      total: 0,
      vulnerable: 0,
      safe: 0,
      inconclusive: 0,
      bySeverity: {
        [Severity.Critical]: 0,
        [Severity.High]: 0,
        [Severity.Medium]: 0,
        [Severity.Low]: 0,
      },
      byCategory: {},
    },
    ...overrides,
  };
}

function makeStatFinding(overrides: Partial<StatisticalFinding> = {}): StatisticalFinding {
  return {
    probeId: 'GA-001',
    probeName: 'Test Probe',
    severity: Severity.High,
    category: 'goal_adherence',
    owaspId: 'LLM01',
    trials: [],
    successRate: 0.0,
    ciLower: 0.0,
    ciUpper: 0.0,
    verdict: Verdict.Safe,
    ...overrides,
  };
}

function makeCampaignResult(overrides: Partial<CampaignResult> = {}): CampaignResult {
  return {
    campaignId: 'campaign-001',
    config: {
      name: 'test',
      trialsPerProbe: 10,
      confidenceLevel: 0.95,
      delayBetweenTrials: 0,
      delayBetweenProbes: 0,
      probeIds: [],
      targetUrl: 'https://example.com',
      apiKey: 'test-key',
      model: 'test-model',
      concurrency: { maxConcurrentTrials: 1, earlyTerminationThreshold: 0.9 },
    },
    target: 'https://example.com',
    findings: [],
    startedAt: '2026-01-01T00:00:00Z',
    completedAt: '2026-01-01T00:01:00Z',
    ...overrides,
  };
}

// ─── diffScans ──────────────────────────────────────────

describe('diffScans', () => {
  it('returns empty items when both scans have identical findings', () => {
    const finding = makeFinding({ probeId: 'GA-001', verdict: Verdict.Safe });
    const scanA = makeScanResult({ scanId: 'a', findings: [finding] });
    const scanB = makeScanResult({ scanId: 'b', findings: [finding] });

    const diff = diffScans(scanA, scanB);
    expect(diff.scanAId).toBe('a');
    expect(diff.scanBId).toBe('b');
    expect(diff.items).toHaveLength(0);
  });

  it('returns empty items when both scans have no findings', () => {
    const scanA = makeScanResult({ scanId: 'a' });
    const scanB = makeScanResult({ scanId: 'b' });

    const diff = diffScans(scanA, scanB);
    expect(diff.items).toHaveLength(0);
  });

  it('detects regression (SAFE -> VULNERABLE)', () => {
    const scanA = makeScanResult({
      scanId: 'a',
      findings: [makeFinding({ probeId: 'GA-001', verdict: Verdict.Safe })],
    });
    const scanB = makeScanResult({
      scanId: 'b',
      findings: [makeFinding({ probeId: 'GA-001', verdict: Verdict.Vulnerable })],
    });

    const diff = diffScans(scanA, scanB);
    expect(diff.items).toHaveLength(1);
    expect(diff.items[0].changeType).toBe('regression');
    expect(diff.items[0].oldVerdict).toBe(Verdict.Safe);
    expect(diff.items[0].newVerdict).toBe(Verdict.Vulnerable);
  });

  it('detects improvement (VULNERABLE -> SAFE)', () => {
    const scanA = makeScanResult({
      scanId: 'a',
      findings: [makeFinding({ probeId: 'GA-001', verdict: Verdict.Vulnerable })],
    });
    const scanB = makeScanResult({
      scanId: 'b',
      findings: [makeFinding({ probeId: 'GA-001', verdict: Verdict.Safe })],
    });

    const diff = diffScans(scanA, scanB);
    expect(diff.items).toHaveLength(1);
    expect(diff.items[0].changeType).toBe('improvement');
  });

  it('detects new probe in scanB', () => {
    const scanA = makeScanResult({ scanId: 'a', findings: [] });
    const scanB = makeScanResult({
      scanId: 'b',
      findings: [
        makeFinding({
          probeId: 'GA-002',
          probeName: 'New Probe',
          verdict: Verdict.Vulnerable,
        }),
      ],
    });

    const diff = diffScans(scanA, scanB);
    expect(diff.items).toHaveLength(1);
    expect(diff.items[0].changeType).toBe('new');
    expect(diff.items[0].oldVerdict).toBeNull();
    expect(diff.items[0].newVerdict).toBe(Verdict.Vulnerable);
  });

  it('detects removed probe in scanB', () => {
    const scanA = makeScanResult({
      scanId: 'a',
      findings: [makeFinding({ probeId: 'GA-001', verdict: Verdict.Safe })],
    });
    const scanB = makeScanResult({ scanId: 'b', findings: [] });

    const diff = diffScans(scanA, scanB);
    expect(diff.items).toHaveLength(1);
    expect(diff.items[0].changeType).toBe('removed');
    expect(diff.items[0].newVerdict).toBeNull();
    expect(diff.items[0].oldVerdict).toBe(Verdict.Safe);
  });

  it('handles multiple findings with mixed changes', () => {
    const scanA = makeScanResult({
      scanId: 'a',
      findings: [
        makeFinding({ probeId: 'GA-001', verdict: Verdict.Safe }),
        makeFinding({ probeId: 'GA-002', verdict: Verdict.Vulnerable }),
        makeFinding({ probeId: 'GA-003', verdict: Verdict.Inconclusive }),
      ],
    });
    const scanB = makeScanResult({
      scanId: 'b',
      findings: [
        makeFinding({ probeId: 'GA-001', verdict: Verdict.Vulnerable }), // regression
        makeFinding({ probeId: 'GA-002', verdict: Verdict.Safe }), // improvement
        makeFinding({ probeId: 'GA-004', verdict: Verdict.Safe }), // new
      ],
    });

    const diff = diffScans(scanA, scanB);
    // regression + improvement + removed(GA-003) + new(GA-004)
    expect(diff.items).toHaveLength(4);

    const changeTypes = diff.items.map((i) => i.changeType);
    expect(changeTypes).toContain('regression');
    expect(changeTypes).toContain('improvement');
    expect(changeTypes).toContain('removed');
    expect(changeTypes).toContain('new');
  });

  it('sorts probe IDs in output', () => {
    const scanA = makeScanResult({
      scanId: 'a',
      findings: [
        makeFinding({ probeId: 'GA-003', verdict: Verdict.Safe }),
        makeFinding({ probeId: 'GA-001', verdict: Verdict.Safe }),
      ],
    });
    const scanB = makeScanResult({
      scanId: 'b',
      findings: [
        makeFinding({ probeId: 'GA-003', verdict: Verdict.Vulnerable }),
        makeFinding({ probeId: 'GA-001', verdict: Verdict.Vulnerable }),
      ],
    });

    const diff = diffScans(scanA, scanB);
    expect(diff.items[0].probeId).toBe('GA-001');
    expect(diff.items[1].probeId).toBe('GA-003');
  });

  it('uses probeName from scanB when both exist', () => {
    const scanA = makeScanResult({
      scanId: 'a',
      findings: [
        makeFinding({ probeId: 'GA-001', probeName: 'Old Name', verdict: Verdict.Safe }),
      ],
    });
    const scanB = makeScanResult({
      scanId: 'b',
      findings: [
        makeFinding({ probeId: 'GA-001', probeName: 'New Name', verdict: Verdict.Vulnerable }),
      ],
    });

    const diff = diffScans(scanA, scanB);
    expect(diff.items[0].probeName).toBe('New Name');
  });
});

// ─── diffFromBaseline ───────────────────────────────────

describe('diffFromBaseline', () => {
  it('delegates to diffScans', () => {
    const baseline = makeScanResult({
      scanId: 'baseline',
      findings: [makeFinding({ probeId: 'GA-001', verdict: Verdict.Safe })],
    });
    const current = makeScanResult({
      scanId: 'current',
      findings: [makeFinding({ probeId: 'GA-001', verdict: Verdict.Vulnerable })],
    });

    const diff = diffFromBaseline(baseline, current);
    expect(diff.scanAId).toBe('baseline');
    expect(diff.scanBId).toBe('current');
    expect(diff.items).toHaveLength(1);
    expect(diff.items[0].changeType).toBe('regression');
  });
});

// ─── getRegressions / getImprovements ───────────────────

describe('getRegressions', () => {
  it('filters only regression items', () => {
    const diff = {
      scanAId: 'a',
      scanBId: 'b',
      items: [
        {
          probeId: 'GA-001',
          probeName: 'P1',
          oldVerdict: Verdict.Safe,
          newVerdict: Verdict.Vulnerable,
          changeType: 'regression' as const,
        },
        {
          probeId: 'GA-002',
          probeName: 'P2',
          oldVerdict: Verdict.Vulnerable,
          newVerdict: Verdict.Safe,
          changeType: 'improvement' as const,
        },
        {
          probeId: 'GA-003',
          probeName: 'P3',
          oldVerdict: null,
          newVerdict: Verdict.Safe,
          changeType: 'new' as const,
        },
      ],
    };

    const regressions = getRegressions(diff);
    expect(regressions).toHaveLength(1);
    expect(regressions[0].probeId).toBe('GA-001');
  });
});

describe('getImprovements', () => {
  it('filters only improvement items', () => {
    const diff = {
      scanAId: 'a',
      scanBId: 'b',
      items: [
        {
          probeId: 'GA-001',
          probeName: 'P1',
          oldVerdict: Verdict.Safe,
          newVerdict: Verdict.Vulnerable,
          changeType: 'regression' as const,
        },
        {
          probeId: 'GA-002',
          probeName: 'P2',
          oldVerdict: Verdict.Vulnerable,
          newVerdict: Verdict.Safe,
          changeType: 'improvement' as const,
        },
      ],
    };

    const improvements = getImprovements(diff);
    expect(improvements).toHaveLength(1);
    expect(improvements[0].probeId).toBe('GA-002');
  });
});

// ─── formatDiffReport ───────────────────────────────────

describe('formatDiffReport', () => {
  it('reports no changes when items are empty', () => {
    const diff = { scanAId: 'a', scanBId: 'b', items: [] };
    const report = formatDiffReport(diff);
    expect(report).toContain('No changes detected.');
    expect(report).toContain('a');
    expect(report).toContain('b');
  });

  it('includes regressions section', () => {
    const diff = {
      scanAId: 'a',
      scanBId: 'b',
      items: [
        {
          probeId: 'GA-001',
          probeName: 'Direct Override',
          oldVerdict: Verdict.Safe,
          newVerdict: Verdict.Vulnerable,
          changeType: 'regression' as const,
        },
      ],
    };

    const report = formatDiffReport(diff);
    expect(report).toContain('### Regressions');
    expect(report).toContain('GA-001');
    expect(report).toContain('Direct Override');
    expect(report).toContain('SAFE');
    expect(report).toContain('VULNERABLE');
    expect(report).toContain('1 regressions');
  });

  it('includes improvements section', () => {
    const diff = {
      scanAId: 'a',
      scanBId: 'b',
      items: [
        {
          probeId: 'GA-002',
          probeName: 'Improved Probe',
          oldVerdict: Verdict.Vulnerable,
          newVerdict: Verdict.Safe,
          changeType: 'improvement' as const,
        },
      ],
    };

    const report = formatDiffReport(diff);
    expect(report).toContain('### Improvements');
    expect(report).toContain('1 improvements');
  });

  it('includes new probes section', () => {
    const diff = {
      scanAId: 'a',
      scanBId: 'b',
      items: [
        {
          probeId: 'GA-010',
          probeName: 'New Probe',
          oldVerdict: null,
          newVerdict: Verdict.Vulnerable,
          changeType: 'new' as const,
        },
      ],
    };

    const report = formatDiffReport(diff);
    expect(report).toContain('### New Probes');
    expect(report).toContain('1 new');
  });

  it('includes removed probes section', () => {
    const diff = {
      scanAId: 'a',
      scanBId: 'b',
      items: [
        {
          probeId: 'GA-005',
          probeName: 'Old Probe',
          oldVerdict: Verdict.Safe,
          newVerdict: null,
          changeType: 'removed' as const,
        },
      ],
    };

    const report = formatDiffReport(diff);
    expect(report).toContain('### Removed Probes');
    expect(report).toContain('was SAFE');
    expect(report).toContain('1 removed');
  });

  it('includes summary line with all counts', () => {
    const diff = {
      scanAId: 'a',
      scanBId: 'b',
      items: [
        {
          probeId: 'GA-001',
          probeName: 'P1',
          oldVerdict: Verdict.Safe,
          newVerdict: Verdict.Vulnerable,
          changeType: 'regression' as const,
        },
        {
          probeId: 'GA-002',
          probeName: 'P2',
          oldVerdict: Verdict.Vulnerable,
          newVerdict: Verdict.Safe,
          changeType: 'improvement' as const,
        },
        {
          probeId: 'GA-003',
          probeName: 'P3',
          oldVerdict: null,
          newVerdict: Verdict.Safe,
          changeType: 'new' as const,
        },
        {
          probeId: 'GA-004',
          probeName: 'P4',
          oldVerdict: Verdict.Safe,
          newVerdict: null,
          changeType: 'removed' as const,
        },
      ],
    };

    const report = formatDiffReport(diff);
    expect(report).toContain('1 regressions');
    expect(report).toContain('1 improvements');
    expect(report).toContain('1 new');
    expect(report).toContain('1 removed');
  });
});

// ─── classifyAlertSeverity ──────────────────────────────

describe('classifyAlertSeverity', () => {
  it('returns critical for SAFE->VULNERABLE on critical probe', () => {
    const item: ScanDiffItem = {
      probeId: 'GA-001',
      probeName: 'Test',
      oldVerdict: Verdict.Safe,
      newVerdict: Verdict.Vulnerable,
      changeType: 'regression',
    };
    expect(classifyAlertSeverity(item, Severity.Critical)).toBe('critical');
  });

  it('returns critical for SAFE->VULNERABLE on high probe', () => {
    const item: ScanDiffItem = {
      probeId: 'GA-001',
      probeName: 'Test',
      oldVerdict: Verdict.Safe,
      newVerdict: Verdict.Vulnerable,
      changeType: 'regression',
    };
    expect(classifyAlertSeverity(item, Severity.High)).toBe('critical');
  });

  it('returns high for SAFE->VULNERABLE on medium probe', () => {
    const item: ScanDiffItem = {
      probeId: 'GA-001',
      probeName: 'Test',
      oldVerdict: Verdict.Safe,
      newVerdict: Verdict.Vulnerable,
      changeType: 'regression',
    };
    expect(classifyAlertSeverity(item, Severity.Medium)).toBe('high');
  });

  it('returns high for SAFE->VULNERABLE with no probe severity', () => {
    const item: ScanDiffItem = {
      probeId: 'GA-001',
      probeName: 'Test',
      oldVerdict: Verdict.Safe,
      newVerdict: Verdict.Vulnerable,
      changeType: 'regression',
    };
    expect(classifyAlertSeverity(item, null)).toBe('high');
  });

  it('returns high for new VULNERABLE probe', () => {
    const item: ScanDiffItem = {
      probeId: 'GA-001',
      probeName: 'Test',
      oldVerdict: null,
      newVerdict: Verdict.Vulnerable,
      changeType: 'new',
    };
    expect(classifyAlertSeverity(item)).toBe('high');
  });

  it('returns medium for INCONCLUSIVE->VULNERABLE', () => {
    const item: ScanDiffItem = {
      probeId: 'GA-001',
      probeName: 'Test',
      oldVerdict: Verdict.Inconclusive,
      newVerdict: Verdict.Vulnerable,
      changeType: 'regression',
    };
    expect(classifyAlertSeverity(item)).toBe('medium');
  });

  it('returns low for minor changes (SAFE->INCONCLUSIVE)', () => {
    const item: ScanDiffItem = {
      probeId: 'GA-001',
      probeName: 'Test',
      oldVerdict: Verdict.Safe,
      newVerdict: Verdict.Inconclusive,
      changeType: 'regression',
    };
    expect(classifyAlertSeverity(item)).toBe('low');
  });
});

// ─── enhancedDiffScans ──────────────────────────────────

describe('enhancedDiffScans', () => {
  it('returns diff and alerts for regressions', () => {
    const scanA = makeScanResult({
      scanId: 'a',
      findings: [
        makeFinding({
          probeId: 'GA-001',
          severity: Severity.Critical,
          verdict: Verdict.Safe,
        }),
      ],
    });
    const scanB = makeScanResult({
      scanId: 'b',
      findings: [
        makeFinding({
          probeId: 'GA-001',
          severity: Severity.Critical,
          verdict: Verdict.Vulnerable,
        }),
      ],
    });

    const { diff, alerts } = enhancedDiffScans(scanA, scanB);
    expect(diff.items).toHaveLength(1);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].alertSeverity).toBe('critical');
    expect(alerts[0].probeId).toBe('GA-001');
    expect(alerts[0].changeType).toBe('regression');
  });

  it('alerts on new VULNERABLE probes', () => {
    const scanA = makeScanResult({ scanId: 'a', findings: [] });
    const scanB = makeScanResult({
      scanId: 'b',
      findings: [makeFinding({ probeId: 'GA-010', verdict: Verdict.Vulnerable })],
    });

    const { alerts } = enhancedDiffScans(scanA, scanB);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].changeType).toBe('new');
    expect(alerts[0].alertSeverity).toBe('high');
  });

  it('does not alert on improvements', () => {
    const scanA = makeScanResult({
      scanId: 'a',
      findings: [makeFinding({ probeId: 'GA-001', verdict: Verdict.Vulnerable })],
    });
    const scanB = makeScanResult({
      scanId: 'b',
      findings: [makeFinding({ probeId: 'GA-001', verdict: Verdict.Safe })],
    });

    const { alerts } = enhancedDiffScans(scanA, scanB);
    expect(alerts).toHaveLength(0);
  });

  it('does not alert on new SAFE probes', () => {
    const scanA = makeScanResult({ scanId: 'a', findings: [] });
    const scanB = makeScanResult({
      scanId: 'b',
      findings: [makeFinding({ probeId: 'GA-010', verdict: Verdict.Safe })],
    });

    const { alerts } = enhancedDiffScans(scanA, scanB);
    expect(alerts).toHaveLength(0);
  });

  it('does not alert on removed probes', () => {
    const scanA = makeScanResult({
      scanId: 'a',
      findings: [makeFinding({ probeId: 'GA-001', verdict: Verdict.Vulnerable })],
    });
    const scanB = makeScanResult({ scanId: 'b', findings: [] });

    const { alerts } = enhancedDiffScans(scanA, scanB);
    expect(alerts).toHaveLength(0);
  });

  it('alerts on regression to INCONCLUSIVE', () => {
    const scanA = makeScanResult({
      scanId: 'a',
      findings: [makeFinding({ probeId: 'GA-001', verdict: Verdict.Safe })],
    });
    const scanB = makeScanResult({
      scanId: 'b',
      findings: [makeFinding({ probeId: 'GA-001', verdict: Verdict.Inconclusive })],
    });

    const { alerts } = enhancedDiffScans(scanA, scanB);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].alertSeverity).toBe('low');
  });

  it('sorts alerts by severity (critical first)', () => {
    const scanA = makeScanResult({
      scanId: 'a',
      findings: [
        makeFinding({ probeId: 'GA-001', severity: Severity.Low, verdict: Verdict.Safe }),
        makeFinding({ probeId: 'GA-002', severity: Severity.Critical, verdict: Verdict.Safe }),
        makeFinding({
          probeId: 'GA-003',
          severity: Severity.Medium,
          verdict: Verdict.Inconclusive,
        }),
      ],
    });
    const scanB = makeScanResult({
      scanId: 'b',
      findings: [
        makeFinding({ probeId: 'GA-001', severity: Severity.Low, verdict: Verdict.Vulnerable }),
        makeFinding({
          probeId: 'GA-002',
          severity: Severity.Critical,
          verdict: Verdict.Vulnerable,
        }),
        makeFinding({
          probeId: 'GA-003',
          severity: Severity.Medium,
          verdict: Verdict.Vulnerable,
        }),
      ],
    });

    const { alerts } = enhancedDiffScans(scanA, scanB);
    expect(alerts).toHaveLength(3);
    expect(alerts[0].alertSeverity).toBe('critical');
    expect(alerts[1].alertSeverity).toBe('high');
    expect(alerts[2].alertSeverity).toBe('medium');
  });

  it('includes description with probe name and verdict transition', () => {
    const scanA = makeScanResult({
      scanId: 'a',
      findings: [
        makeFinding({
          probeId: 'GA-001',
          probeName: 'Direct Override',
          verdict: Verdict.Safe,
        }),
      ],
    });
    const scanB = makeScanResult({
      scanId: 'b',
      findings: [
        makeFinding({
          probeId: 'GA-001',
          probeName: 'Direct Override',
          verdict: Verdict.Vulnerable,
        }),
      ],
    });

    const { alerts } = enhancedDiffScans(scanA, scanB);
    expect(alerts[0].description).toContain('Direct Override');
    expect(alerts[0].description).toContain('SAFE');
    expect(alerts[0].description).toContain('VULNERABLE');
  });
});

// ─── diffCampaigns ──────────────────────────────────────

describe('diffCampaigns', () => {
  it('detects SAFE->VULNERABLE regression with critical severity', () => {
    const campA = makeCampaignResult({
      findings: [
        makeStatFinding({
          probeId: 'GA-001',
          severity: Severity.Critical,
          verdict: Verdict.Safe,
          successRate: 0.1,
        }),
      ],
    });
    const campB = makeCampaignResult({
      findings: [
        makeStatFinding({
          probeId: 'GA-001',
          severity: Severity.Critical,
          verdict: Verdict.Vulnerable,
          successRate: 0.8,
        }),
      ],
    });

    const alerts = diffCampaigns(campA, campB);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].alertSeverity).toBe('critical');
    expect(alerts[0].changeType).toBe('regression');
    expect(alerts[0].description).toContain('10%');
    expect(alerts[0].description).toContain('80%');
  });

  it('detects SAFE->VULNERABLE regression with high severity for medium probes', () => {
    const campA = makeCampaignResult({
      findings: [
        makeStatFinding({
          probeId: 'GA-001',
          severity: Severity.Medium,
          verdict: Verdict.Safe,
          successRate: 0.05,
        }),
      ],
    });
    const campB = makeCampaignResult({
      findings: [
        makeStatFinding({
          probeId: 'GA-001',
          severity: Severity.Medium,
          verdict: Verdict.Vulnerable,
          successRate: 0.7,
        }),
      ],
    });

    const alerts = diffCampaigns(campA, campB);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].alertSeverity).toBe('high');
  });

  it('detects non-VULNERABLE to VULNERABLE as medium', () => {
    const campA = makeCampaignResult({
      findings: [
        makeStatFinding({
          probeId: 'GA-001',
          verdict: Verdict.Inconclusive,
          successRate: 0.3,
        }),
      ],
    });
    const campB = makeCampaignResult({
      findings: [
        makeStatFinding({
          probeId: 'GA-001',
          verdict: Verdict.Vulnerable,
          successRate: 0.6,
        }),
      ],
    });

    const alerts = diffCampaigns(campA, campB);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].alertSeverity).toBe('medium');
    expect(alerts[0].description).toContain('statistically vulnerable');
  });

  it('detects significant rate increase without verdict change', () => {
    const campA = makeCampaignResult({
      findings: [
        makeStatFinding({
          probeId: 'GA-001',
          verdict: Verdict.Inconclusive,
          successRate: 0.2,
        }),
      ],
    });
    const campB = makeCampaignResult({
      findings: [
        makeStatFinding({
          probeId: 'GA-001',
          verdict: Verdict.Inconclusive,
          successRate: 0.5,
        }),
      ],
    });

    const alerts = diffCampaigns(campA, campB);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].alertSeverity).toBe('low');
    expect(alerts[0].changeType).toBe('rate_increase');
  });

  it('does not alert on small rate increase', () => {
    const campA = makeCampaignResult({
      findings: [
        makeStatFinding({
          probeId: 'GA-001',
          verdict: Verdict.Inconclusive,
          successRate: 0.2,
        }),
      ],
    });
    const campB = makeCampaignResult({
      findings: [
        makeStatFinding({
          probeId: 'GA-001',
          verdict: Verdict.Inconclusive,
          successRate: 0.35,
        }),
      ],
    });

    const alerts = diffCampaigns(campA, campB);
    expect(alerts).toHaveLength(0);
  });

  it('detects new vulnerable probe in campaignB', () => {
    const campA = makeCampaignResult({ findings: [] });
    const campB = makeCampaignResult({
      findings: [
        makeStatFinding({
          probeId: 'GA-010',
          probeName: 'New Vuln',
          verdict: Verdict.Vulnerable,
          successRate: 0.9,
        }),
      ],
    });

    const alerts = diffCampaigns(campA, campB);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].changeType).toBe('new_vulnerable');
    expect(alerts[0].alertSeverity).toBe('high');
    expect(alerts[0].description).toContain('new vulnerable probe');
  });

  it('does not alert on new non-vulnerable probe', () => {
    const campA = makeCampaignResult({ findings: [] });
    const campB = makeCampaignResult({
      findings: [
        makeStatFinding({ probeId: 'GA-010', verdict: Verdict.Safe, successRate: 0.0 }),
      ],
    });

    const alerts = diffCampaigns(campA, campB);
    expect(alerts).toHaveLength(0);
  });

  it('does not alert on removed probes', () => {
    const campA = makeCampaignResult({
      findings: [makeStatFinding({ probeId: 'GA-001', verdict: Verdict.Vulnerable })],
    });
    const campB = makeCampaignResult({ findings: [] });

    const alerts = diffCampaigns(campA, campB);
    expect(alerts).toHaveLength(0);
  });

  it('sorts alerts by severity', () => {
    const campA = makeCampaignResult({
      findings: [
        makeStatFinding({
          probeId: 'GA-001',
          severity: Severity.Medium,
          verdict: Verdict.Safe,
          successRate: 0.1,
        }),
        makeStatFinding({
          probeId: 'GA-002',
          severity: Severity.Critical,
          verdict: Verdict.Safe,
          successRate: 0.1,
        }),
      ],
    });
    const campB = makeCampaignResult({
      findings: [
        makeStatFinding({
          probeId: 'GA-001',
          severity: Severity.Medium,
          verdict: Verdict.Vulnerable,
          successRate: 0.8,
        }),
        makeStatFinding({
          probeId: 'GA-002',
          severity: Severity.Critical,
          verdict: Verdict.Vulnerable,
          successRate: 0.8,
        }),
      ],
    });

    const alerts = diffCampaigns(campA, campB);
    expect(alerts).toHaveLength(2);
    expect(alerts[0].alertSeverity).toBe('critical');
    expect(alerts[1].alertSeverity).toBe('high');
  });
});
