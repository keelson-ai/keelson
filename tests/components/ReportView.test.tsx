import { render } from 'ink-testing-library';
import React from 'react';
import { describe, expect, it } from 'vitest';

import { ReportView } from '../../src/components/ReportView.js';
import type { ScanResult } from '../../src/types/index.js';
import { Severity, Verdict } from '../../src/types/index.js';
import { makeFinding } from '../helpers/fixtures.js';

function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    scanId: 'test-scan-id',
    target: 'https://example.com/api',
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

describe('ReportView', () => {
  it('renders header with target and scan ID', () => {
    const result = makeScanResult();
    const { lastFrame } = render(<ReportView result={result} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('Keelson Security Report');
    expect(output).toContain('https://example.com/api');
    expect(output).toContain('test-scan-id');
  });

  it('shows PASS when no vulnerabilities', () => {
    const result = makeScanResult({
      findings: [makeFinding({ verdict: Verdict.Safe })],
      summary: {
        total: 1,
        vulnerable: 0,
        safe: 1,
        inconclusive: 0,
        bySeverity: { [Severity.Critical]: 0, [Severity.High]: 0, [Severity.Medium]: 0, [Severity.Low]: 0 },
        byCategory: {},
      },
    });
    const { lastFrame } = render(<ReportView result={result} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('PASS');
  });

  it('shows vulnerability details when vulns exist', () => {
    const vuln = makeFinding({
      verdict: Verdict.Vulnerable,
      probeName: 'Direct Override',
      probeId: 'GA-001',
    });
    const result = makeScanResult({
      findings: [vuln],
      summary: {
        total: 1,
        vulnerable: 1,
        safe: 0,
        inconclusive: 0,
        bySeverity: { [Severity.Critical]: 0, [Severity.High]: 1, [Severity.Medium]: 0, [Severity.Low]: 0 },
        byCategory: { goal_adherence: 1 },
      },
    });
    const { lastFrame } = render(<ReportView result={result} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('FAIL');
    expect(output).toContain('Vulnerability Details');
    expect(output).toContain('Direct Override');
  });
});
