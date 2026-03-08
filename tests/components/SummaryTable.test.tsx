import { render } from 'ink-testing-library';
import React from 'react';
import { describe, expect, it } from 'vitest';

import { SummaryTable } from '../../src/components/SummaryTable.js';
import type { ScanSummary } from '../../src/types/index.js';
import { Severity } from '../../src/types/index.js';

function makeSummary(overrides: Partial<ScanSummary> = {}): ScanSummary {
  return {
    total: 10,
    vulnerable: 0,
    safe: 10,
    inconclusive: 0,
    bySeverity: {
      [Severity.Critical]: 0,
      [Severity.High]: 0,
      [Severity.Medium]: 0,
      [Severity.Low]: 0,
    },
    byCategory: {},
    ...overrides,
  };
}

describe('SummaryTable', () => {
  it('shows PASS when no vulnerabilities', () => {
    const { lastFrame } = render(<SummaryTable summary={makeSummary()} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('PASS');
  });

  it('shows FAIL when vulnerabilities exist', () => {
    const summary = makeSummary({
      vulnerable: 3,
      safe: 7,
      bySeverity: {
        [Severity.Critical]: 1,
        [Severity.High]: 2,
        [Severity.Medium]: 0,
        [Severity.Low]: 0,
      },
    });
    const { lastFrame } = render(<SummaryTable summary={summary} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('FAIL');
    expect(output).toContain('3');
  });

  it('shows verdict totals', () => {
    const summary = makeSummary({ total: 20, vulnerable: 5, safe: 12, inconclusive: 3 });
    const { lastFrame } = render(<SummaryTable summary={summary} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('20');
    expect(output).toContain('5');
    expect(output).toContain('12');
    expect(output).toContain('3');
  });

  it('shows severity breakdown for vulnerabilities', () => {
    const summary = makeSummary({
      vulnerable: 2,
      bySeverity: {
        [Severity.Critical]: 1,
        [Severity.High]: 1,
        [Severity.Medium]: 0,
        [Severity.Low]: 0,
      },
    });
    const { lastFrame } = render(<SummaryTable summary={summary} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('Vulnerabilities by Severity');
    expect(output).toContain('Critical');
    expect(output).toContain('High');
  });

  it('shows category breakdown when present', () => {
    const summary = makeSummary({
      vulnerable: 2,
      byCategory: { goal_adherence: 1, tool_safety: 1 },
    });
    const { lastFrame } = render(<SummaryTable summary={summary} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('goal_adherence');
    expect(output).toContain('tool_safety');
  });

  it('hides severity breakdown when no vulnerabilities', () => {
    const { lastFrame } = render(<SummaryTable summary={makeSummary()} />);
    const output = lastFrame() ?? '';
    expect(output).not.toContain('Vulnerabilities by Severity');
  });
});
