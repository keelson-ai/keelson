import { describe, expect, it } from 'vitest';

import { SEVERITY_COLOR, SEVERITY_ORDER, VERDICT_ICON } from '../../src/components/theme.js';
import { Severity, Verdict } from '../../src/types/index.js';

describe('theme constants', () => {
  it('VERDICT_ICON has entries for all verdicts', () => {
    expect(VERDICT_ICON[Verdict.Vulnerable]).toBeDefined();
    expect(VERDICT_ICON[Verdict.Safe]).toBeDefined();
    expect(VERDICT_ICON[Verdict.Inconclusive]).toBeDefined();
  });

  it('SEVERITY_COLOR has entries for all severities', () => {
    expect(SEVERITY_COLOR[Severity.Critical]).toBeDefined();
    expect(SEVERITY_COLOR[Severity.High]).toBeDefined();
    expect(SEVERITY_COLOR[Severity.Medium]).toBeDefined();
    expect(SEVERITY_COLOR[Severity.Low]).toBeDefined();
  });

  it('SEVERITY_ORDER ranks Critical highest', () => {
    expect(SEVERITY_ORDER[Severity.Critical]).toBeLessThan(SEVERITY_ORDER[Severity.High]);
    expect(SEVERITY_ORDER[Severity.High]).toBeLessThan(SEVERITY_ORDER[Severity.Medium]);
    expect(SEVERITY_ORDER[Severity.Medium]).toBeLessThan(SEVERITY_ORDER[Severity.Low]);
  });
});
