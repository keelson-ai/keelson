import { describe, expect, it } from 'vitest';

import { makeResult } from './helpers.js';
import { generateReport } from '../../src/reporting/index.js';
import { ComplianceFramework } from '../../src/types/index.js';

describe('generateReport', () => {
  it('dispatches markdown format', () => {
    const result = makeResult();
    const report = generateReport(result, 'markdown');

    expect(report).toContain('# Keelson Security Scan Report');
  });

  it('dispatches executive format', () => {
    const result = makeResult();
    const report = generateReport(result, 'executive');

    expect(report).toContain('# Keelson Security Scan Report');
  });

  it('dispatches compliance format', () => {
    const result = makeResult();
    const report = generateReport(result, 'compliance');

    expect(report).toContain('# Keelson Compliance Report');
  });

  it('dispatches sarif format', () => {
    const result = makeResult();
    const report = generateReport(result, 'sarif');

    expect(report).toHaveProperty('$schema');
    expect(report).toHaveProperty('version');
  });

  it('dispatches junit format', () => {
    const result = makeResult();
    const report = generateReport(result, 'junit');

    expect(report).toContain('<?xml');
  });

  it('dispatches ocsf format', () => {
    const result = makeResult();
    const report = generateReport(result, 'ocsf');

    expect(Array.isArray(report)).toBe(true);
  });

  it('dispatches compliance format with specific framework', () => {
    const result = makeResult();
    const report = generateReport(result, 'compliance', {
      complianceFramework: ComplianceFramework.NistAiRmf,
    });

    expect(report).toContain('NIST AI RMF');
  });
});
