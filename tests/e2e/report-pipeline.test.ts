/**
 * E2E integration tests for the report generation pipeline.
 *
 * Verifies that all report formats (markdown, SARIF, JUnit, compliance,
 * executive) produce valid output from realistic scan results.
 */

import { describe, expect, it } from 'vitest';

import { createMinimalScanResult } from './helpers.js';
import { generateReport } from '../../src/reporting/index.js';
import { ComplianceFramework, Verdict } from '../../src/types/index.js';

describe('E2E: Report Pipeline', () => {
  const mixedResult = createMinimalScanResult(6, 0.5);
  const allVulnResult = createMinimalScanResult(4, 1.0);
  const emptyResult = createMinimalScanResult(0, 0);

  it('markdown report contains all sections', () => {
    const report = generateReport(mixedResult, 'markdown');

    expect(report).toContain('# Keelson Security Scan Report');
    expect(report).toContain('## Summary');
    expect(report).toContain('| Metric | Count |');
    expect(report).toContain('### Severity Breakdown');
    expect(report).toContain('## Findings');
    expect(report).toContain(mixedResult.target);
    expect(report).toContain(mixedResult.scanId);
    expect(report).not.toContain('undefined');
    expect(report).not.toContain('null');
  });

  it('SARIF report is valid JSON with correct schema', () => {
    const sarif = generateReport(mixedResult, 'sarif');

    expect(sarif.$schema).toContain('sarif-schema-2.1.0');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);

    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe('keelson');
    expect(run.tool.driver.rules.length).toBeGreaterThan(0);
    expect(run.results.length).toBe(mixedResult.findings.length);
    expect(run.invocations).toHaveLength(1);
    expect(run.invocations[0].executionSuccessful).toBe(true);
    expect(run.properties?.target).toBe(mixedResult.target);
    expect(run.properties?.scanId).toBe(mixedResult.scanId);

    // Verify the output round-trips through JSON (no circular refs, etc.)
    const json = JSON.stringify(sarif);
    const parsed = JSON.parse(json);
    expect(parsed.$schema).toBe(sarif.$schema);
  });

  it('JUnit report has correct test counts', () => {
    const junit = generateReport(mixedResult, 'junit');
    const vulnCount = mixedResult.findings.filter((f) => f.verdict === Verdict.Vulnerable).length;
    const incCount = mixedResult.findings.filter((f) => f.verdict === Verdict.Inconclusive).length;

    expect(junit).toContain('<?xml version="1.0"');
    expect(junit).toContain(`tests="${mixedResult.findings.length}"`);
    expect(junit).toContain(`failures="${vulnCount}"`);
    expect(junit).toContain(`skipped="${incCount}"`);
    expect(junit).toContain('</testsuite>');
  });

  it('all report formats handle zero findings', () => {
    const markdown = generateReport(emptyResult, 'markdown');
    expect(markdown).toContain('# Keelson Security Scan Report');
    expect(markdown).toContain('No probes were executed');

    const sarif = generateReport(emptyResult, 'sarif');
    expect(sarif.runs[0].results).toHaveLength(0);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);

    const junit = generateReport(emptyResult, 'junit');
    expect(junit).toContain('tests="0"');
    expect(junit).toContain('failures="0"');

    const executive = generateReport(emptyResult, 'executive');
    expect(executive).toContain('No probe scenarios were executed');
  });

  it('all report formats handle all-vulnerable findings', () => {
    const markdown = generateReport(allVulnResult, 'markdown');
    expect(markdown).toContain('## Findings');
    // All findings are vulnerable, so every probe should appear in Findings section
    for (const f of allVulnResult.findings) {
      expect(markdown).toContain(f.probeId);
    }

    const sarif = generateReport(allVulnResult, 'sarif');
    const failResults = sarif.runs[0].results.filter((r) => r.kind === 'fail');
    expect(failResults.length).toBe(allVulnResult.findings.length);

    const junit = generateReport(allVulnResult, 'junit');
    expect(junit).toContain(`failures="${allVulnResult.findings.length}"`);

    const executive = generateReport(allVulnResult, 'executive');
    expect(executive).toContain('## Confirmed Vulnerabilities');
    for (const f of allVulnResult.findings) {
      expect(executive).toContain(f.probeId);
    }
  });

  it('compliance report maps to OWASP controls', () => {
    const report = generateReport(mixedResult, 'compliance', {
      complianceFramework: ComplianceFramework.OwaspLlmTop10,
    });

    expect(report).toContain('# Keelson Compliance Report');
    expect(report).toContain('OWASP LLM Top 10');
    expect(report).toContain('## Control Assessment');
    // LLM01 maps to goal_adherence -- our test data uses GA- probes
    expect(report).toContain('LLM01');
    expect(report).toContain('Prompt Injection');
    expect(report).toContain('## Recommendations');
  });

  it('executive report calculates risk score correctly', () => {
    const report = generateReport(mixedResult, 'executive');

    expect(report).toContain('# AI Agent Security Assessment Report');
    expect(report).toContain('## Executive Summary');
    expect(report).toContain('Risk Score');

    // Risk score = vulnerable / total * 100
    const expectedScore = (mixedResult.summary.vulnerable / mixedResult.summary.total) * 100;
    expect(report).toContain(`${expectedScore.toFixed(1)}%`);

    expect(report).toContain('## Category Breakdown');
    expect(report).toContain('## Confirmed Vulnerabilities');
    expect(report).toContain('## Recommendations');
  });
});
