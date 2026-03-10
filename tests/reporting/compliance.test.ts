import { describe, expect, it } from 'vitest';

import { makeFinding, makeResult, makeSummary } from './helpers.js';
import {
  FRAMEWORK_CONTROLS,
  generateComplianceReport,
  mapFindingsToFramework,
} from '../../src/reporting/compliance.js';
import { ComplianceFramework, Verdict } from '../../src/types/index.js';

describe('mapFindingsToFramework', () => {
  it('maps GA findings to LLM01 for OWASP', () => {
    const findings = [makeFinding({ probeId: 'GA-001', category: 'Goal Adherence', owaspId: 'LLM01' })];
    const mappings = mapFindingsToFramework(findings, ComplianceFramework.OwaspLlmTop10);

    const llm01 = mappings.find((m) => m.controlId === 'LLM01');
    expect(llm01).toBeDefined();
    expect(llm01?.findings).toHaveLength(1);
    expect(llm01?.findings[0].probeId).toBe('GA-001');
  });

  it('maps TS findings to LLM02 and LLM07 for OWASP', () => {
    const findings = [
      makeFinding({
        probeId: 'TS-001',
        category: 'Tool Safety',
        owaspId: 'LLM02',
        verdict: Verdict.Vulnerable,
      }),
    ];
    const mappings = mapFindingsToFramework(findings, ComplianceFramework.OwaspLlmTop10);

    const llm02 = mappings.find((m) => m.controlId === 'LLM02');
    const llm07 = mappings.find((m) => m.controlId === 'LLM07');

    expect(llm02?.findings).toHaveLength(1);
    expect(llm07?.findings).toHaveLength(1);
  });

  it('sets status to fail when any finding is vulnerable', () => {
    const findings = [
      makeFinding({
        probeId: 'GA-001',
        category: 'Goal Adherence',
        verdict: Verdict.Vulnerable,
      }),
    ];
    const mappings = mapFindingsToFramework(findings, ComplianceFramework.OwaspLlmTop10);

    const llm01 = mappings.find((m) => m.controlId === 'LLM01');
    expect(llm01?.status).toBe('fail');
  });

  it('sets status to pass when all findings are safe', () => {
    const findings = [
      makeFinding({
        probeId: 'GA-001',
        category: 'Goal Adherence',
        verdict: Verdict.Safe,
      }),
    ];
    const mappings = mapFindingsToFramework(findings, ComplianceFramework.OwaspLlmTop10);

    const llm01 = mappings.find((m) => m.controlId === 'LLM01');
    expect(llm01?.status).toBe('pass');
  });

  it('sets status to partial when findings are inconclusive', () => {
    const findings = [
      makeFinding({
        probeId: 'GA-001',
        category: 'Goal Adherence',
        verdict: Verdict.Inconclusive,
      }),
    ];
    const mappings = mapFindingsToFramework(findings, ComplianceFramework.OwaspLlmTop10);

    const llm01 = mappings.find((m) => m.controlId === 'LLM01');
    expect(llm01?.status).toBe('partial');
  });

  it('covers all 10 OWASP controls', () => {
    const findings = [makeFinding()];
    const mappings = mapFindingsToFramework(findings, ComplianceFramework.OwaspLlmTop10);

    expect(mappings).toHaveLength(10);
    const controlIds = mappings.map((m) => m.controlId);
    expect(controlIds).toContain('LLM01');
    expect(controlIds).toContain('LLM10');
  });

  it('maps NIST AI RMF functions', () => {
    const findings = [makeFinding({ probeId: 'GA-001', category: 'Goal Adherence' })];
    const mappings = mapFindingsToFramework(findings, ComplianceFramework.NistAiRmf);

    expect(mappings).toHaveLength(4);
    const controlIds = mappings.map((m) => m.controlId);
    expect(controlIds).toContain('GOVERN');
    expect(controlIds).toContain('MAP');
    expect(controlIds).toContain('MEASURE');
    expect(controlIds).toContain('MANAGE');
  });

  it('NIST MEASURE gets all findings', () => {
    const findings = [
      makeFinding({ probeId: 'GA-001', category: 'Goal Adherence' }),
      makeFinding({ probeId: 'TS-001', category: 'Tool Safety' }),
    ];
    const mappings = mapFindingsToFramework(findings, ComplianceFramework.NistAiRmf);

    const measure = mappings.find((m) => m.controlId === 'MEASURE');
    expect(measure?.findings).toHaveLength(2);
  });

  it('maps EU AI Act articles', () => {
    const findings = [makeFinding()];
    const mappings = mapFindingsToFramework(findings, ComplianceFramework.EuAiAct);

    expect(mappings.length).toBeGreaterThanOrEqual(4);
    const controlIds = mappings.map((m) => m.controlId);
    expect(controlIds).toContain('Article 9');
    expect(controlIds).toContain('Article 15');
  });

  it('maps PCI DSS v4 controls', () => {
    const findings = [makeFinding({ probeId: 'GA-001', category: 'Goal Adherence' })];
    const mappings = mapFindingsToFramework(findings, ComplianceFramework.PciDssV4);

    expect(mappings.length).toBeGreaterThanOrEqual(4);
    const controlIds = mappings.map((m) => m.controlId);
    expect(controlIds).toContain('6.2');
    expect(controlIds).toContain('6.3');
  });

  it('ISO 42001 A.6 gets all findings', () => {
    const findings = [makeFinding({ probeId: 'GA-001' }), makeFinding({ probeId: 'TS-001' })];
    const mappings = mapFindingsToFramework(findings, ComplianceFramework.Iso42001);

    const a6 = mappings.find((m) => m.controlId === 'A.6');
    expect(a6?.findings).toHaveLength(2);
  });

  it('keeps worst verdict when same probeId appears with different verdicts', () => {
    const findings = [
      makeFinding({
        probeId: 'GA-001',
        category: 'Goal Adherence',
        verdict: Verdict.Safe,
      }),
      makeFinding({
        probeId: 'GA-001',
        category: 'Goal Adherence',
        verdict: Verdict.Vulnerable,
      }),
    ];
    const mappings = mapFindingsToFramework(findings, ComplianceFramework.OwaspLlmTop10);

    const llm01 = mappings.find((m) => m.controlId === 'LLM01');
    expect(llm01?.findings).toHaveLength(1);
    expect(llm01?.findings[0].verdict).toBe(Verdict.Vulnerable);
  });

  it('SOC2 CC7.2 gets all findings', () => {
    const findings = [makeFinding({ probeId: 'GA-001' }), makeFinding({ probeId: 'TS-001' })];
    const mappings = mapFindingsToFramework(findings, ComplianceFramework.Soc2);

    const cc72 = mappings.find((m) => m.controlId === 'CC7.2');
    expect(cc72?.findings).toHaveLength(2);
  });
});

describe('FRAMEWORK_CONTROLS', () => {
  it('has entries for all 6 frameworks', () => {
    expect(Object.keys(FRAMEWORK_CONTROLS)).toHaveLength(6);
    expect(FRAMEWORK_CONTROLS[ComplianceFramework.OwaspLlmTop10]).toBeDefined();
    expect(FRAMEWORK_CONTROLS[ComplianceFramework.NistAiRmf]).toBeDefined();
    expect(FRAMEWORK_CONTROLS[ComplianceFramework.EuAiAct]).toBeDefined();
    expect(FRAMEWORK_CONTROLS[ComplianceFramework.Iso42001]).toBeDefined();
    expect(FRAMEWORK_CONTROLS[ComplianceFramework.Soc2]).toBeDefined();
    expect(FRAMEWORK_CONTROLS[ComplianceFramework.PciDssV4]).toBeDefined();
  });
});

describe('generateComplianceReport', () => {
  it('generates OWASP compliance report with extracted date', () => {
    const result = makeResult();
    const report = generateComplianceReport(result, ComplianceFramework.OwaspLlmTop10);

    expect(report).toContain('# Keelson Compliance Report');
    expect(report).toContain('**Framework**: OWASP LLM Top 10');
    expect(report).toContain('**Date**: 2026-03-08');
    expect(report).toContain('**Status**: Complete');
    expect(report).toContain('## Executive Summary');
    expect(report).toContain('## Control Assessment');
    expect(report).toContain('LLM01: Prompt Injection');
  });

  it('shows pass rate and coverage', () => {
    const result = makeResult();
    const report = generateComplianceReport(result, ComplianceFramework.OwaspLlmTop10);

    expect(report).toContain('**Overall Coverage**:');
    expect(report).toContain('**Pass Rate**:');
  });

  it('shows FAIL status for vulnerable controls', () => {
    const result = makeResult();
    const report = generateComplianceReport(result, ComplianceFramework.OwaspLlmTop10);

    expect(report).toContain('**Status**: FAIL');
  });

  it('includes remediation for failing controls', () => {
    const result = makeResult();
    const report = generateComplianceReport(result, ComplianceFramework.OwaspLlmTop10);

    expect(report).toContain('**Remediation**:');
  });

  it('includes recommendations', () => {
    const result = makeResult();
    const report = generateComplianceReport(result, ComplianceFramework.OwaspLlmTop10);

    expect(report).toContain('## Recommendations');
    expect(report).toContain('Address failing controls');
  });

  it('handles all framework types', () => {
    const result = makeResult();

    for (const fw of Object.values(ComplianceFramework)) {
      const report = generateComplianceReport(result, fw);
      expect(report).toContain('# Keelson Compliance Report');
      expect(report).toContain('## Control Assessment');
    }
  });

  it('shows findings table with uppercase verdict labels', () => {
    const result = makeResult();
    const report = generateComplianceReport(result, ComplianceFramework.OwaspLlmTop10);

    expect(report).toContain('| Probe | Verdict | Severity |');
    expect(report).toContain('GA-001');
    expect(report).toContain('VULNERABLE');
  });

  it('handles zero vulnerabilities', () => {
    const findings = [makeFinding({ probeId: 'GA-001', verdict: Verdict.Safe })];
    const result = makeResult({ findings, summary: makeSummary(findings) });
    const report = generateComplianceReport(result, ComplianceFramework.OwaspLlmTop10);

    expect(report).toContain('passed security validation');
  });

  it('includes methodology section', () => {
    const result = makeResult();
    const report = generateComplianceReport(result, ComplianceFramework.OwaspLlmTop10);

    expect(report).toContain('## Methodology');
    expect(report).toContain('Keelson AI Agent Security Scanner');
  });

  it('includes footer with timestamp', () => {
    const result = makeResult();
    const report = generateComplianceReport(result, ComplianceFramework.OwaspLlmTop10);

    expect(report).toContain('Report generated by Keelson');
  });
});
