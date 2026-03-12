import { describe, expect, it } from 'vitest';

import { makeFinding, makeResult, makeSummary } from './helpers.js';
import { generateExecutiveReport } from '../../src/reporting/executive.js';
import { Severity, Verdict } from '../../src/types/index.js';

describe('generateExecutiveReport', () => {
  it('includes canonical header with scan metadata', () => {
    const result = makeResult();
    const report = generateExecutiveReport(result);

    expect(report).toContain('# Keelson Security Scan Report');
    expect(report).toContain('**Date:** 2026-03-08');
    expect(report).toContain('**Target:** https://api.example.com/v1/chat');
    expect(report).toContain('**Scan ID:** scan-test-001');
    expect(report).toContain('**Scanner:** Keelson AI Agent Security Scanner');
  });

  it('includes executive summary with key findings table', () => {
    const result = makeResult();
    const report = generateExecutiveReport(result);

    expect(report).toContain('## Executive Summary');
    expect(report).toContain('### Key Findings');
    expect(report).toContain('| Severity | Count | Summary |');
  });

  it('key findings table lists vulnerable findings by severity', () => {
    const result = makeResult();
    const report = generateExecutiveReport(result);

    expect(report).toContain('| **Critical** | 1 |');
    expect(report).toContain('| **High** | 2 |');
    expect(report).toContain('| **Safe** | 1 |');
  });

  it('includes overall risk rating for critical vulnerabilities', () => {
    const result = makeResult();
    const report = generateExecutiveReport(result);

    expect(report).toContain('**Overall Risk Rating: CRITICAL**');
    expect(report).toContain('Immediate remediation is required');
  });

  it('generates HIGH risk rating when no critical but has high', () => {
    const findings = [
      makeFinding({
        probeId: 'GA-001',
        severity: Severity.High,
        verdict: Verdict.Vulnerable,
      }),
      makeFinding({
        probeId: 'GA-002',
        severity: Severity.Low,
        verdict: Verdict.Safe,
      }),
      makeFinding({
        probeId: 'GA-003',
        severity: Severity.Low,
        verdict: Verdict.Safe,
      }),
    ];
    const result = makeResult({ findings, summary: makeSummary(findings) });
    const report = generateExecutiveReport(result);

    expect(report).toContain('**Overall Risk Rating: HIGH**');
  });

  it('generates MEDIUM risk rating with only medium/low vulns and <=30%', () => {
    const findings = [
      makeFinding({
        probeId: 'GA-001',
        severity: Severity.Medium,
        verdict: Verdict.Vulnerable,
      }),
      makeFinding({
        probeId: 'GA-002',
        severity: Severity.Low,
        verdict: Verdict.Safe,
      }),
      makeFinding({
        probeId: 'GA-003',
        severity: Severity.Low,
        verdict: Verdict.Safe,
      }),
      makeFinding({
        probeId: 'GA-004',
        severity: Severity.Low,
        verdict: Verdict.Safe,
      }),
    ];
    const result = makeResult({ findings, summary: makeSummary(findings) });
    const report = generateExecutiveReport(result);

    expect(report).toContain('**Overall Risk Rating: MEDIUM**');
  });

  it('generates MEDIUM-HIGH risk rating when >30% vulnerable with no critical/high', () => {
    const findings = [
      makeFinding({
        probeId: 'GA-001',
        severity: Severity.Medium,
        verdict: Verdict.Vulnerable,
      }),
      makeFinding({
        probeId: 'GA-002',
        severity: Severity.Medium,
        verdict: Verdict.Vulnerable,
      }),
      makeFinding({
        probeId: 'GA-003',
        severity: Severity.Low,
        verdict: Verdict.Safe,
      }),
    ];
    const result = makeResult({ findings, summary: makeSummary(findings) });
    const report = generateExecutiveReport(result);

    expect(report).toContain('**Overall Risk Rating: MEDIUM-HIGH**');
  });

  it('generates LOW risk rating when no vulnerabilities', () => {
    const findings = [
      makeFinding({ probeId: 'GA-001', verdict: Verdict.Safe }),
      makeFinding({ probeId: 'TS-001', verdict: Verdict.Safe }),
    ];
    const result = makeResult({ findings, summary: makeSummary(findings) });
    const report = generateExecutiveReport(result);

    expect(report).toContain('**Overall Risk Rating: LOW**');
    expect(report).toContain('robust security controls');
  });

  it('includes numbered detailed findings for vulnerable probes', () => {
    const result = makeResult();
    const report = generateExecutiveReport(result);

    expect(report).toContain('## Detailed Findings');
    expect(report).toContain('### FINDING 1:');
    expect(report).toContain('**Severity: CRITICAL**');
    expect(report).toContain('**Probe: GA-002**');
    expect(report).toContain('**OWASP: LLM01**');
    expect(report).toContain('**Description:**');
    expect(report).toContain('**Evidence:**');
    expect(report).toContain('**Verdict: VULNERABLE**');
  });

  it('includes inconclusive findings in detailed findings', () => {
    const result = makeResult();
    const report = generateExecutiveReport(result);

    expect(report).toContain('**Verdict: INCONCLUSIVE**');
    expect(report).toContain('MI-001');
  });

  it('includes safe findings table', () => {
    const result = makeResult();
    const report = generateExecutiveReport(result);

    expect(report).toContain('## Safe Findings');
    expect(report).toContain('| Probe | Result | Notes |');
    expect(report).toContain('| **TS-001** Unauthorized Tool Invocation | **SAFE** |');
  });

  it('includes recommendations grouped by severity', () => {
    const result = makeResult();
    const report = generateExecutiveReport(result);

    expect(report).toContain('## Recommendations');
    expect(report).toContain('### Critical Priority');
    expect(report).toContain('Harden system prompt boundaries');
  });

  it('shows leakage signals in vulnerable findings', () => {
    const result = makeResult();
    const report = generateExecutiveReport(result);

    expect(report).toContain('**Leakage Signals:**');
    expect(report).toContain('system_prompt_leak');
  });

  it('includes conclusion section', () => {
    const result = makeResult();
    const report = generateExecutiveReport(result);

    expect(report).toContain('## Conclusion');
    expect(report).toContain('vulnerabilities were identified');
  });

  it('includes footer with scan duration and probe count', () => {
    const result = makeResult();
    const report = generateExecutiveReport(result);

    expect(report).toContain('*Report generated by Keelson AI Agent Security Scanner*');
    expect(report).toContain('*Scan duration:');
    expect(report).toContain('*Probes executed: 5*');
  });

  it('handles zero vulnerabilities', () => {
    const findings = [
      makeFinding({ probeId: 'GA-001', verdict: Verdict.Safe }),
      makeFinding({ probeId: 'TS-001', verdict: Verdict.Safe }),
    ];
    const result = makeResult({ findings, summary: makeSummary(findings) });
    const report = generateExecutiveReport(result);

    expect(report).toContain('**Overall Risk Rating: LOW**');
    expect(report).toContain('No vulnerabilities or inconclusive findings were identified.');
    expect(report).toContain('No vulnerabilities were confirmed. Continue regular security assessments');
  });

  it('includes evidence in code block format', () => {
    const result = makeResult();
    const report = generateExecutiveReport(result);

    expect(report).toContain('```\nProbe:');
    expect(report).toContain('Response:');
    expect(report).toContain('```');
  });
});
