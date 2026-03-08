import { describe, expect, it } from 'vitest';

import { generateJunit } from '../../src/reporting/junit.js';
import { Verdict } from '../../src/types/index.js';
import { makeFinding, makeResult, makeSummary } from './helpers.js';

describe('generateJunit', () => {
  it('produces valid XML declaration', () => {
    const result = makeResult();
    const xml = generateJunit(result);

    expect(xml).toMatch(/^<\?xml version="1.0" encoding="UTF-8"\?>/);
  });

  it('includes testsuite element with correct attributes', () => {
    const result = makeResult();
    const xml = generateJunit(result);

    expect(xml).toContain('name="keelson-scan-scan-test-001"');
    expect(xml).toContain('tests="5"');
    expect(xml).toContain('failures="3"');
    expect(xml).toContain('skipped="1"');
    expect(xml).toContain('errors="0"');
  });

  it('includes timestamp attribute', () => {
    const result = makeResult();
    const xml = generateJunit(result);

    expect(xml).toContain('timestamp="2026-03-08T10:00:00.000Z"');
  });

  it('includes properties section', () => {
    const result = makeResult();
    const xml = generateJunit(result);

    expect(xml).toContain('<properties>');
    expect(xml).toContain('name="target" value="https://api.example.com/v1/chat"');
    expect(xml).toContain('name="scan_id" value="scan-test-001"');
  });

  it('maps vulnerable findings to failure elements', () => {
    const result = makeResult();
    const xml = generateJunit(result);

    expect(xml).toContain('<failure');
    expect(xml).toContain('type="vulnerability"');
    // Should contain the reasoning as text
    expect(xml).toContain('complied with the instruction override');
  });

  it('maps safe findings to passing test cases (no child elements)', () => {
    const findings = [makeFinding({ probeId: 'TS-001', verdict: Verdict.Safe })];
    const result = makeResult({ findings, summary: makeSummary(findings) });
    const xml = generateJunit(result);

    // Should have a testcase but no failure or skipped
    expect(xml).toContain('<testcase');
    expect(xml).not.toContain('<failure');
    expect(xml).not.toContain('<skipped');
  });

  it('maps inconclusive findings to skipped elements', () => {
    const result = makeResult();
    const xml = generateJunit(result);

    expect(xml).toContain('<skipped');
    expect(xml).toContain('result was inconclusive');
  });

  it('calculates time from evidence', () => {
    const result = makeResult();
    const xml = generateJunit(result);

    // GA-001 has 150ms evidence
    expect(xml).toContain('time="0.150"');
  });

  it('escapes XML special characters', () => {
    const findings = [
      makeFinding({
        probeId: 'GA-001',
        probeName: 'Test <with> & "special" chars',
        reasoning: 'Reasoning with <xml> & "quotes"',
      }),
    ];
    const result = makeResult({ findings, summary: makeSummary(findings) });
    const xml = generateJunit(result);

    expect(xml).toContain('&lt;with&gt;');
    expect(xml).toContain('&amp;');
    expect(xml).toContain('&quot;special&quot;');
    // Should not contain unescaped angle brackets in attribute values
    expect(xml).not.toMatch(/name="[^"]*<[^"]*"/);
  });

  it('uses category as classname', () => {
    const result = makeResult();
    const xml = generateJunit(result);

    expect(xml).toContain('classname="Goal Adherence"');
    expect(xml).toContain('classname="Tool Safety"');
  });

  it('handles empty findings', () => {
    const findings: never[] = [];
    const result = makeResult({ findings, summary: makeSummary(findings) });
    const xml = generateJunit(result);

    expect(xml).toContain('tests="0"');
    expect(xml).toContain('failures="0"');
    expect(xml).toContain('skipped="0"');
  });
});
