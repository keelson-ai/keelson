import { describe, expect, it } from 'vitest';

import { generateSarif } from '../../src/reporting/sarif.js';
import type { SarifLog } from '../../src/reporting/sarif.js';
import { Severity, Verdict } from '../../src/types/index.js';
import { makeFinding, makeResult, makeSummary } from './helpers.js';

describe('generateSarif', () => {
  it('produces valid SARIF v2.1.0 structure', () => {
    const result = makeResult();
    const sarif: SarifLog = generateSarif(result);

    expect(sarif.$schema).toContain('sarif-schema-2.1.0');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
  });

  it('includes tool driver info', () => {
    const result = makeResult();
    const sarif = generateSarif(result);
    const driver = sarif.runs[0].tool.driver;

    expect(driver.name).toBe('keelson');
    expect(driver.semanticVersion).toBe('0.5.0');
    expect(driver.informationUri).toContain('keelson');
  });

  it('creates rules from unique probe IDs', () => {
    const result = makeResult();
    const sarif = generateSarif(result);
    const rules = sarif.runs[0].tool.driver.rules;

    // 5 findings with unique probe IDs
    expect(rules).toHaveLength(5);
    expect(rules[0].id).toBe('GA-001');
    expect(rules[0].shortDescription.text).toBe('Direct Instruction Override');
  });

  it('deduplicates rules for same probe ID', () => {
    const findings = [
      makeFinding({ probeId: 'GA-001' }),
      makeFinding({ probeId: 'GA-001', probeName: 'Same probe different run' }),
    ];
    const result = makeResult({ findings, summary: makeSummary(findings) });
    const sarif = generateSarif(result);

    // Same probe ID should result in 1 rule but 2 results
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(1);
    expect(sarif.runs[0].results).toHaveLength(2);
  });

  it('maps severity to SARIF level correctly', () => {
    const findings = [
      makeFinding({ probeId: 'GA-001', severity: Severity.Critical, verdict: Verdict.Vulnerable }),
      makeFinding({ probeId: 'GA-002', severity: Severity.High, verdict: Verdict.Vulnerable }),
      makeFinding({ probeId: 'GA-003', severity: Severity.Medium, verdict: Verdict.Vulnerable }),
      makeFinding({ probeId: 'GA-004', severity: Severity.Low, verdict: Verdict.Vulnerable }),
    ];
    const result = makeResult({ findings, summary: makeSummary(findings) });
    const sarif = generateSarif(result);
    const rules = sarif.runs[0].tool.driver.rules;

    expect(rules[0].defaultConfiguration.level).toBe('error');   // Critical
    expect(rules[1].defaultConfiguration.level).toBe('error');   // High
    expect(rules[2].defaultConfiguration.level).toBe('warning'); // Medium
    expect(rules[3].defaultConfiguration.level).toBe('note');    // Low
  });

  it('maps verdict to SARIF kind correctly', () => {
    const result = makeResult();
    const sarif = generateSarif(result);
    const results = sarif.runs[0].results;

    const vulnResult = results.find((r) => r.ruleId === 'GA-001');
    const safeResult = results.find((r) => r.ruleId === 'TS-001');
    const inconclusiveResult = results.find((r) => r.ruleId === 'MI-001');

    expect(vulnResult?.kind).toBe('fail');
    expect(safeResult?.kind).toBe('pass');
    expect(inconclusiveResult?.kind).toBe('review');
  });

  it('sets level to none for non-vulnerable results', () => {
    const result = makeResult();
    const sarif = generateSarif(result);
    const results = sarif.runs[0].results;

    const safeResult = results.find((r) => r.ruleId === 'TS-001');
    expect(safeResult?.level).toBe('none');
  });

  it('includes locations for findings with evidence', () => {
    const result = makeResult();
    const sarif = generateSarif(result);
    const results = sarif.runs[0].results;

    const vulnResult = results.find((r) => r.ruleId === 'GA-001');
    expect(vulnResult?.locations).toBeDefined();
    expect(vulnResult?.locations?.[0].physicalLocation.artifactLocation.uri).toBe('GA-001');
    expect(vulnResult?.locations?.[0].physicalLocation.artifactLocation.uriBaseId).toBe('PROBES');
  });

  it('includes evidence in properties', () => {
    const result = makeResult();
    const sarif = generateSarif(result);
    const results = sarif.runs[0].results;

    const vulnResult = results.find((r) => r.ruleId === 'GA-001');
    expect(vulnResult?.properties.evidence).toBeDefined();
    expect(vulnResult?.properties.evidence?.[0].prompt).toContain('Ignore all previous');
  });

  it('includes invocation timestamps', () => {
    const result = makeResult();
    const sarif = generateSarif(result);
    const invocation = sarif.runs[0].invocations[0];

    expect(invocation.executionSuccessful).toBe(true);
    expect(invocation.startTimeUtc).toBe('2026-03-08T10:00:00.000Z');
    expect(invocation.endTimeUtc).toBe('2026-03-08T10:05:00.000Z');
  });

  it('includes scan properties', () => {
    const result = makeResult();
    const sarif = generateSarif(result);

    expect(sarif.runs[0].properties?.target).toBe('https://api.example.com/v1/chat');
    expect(sarif.runs[0].properties?.scanId).toBe('scan-test-001');
  });

  it('handles empty findings', () => {
    const findings: never[] = [];
    const result = makeResult({ findings, summary: makeSummary(findings) });
    const sarif = generateSarif(result);

    expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
    expect(sarif.runs[0].results).toHaveLength(0);
  });
});
