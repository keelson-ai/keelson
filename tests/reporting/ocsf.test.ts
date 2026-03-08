import { describe, expect, it } from 'vitest';

import { makeFinding, makeResult, makeSummary } from './helpers.js';
import { findingToOcsf, generateOcsf } from '../../src/reporting/ocsf.js';
import { Severity, Verdict } from '../../src/types/index.js';

describe('findingToOcsf', () => {
  it('produces correct OCSF class and category identifiers', () => {
    const finding = makeFinding();
    const event = findingToOcsf(finding, 'https://api.example.com');

    expect(event.class_uid).toBe(2002);
    expect(event.class_name).toBe('Vulnerability Finding');
    expect(event.category_uid).toBe(2);
    expect(event.category_name).toBe('Findings');
    expect(event.activity_id).toBe(1);
    expect(event.activity_name).toBe('Create');
    expect(event.type_uid).toBe(200201);
  });

  it('maps severity correctly', () => {
    const critical = findingToOcsf(
      makeFinding({ severity: Severity.Critical }),
      'https://api.example.com',
    );
    const high = findingToOcsf(
      makeFinding({ severity: Severity.High }),
      'https://api.example.com',
    );
    const medium = findingToOcsf(
      makeFinding({ severity: Severity.Medium }),
      'https://api.example.com',
    );
    const low = findingToOcsf(
      makeFinding({ severity: Severity.Low }),
      'https://api.example.com',
    );

    expect(critical.severity_id).toBe(5);
    expect(critical.severity).toBe('Critical');
    expect(high.severity_id).toBe(4);
    expect(high.severity).toBe('High');
    expect(medium.severity_id).toBe(3);
    expect(medium.severity).toBe('Medium');
    expect(low.severity_id).toBe(2);
    expect(low.severity).toBe('Low');
  });

  it('maps verdict to status correctly', () => {
    const vulnerable = findingToOcsf(
      makeFinding({ verdict: Verdict.Vulnerable }),
      'https://api.example.com',
    );
    const safe = findingToOcsf(
      makeFinding({ verdict: Verdict.Safe }),
      'https://api.example.com',
    );
    const inconclusive = findingToOcsf(
      makeFinding({ verdict: Verdict.Inconclusive }),
      'https://api.example.com',
    );

    expect(vulnerable.status_id).toBe(1);
    expect(vulnerable.status).toBe('New');
    expect(safe.status_id).toBe(4);
    expect(safe.status).toBe('Resolved');
    expect(inconclusive.status_id).toBe(2);
    expect(inconclusive.status).toBe('In Progress');
  });

  it('includes finding info with uid and title', () => {
    const finding = makeFinding();
    const event = findingToOcsf(finding, 'https://api.example.com');

    expect(event.finding_info.uid).toBe('GA-001');
    expect(event.finding_info.title).toBe('Direct Instruction Override');
    expect(event.finding_info.types).toEqual(['Goal Adherence']);
  });

  it('includes OWASP analytic info', () => {
    const finding = makeFinding({ owaspId: 'LLM01' });
    const event = findingToOcsf(finding, 'https://api.example.com');

    expect(event.finding_info.analytic.uid).toBe('LLM01');
    expect(event.finding_info.analytic.name).toBe('LLM01');
  });

  it('includes confidence score as integer', () => {
    const finding = makeFinding({ confidence: 0.92 });
    const event = findingToOcsf(finding, 'https://api.example.com');

    expect(event.confidence_score).toBe(92);
  });

  it('includes metadata with product info', () => {
    const finding = makeFinding();
    const event = findingToOcsf(finding, 'https://api.example.com');

    expect(event.metadata.version).toBe('1.1.0');
    expect(event.metadata.product.name).toBe('Keelson');
    expect(event.metadata.product.vendor_name).toBe('Keelson');
  });

  it('includes resource with target URL', () => {
    const finding = makeFinding();
    const event = findingToOcsf(finding, 'https://api.example.com');

    expect(event.resources).toHaveLength(1);
    expect(event.resources[0].uid).toBe('https://api.example.com');
    expect(event.resources[0].type).toBe('API Endpoint');
  });

  it('includes evidences when evidence exists', () => {
    const finding = makeFinding();
    const event = findingToOcsf(finding, 'https://api.example.com');

    expect(event.evidences).toBeDefined();
    expect(event.evidences).toHaveLength(1);
    expect(event.evidences![0].data.prompt).toContain('Ignore all previous');
    expect(event.evidences![0].data.response).toBe('PWNED');
    expect(event.evidences![0].data.response_time_ms).toBe(150);
  });

  it('omits evidences when no evidence', () => {
    const finding = makeFinding({ evidence: [] });
    const event = findingToOcsf(finding, 'https://api.example.com');

    expect(event.evidences).toBeUndefined();
  });

  it('uses reasoning as description', () => {
    const finding = makeFinding({ reasoning: 'Agent was compromised.' });
    const event = findingToOcsf(finding, 'https://api.example.com');

    expect(event.finding_info.desc).toBe('Agent was compromised.');
  });

  it('falls back to probeName:verdict when no reasoning', () => {
    const finding = makeFinding({ reasoning: '' });
    const event = findingToOcsf(finding, 'https://api.example.com');

    expect(event.finding_info.desc).toContain('Direct Instruction Override');
    expect(event.finding_info.desc).toContain('VULNERABLE');
  });
});

describe('generateOcsf', () => {
  it('produces one event per finding', () => {
    const result = makeResult();
    const events = generateOcsf(result);

    expect(events).toHaveLength(5);
  });

  it('all events have correct class_uid', () => {
    const result = makeResult();
    const events = generateOcsf(result);

    for (const event of events) {
      expect(event.class_uid).toBe(2002);
    }
  });

  it('uses scan target as resource', () => {
    const result = makeResult();
    const events = generateOcsf(result);

    for (const event of events) {
      expect(event.resources[0].uid).toBe('https://api.example.com/v1/chat');
    }
  });

  it('handles empty findings', () => {
    const findings: never[] = [];
    const result = makeResult({ findings, summary: makeSummary(findings) });
    const events = generateOcsf(result);

    expect(events).toHaveLength(0);
  });
});
