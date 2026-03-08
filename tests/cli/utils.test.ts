import { describe, expect, it } from 'vitest';

import { checkFailGates, countBy, formatFinding, parseFloatSafe, parseIntSafe, truncate } from '../../src/cli/utils.js';
import { makeFinding } from '../helpers/fixtures.js';

describe('checkFailGates', () => {
  it('returns 0 when failOnVuln is false', () => {
    expect(checkFailGates(5, 10, false, 0)).toBe(0);
  });

  it('returns 0 when there are no findings', () => {
    expect(checkFailGates(0, 0, true, 0)).toBe(0);
  });

  it('returns 1 when vuln rate exceeds threshold', () => {
    expect(checkFailGates(3, 10, true, 0.2)).toBe(1);
  });

  it('returns 0 when vuln rate equals threshold', () => {
    expect(checkFailGates(2, 10, true, 0.2)).toBe(0);
  });

  it('returns 0 when vuln rate is below threshold', () => {
    expect(checkFailGates(1, 10, true, 0.2)).toBe(0);
  });

  it('returns 1 with zero threshold and any vulnerability', () => {
    expect(checkFailGates(1, 10, true, 0)).toBe(1);
  });

  it('returns 0 with zero threshold and no vulnerabilities', () => {
    expect(checkFailGates(0, 10, true, 0)).toBe(0);
  });

  it('returns 1 when all probes are vulnerable and threshold is 0.9', () => {
    expect(checkFailGates(10, 10, true, 0.9)).toBe(1);
  });
});

describe('parseIntSafe', () => {
  it('parses valid integers', () => {
    expect(parseIntSafe('42', 0)).toBe(42);
  });

  it('returns fallback for non-numeric strings', () => {
    expect(parseIntSafe('foo', 10)).toBe(10);
  });

  it('returns fallback for empty string', () => {
    expect(parseIntSafe('', 5)).toBe(5);
  });

  it('parses leading numeric portion', () => {
    expect(parseIntSafe('10abc', 0)).toBe(10);
  });
});

describe('parseFloatSafe', () => {
  it('parses valid floats', () => {
    expect(parseFloatSafe('0.5', 0)).toBe(0.5);
  });

  it('returns fallback for non-numeric strings', () => {
    expect(parseFloatSafe('abc', 1.0)).toBe(1.0);
  });
});

describe('formatFinding', () => {
  it('includes probe name and ID', () => {
    const finding = makeFinding({ probeName: 'Test Override', probeId: 'GA-001' });
    const output = formatFinding(finding, 0);
    expect(output).toContain('Test Override');
    expect(output).toContain('GA-001');
  });

  it('includes reasoning when present', () => {
    const finding = makeFinding({ reasoning: 'The agent complied with the override' });
    const output = formatFinding(finding, 0);
    expect(output).toContain('The agent complied');
  });

  it('truncates long reasoning', () => {
    const longReasoning = 'A'.repeat(300);
    const finding = makeFinding({ reasoning: longReasoning });
    const output = formatFinding(finding, 0);
    expect(output).toContain('...');
    expect(output).not.toContain('A'.repeat(300));
  });

  it('shows evidence preview when available', () => {
    const finding = makeFinding({
      evidence: [{ stepIndex: 0, prompt: 'test prompt', response: 'test response', responseTimeMs: 50 }],
    });
    const output = formatFinding(finding, 0);
    expect(output).toContain('test prompt');
    expect(output).toContain('test response');
  });

  it('handles empty evidence', () => {
    const finding = makeFinding({ evidence: [] });
    const output = formatFinding(finding, 0);
    expect(output).not.toContain('Prompt:');
  });
});

describe('truncate', () => {
  it('returns text unchanged if within limit', () => {
    expect(truncate('hello', 10)).toBe('hello');
  });

  it('truncates and adds ellipsis when text exceeds limit', () => {
    expect(truncate('hello world', 5)).toBe('hello...');
  });

  it('handles exact length', () => {
    expect(truncate('hello', 5)).toBe('hello');
  });

  it('handles empty string', () => {
    expect(truncate('', 10)).toBe('');
  });
});

describe('countBy', () => {
  it('counts items by key', () => {
    const items = ['a', 'b', 'a', 'c', 'b', 'a'];
    const counts = countBy(items, (x) => x);
    expect(counts.get('a')).toBe(3);
    expect(counts.get('b')).toBe(2);
    expect(counts.get('c')).toBe(1);
  });

  it('returns empty map for empty input', () => {
    const counts = countBy([], (x: string) => x);
    expect(counts.size).toBe(0);
  });
});
