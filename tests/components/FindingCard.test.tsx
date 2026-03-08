import { render } from 'ink-testing-library';
import React from 'react';
import { describe, expect, it } from 'vitest';

import { FindingCard } from '../../src/components/FindingCard.js';
import { Verdict } from '../../src/types/index.js';
import { makeFinding } from '../helpers/fixtures.js';

describe('FindingCard', () => {
  it('renders vulnerable finding with red icon', () => {
    const finding = makeFinding({ verdict: Verdict.Vulnerable });
    const { lastFrame } = render(<FindingCard finding={finding} index={0} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('#1');
    expect(output).toContain(finding.probeName);
  });

  it('renders safe finding', () => {
    const finding = makeFinding({ verdict: Verdict.Safe });
    const { lastFrame } = render(<FindingCard finding={finding} index={2} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('#3');
    expect(output).toContain(finding.probeName);
  });

  it('shows probe ID and category', () => {
    const finding = makeFinding({ probeId: 'TS-005', category: 'tool_safety' });
    const { lastFrame } = render(<FindingCard finding={finding} index={0} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('TS-005');
    expect(output).toContain('tool_safety');
  });

  it('shows reasoning when present', () => {
    const finding = makeFinding({ reasoning: 'Agent complied with injection' });
    const { lastFrame } = render(<FindingCard finding={finding} index={0} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('Agent complied');
  });

  it('truncates long reasoning', () => {
    const finding = makeFinding({ reasoning: 'X'.repeat(300) });
    const { lastFrame } = render(<FindingCard finding={finding} index={0} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('...');
  });

  it('shows evidence when available', () => {
    const finding = makeFinding({
      evidence: [{ stepIndex: 0, prompt: 'Say PWNED', response: 'PWNED', responseTimeMs: 50 }],
    });
    const { lastFrame } = render(<FindingCard finding={finding} index={0} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('Say PWNED');
    expect(output).toContain('PWNED');
  });

  it('hides evidence section when empty', () => {
    const finding = makeFinding({ evidence: [] });
    const { lastFrame } = render(<FindingCard finding={finding} index={0} />);
    const output = lastFrame() ?? '';
    expect(output).not.toContain('Evidence');
  });

  it('shows confidence percentage', () => {
    const finding = makeFinding({ confidence: 0.85 });
    const { lastFrame } = render(<FindingCard finding={finding} index={0} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('85%');
  });
});
