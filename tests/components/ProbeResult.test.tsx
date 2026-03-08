import { render } from 'ink-testing-library';
import React from 'react';
import { describe, expect, it } from 'vitest';

import { ProbeResult } from '../../src/components/ProbeResult.js';
import { Verdict } from '../../src/types/index.js';
import { makeFinding } from '../helpers/fixtures.js';

describe('ProbeResult', () => {
  it('renders verdict and probe info', () => {
    const finding = makeFinding({
      verdict: Verdict.Vulnerable,
      probeId: 'GA-001',
      probeName: 'Direct Override',
    });
    const { lastFrame } = render(<ProbeResult finding={finding} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('VULNERABLE');
    expect(output).toContain('GA-001');
    expect(output).toContain('Direct Override');
  });

  it('shows confidence percentage', () => {
    const finding = makeFinding({ confidence: 0.92 });
    const { lastFrame } = render(<ProbeResult finding={finding} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('92%');
  });

  it('shows reasoning', () => {
    const finding = makeFinding({ reasoning: 'Agent responded with PWNED' });
    const { lastFrame } = render(<ProbeResult finding={finding} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('Agent responded with PWNED');
  });

  it('shows evidence by default', () => {
    const finding = makeFinding({
      evidence: [{ stepIndex: 0, prompt: 'test prompt', response: 'PWNED', responseTimeMs: 50 }],
    });
    const { lastFrame } = render(<ProbeResult finding={finding} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('Evidence');
    expect(output).toContain('test prompt');
  });

  it('hides evidence when showEvidence is false', () => {
    const finding = makeFinding({
      evidence: [{ stepIndex: 0, prompt: 'test', response: 'PWNED', responseTimeMs: 50 }],
    });
    const { lastFrame } = render(<ProbeResult finding={finding} showEvidence={false} />);
    const output = lastFrame() ?? '';
    expect(output).not.toContain('Evidence');
  });

  it('renders safe verdict', () => {
    const finding = makeFinding({ verdict: Verdict.Safe });
    const { lastFrame } = render(<ProbeResult finding={finding} />);
    const output = lastFrame() ?? '';
    expect(output).toContain('SAFE');
  });
});
