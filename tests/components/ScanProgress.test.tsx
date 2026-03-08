import { render } from 'ink-testing-library';
import React from 'react';
import { describe, expect, it } from 'vitest';

import { ScanProgress } from '../../src/components/ScanProgress.js';

describe('ScanProgress', () => {
  it('renders without crashing', () => {
    const { lastFrame } = render(
      <ScanProgress
        current={5}
        total={10}
        currentProbe="GA-001: Direct Instruction Override"
        findings={{ vulnerable: 2, safe: 2, inconclusive: 1 }}
      />,
    );

    const output = lastFrame();
    expect(output).toBeDefined();
  });

  it('shows progress numbers', () => {
    const { lastFrame } = render(
      <ScanProgress current={45} total={100} findings={{ vulnerable: 10, safe: 30, inconclusive: 5 }} />,
    );

    const output = lastFrame() ?? '';
    expect(output).toContain('45');
    expect(output).toContain('100');
  });

  it('shows verdict counts', () => {
    const { lastFrame } = render(
      <ScanProgress current={10} total={20} findings={{ vulnerable: 3, safe: 5, inconclusive: 2 }} />,
    );

    const output = lastFrame() ?? '';
    expect(output).toContain('3');
    expect(output).toContain('5');
    expect(output).toContain('2');
  });

  it('shows current probe when provided', () => {
    const { lastFrame } = render(
      <ScanProgress
        current={1}
        total={10}
        currentProbe="TS-005: Tool Injection"
        findings={{ vulnerable: 0, safe: 0, inconclusive: 0 }}
      />,
    );

    const output = lastFrame() ?? '';
    expect(output).toContain('TS-005');
  });

  it('renders without currentProbe', () => {
    const { lastFrame } = render(
      <ScanProgress current={0} total={10} findings={{ vulnerable: 0, safe: 0, inconclusive: 0 }} />,
    );

    const output = lastFrame() ?? '';
    expect(output).toContain('Keelson Security Scan');
    expect(output).not.toContain('Current:');
  });

  it('shows percentage', () => {
    const { lastFrame } = render(
      <ScanProgress current={50} total={100} findings={{ vulnerable: 0, safe: 0, inconclusive: 0 }} />,
    );

    const output = lastFrame() ?? '';
    expect(output).toContain('50%');
  });
});
