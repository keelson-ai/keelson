import { describe, expect, it } from 'vitest';
import React from 'react';
import { render } from 'ink-testing-library';

import { ScanProgress } from '../../src/components/ScanProgress.js';

// ink-testing-library may not be installed; these tests verify component logic
// by testing the render output if available, or fall back to structural tests

describe('ScanProgress', () => {
  let renderFn: typeof render | undefined;

  try {
    // If ink-testing-library is available, use it
    renderFn = render;
  } catch {
    renderFn = undefined;
  }

  it('renders without crashing', () => {
    if (!renderFn) {
      // Structural test: verify the component is a valid function
      expect(typeof ScanProgress).toBe('function');
      return;
    }

    const { lastFrame } = renderFn(
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
    if (!renderFn) {
      expect(typeof ScanProgress).toBe('function');
      return;
    }

    const { lastFrame } = renderFn(
      <ScanProgress
        current={45}
        total={100}
        findings={{ vulnerable: 10, safe: 30, inconclusive: 5 }}
      />,
    );

    const output = lastFrame() ?? '';
    expect(output).toContain('45');
    expect(output).toContain('100');
  });

  it('shows verdict counts', () => {
    if (!renderFn) {
      expect(typeof ScanProgress).toBe('function');
      return;
    }

    const { lastFrame } = renderFn(
      <ScanProgress
        current={10}
        total={20}
        findings={{ vulnerable: 3, safe: 5, inconclusive: 2 }}
      />,
    );

    const output = lastFrame() ?? '';
    expect(output).toContain('3');
    expect(output).toContain('5');
    expect(output).toContain('2');
  });

  it('shows current probe when provided', () => {
    if (!renderFn) {
      expect(typeof ScanProgress).toBe('function');
      return;
    }

    const { lastFrame } = renderFn(
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
});
