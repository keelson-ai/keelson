import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

describe('erode command', () => {
  it('shows help text', () => {
    const result = spawnSync('node', ['dist/cli/index.js', 'erode', '--help'], {
      encoding: 'utf-8',
      timeout: 5000,
    });
    const output = result.stdout + result.stderr;
    expect(output).toContain('session erosion');
    expect(output).toContain('--prober-key');
    expect(output).toContain('--company');
    expect(output).toContain('--max-turns');
    expect(output).toContain('--category');
    expect(output).toContain('--search-api-key');
  });
});
