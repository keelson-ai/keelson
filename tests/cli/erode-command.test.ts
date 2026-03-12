import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

const CLI = resolve(import.meta.dirname, '../../dist/cli/index.js');
const hasBuild = existsSync(CLI);

describe.runIf(hasBuild)('erode command', () => {
  it('shows help text', () => {
    const result = spawnSync('node', [CLI, 'erode', '--help'], {
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
