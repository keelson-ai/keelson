import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

const CLI = resolve(import.meta.dirname, '../../dist/cli/index.js');
const hasBuild = existsSync(CLI);

describe.runIf(hasBuild)('CLI verbosity flags', () => {
  it('--help shows -v option', () => {
    const out = execFileSync('node', [CLI, '--help'], { encoding: 'utf-8' });
    expect(out).toContain('-v, --verbose');
  });

  it('probe --help still works', () => {
    const out = execFileSync('node', [CLI, 'probe', '--help'], { encoding: 'utf-8' });
    expect(out).toContain('--probe-id');
  });

  it('scan --help still works', () => {
    const out = execFileSync('node', [CLI, 'scan', '--help'], { encoding: 'utf-8' });
    expect(out).toContain('--target');
  });

  it('list command works with -v flag', () => {
    const out = execFileSync('node', [CLI, '-v', 'list', '--category', 'goal_adherence'], {
      encoding: 'utf-8',
    });
    expect(out).toContain('GA-001');
  });
});
