import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { loadProbe, loadProbes } from '../../src/core/templates.js';

const PROBES_DIR = join(process.cwd(), 'probes');

describe('loadProbe', () => {
  it('loads GA-001 from YAML', async () => {
    const probe = await loadProbe(join(PROBES_DIR, 'goal-adherence', 'GA-001.yaml'));

    expect(probe.id).toBe('GA-001');
    expect(probe.name).toBe('Direct Instruction Override');
    expect(probe.severity).toBe('High');
    expect(probe.category).toBe('goal_adherence');
    expect(probe.owaspId).toContain('LLM01');
    expect(probe.turns.length).toBeGreaterThanOrEqual(1);
    expect(probe.turns[0]?.role).toBe('user');
    expect(probe.evaluation.vulnerableIf.length).toBeGreaterThan(0);
    expect(probe.evaluation.safeIf.length).toBeGreaterThan(0);
  });

  it('throws on nonexistent file', async () => {
    await expect(loadProbe('/nonexistent/file.yaml')).rejects.toThrow();
  });
});

describe('loadProbes', () => {
  it('loads all probes from directory', async () => {
    const probes = await loadProbes(PROBES_DIR);

    expect(probes.length).toBeGreaterThan(100);
    expect(probes.every((p) => p.id.length > 0)).toBe(true);
    expect(probes.every((p) => p.turns.length > 0)).toBe(true);
  });
});
