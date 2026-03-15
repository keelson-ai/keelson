import { describe, expect, it } from 'vitest';

import { applyPreset, getPreset, listPresets } from '../../src/core/presets.js';
import type { ProbeTemplate } from '../../src/types/index.js';
import { Severity } from '../../src/types/index.js';

function makeProbe(overrides: Partial<ProbeTemplate> = {}): ProbeTemplate {
  return {
    id: 'GA-001',
    name: 'Test',
    severity: Severity.High,
    category: 'goal_adherence',
    owaspId: 'LLM01',
    objective: 'test',
    turns: [{ role: 'user', content: 'test' }],
    evaluation: { vulnerableIf: ['test'], safeIf: ['test'], inconclusiveIf: [] },
    ...overrides,
  };
}

describe('getPreset', () => {
  it('returns a known preset', () => {
    const preset = getPreset('quick');
    expect(preset.name).toBe('quick');
    expect(preset.minSeverity).toBe(Severity.High);
  });

  it('throws for unknown preset', () => {
    expect(() => getPreset('nonexistent')).toThrow(/Unknown preset/);
  });
});

describe('listPresets', () => {
  it('returns all presets', () => {
    const presets = listPresets();
    expect(presets.length).toBeGreaterThanOrEqual(7);
    const names = presets.map((p) => p.name);
    expect(names).toContain('default');
    expect(names).toContain('quick');
    expect(names).toContain('owasp-top10');
    expect(names).toContain('agentic');
  });
});

describe('applyPreset', () => {
  const probes: ProbeTemplate[] = [
    makeProbe({ id: 'GA-001', category: 'goal_adherence', severity: Severity.Critical }),
    makeProbe({ id: 'GA-002', category: 'goal_adherence', severity: Severity.Medium }),
    makeProbe({ id: 'TS-001', category: 'tool_safety', severity: Severity.High }),
    makeProbe({ id: 'MI-001', category: 'memory_integrity', severity: Severity.Low }),
    makeProbe({ id: 'SI-001', category: 'session_isolation', severity: Severity.High }),
    makeProbe({ id: 'DI-001', category: 'delegation_integrity', severity: Severity.Medium }),
  ];

  it('default preset returns all probes', () => {
    const result = applyPreset(probes, 'default');
    expect(result).toHaveLength(probes.length);
  });

  it('quick preset filters by severity and limits count', () => {
    const result = applyPreset(probes, 'quick');
    // Only critical and high severity
    for (const p of result) {
      expect([Severity.Critical, Severity.High]).toContain(p.severity);
    }
  });

  it('owasp-top10 filters to matching categories', () => {
    const result = applyPreset(probes, 'owasp-top10');
    const categories = result.map((p) => p.category);
    // Should include goal_adherence, tool_safety, memory_integrity but not session_isolation, delegation_integrity
    expect(categories).toContain('goal_adherence');
    expect(categories).toContain('tool_safety');
    expect(categories).toContain('memory_integrity');
    expect(categories).not.toContain('session_isolation');
    expect(categories).not.toContain('delegation_integrity');
  });

  it('agentic preset includes tool and delegation categories', () => {
    const result = applyPreset(probes, 'agentic');
    const categories = new Set(result.map((p) => p.category));
    expect(categories.has('tool_safety')).toBe(true);
    expect(categories.has('delegation_integrity')).toBe(true);
    expect(categories.has('goal_adherence')).toBe(false);
  });

  it('data-privacy preset includes session and memory categories', () => {
    const result = applyPreset(probes, 'data-privacy');
    const categories = new Set(result.map((p) => p.category));
    expect(categories.has('session_isolation')).toBe(true);
    expect(categories.has('memory_integrity')).toBe(true);
    expect(categories.has('tool_safety')).toBe(false);
  });

  it('throws for unknown preset', () => {
    expect(() => applyPreset(probes, 'nonexistent')).toThrow(/Unknown preset/);
  });

  it('maxProbes limits output and prioritizes higher severity', () => {
    // Create many probes
    const manyProbes = Array.from({ length: 50 }, (_, i) =>
      makeProbe({
        id: `GA-${String(i + 1).padStart(3, '0')}`,
        category: 'goal_adherence',
        severity: i < 5 ? Severity.Critical : i < 15 ? Severity.High : Severity.Medium,
      }),
    );
    const result = applyPreset(manyProbes, 'quick');
    expect(result.length).toBeLessThanOrEqual(30);
    // First results should be critical
    expect(result[0].severity).toBe(Severity.Critical);
  });
});
