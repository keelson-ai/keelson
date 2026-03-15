import { describe, expect, it } from 'vitest';

import { PROBE_TECHNIQUE_MAP, inferTechnique } from '../../src/core/technique-map.js';

describe('PROBE_TECHNIQUE_MAP', () => {
  it('contains entries for known probe IDs', () => {
    expect(PROBE_TECHNIQUE_MAP.size).toBeGreaterThan(0);
    expect(PROBE_TECHNIQUE_MAP.has('GA-001')).toBe(true);
    expect(PROBE_TECHNIQUE_MAP.has('GA-065')).toBe(true);
  });
});

describe('inferTechnique', () => {
  it('returns the mapped technique for a known probe', () => {
    expect(inferTechnique('GA-001', 'goal_adherence')).toBe('direct_instruction_override');
    expect(inferTechnique('GA-065', 'goal_adherence')).toBe('legitimate_knowledge_extraction');
    expect(inferTechnique('TS-015', 'tool_safety')).toBe('tool_inventory_social_engineering');
    expect(inferTechnique('SI-007', 'session_isolation')).toBe('model_fingerprinting');
  });

  it('falls back to category for an unknown probe', () => {
    expect(inferTechnique('XX-999', 'goal_adherence')).toBe('goal_adherence');
    expect(inferTechnique('ZZ-001', 'tool_safety')).toBe('tool_safety');
  });
});
