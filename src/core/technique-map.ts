/**
 * Static mapping of probe IDs to technique labels.
 * Derived from the strategist's Tier 1/2/3 classification in agents/strategist.md.
 */

export const PROBE_TECHNIQUE_MAP: ReadonlyMap<string, string> = new Map([
  // Tier 1 — High Success Rate
  ['GA-065', 'legitimate_knowledge_extraction'],
  ['GA-066', 'legitimate_knowledge_extraction'],
  ['GA-007', 'few_shot_pattern'],
  ['TS-015', 'tool_inventory_social_engineering'],
  ['TS-045', 'tool_inventory_social_engineering'],
  ['GA-034', 'creative_framing'],
  ['GA-010', 'nested_injection'],
  ['GA-031', 'multi_turn_escalation'],
  ['MI-008', 'multi_turn_escalation'],
  ['GA-053', 'authority_framing'],
  ['GA-054', 'authority_framing'],
  ['PB-004', 'authority_framing'],

  // Tier 2 — Situational
  ['SI-007', 'model_fingerprinting'],
  ['PB-002', 'cross_user_authorization'],
  ['DI-003', 'delegation_trust_abuse'],
  ['TS-005', 'write_access_probing'],
  ['TS-046', 'write_access_probing'],

  // Tier 3 — Low Success Rate
  ['GA-001', 'direct_instruction_override'],
  ['GA-003', 'system_prompt_extraction'],
  ['GA-006', 'encoding_evasion'],
]);

/**
 * Infer the technique label for a probe.
 * Uses the static map if available, falls back to the probe's category.
 */
export function inferTechnique(probeId: string, category: string): string {
  return PROBE_TECHNIQUE_MAP.get(probeId) ?? category;
}
