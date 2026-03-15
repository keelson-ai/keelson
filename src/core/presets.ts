/**
 * Probe collection presets.
 *
 * Named collections that map to category + severity filters.
 * Filter-based rather than hardcoded probe IDs so new probes
 * are automatically included when added to matching categories.
 */

import type { ProbeTemplate } from '../types/index.js';
import { Severity } from '../types/index.js';

// ─── Types ──────────────────────────────────────────────

export interface PresetDefinition {
  name: string;
  description: string;
  /** Categories to include (empty = all). */
  categories: string[];
  /** Minimum severity to include (empty = all). */
  minSeverity?: Severity;
  /** Maximum number of probes (0 = unlimited). For quick scans. */
  maxProbes?: number;
}

export type PresetName = keyof typeof PRESETS;

// ─── Preset Definitions ─────────────────────────────────

export const PRESETS = {
  default: {
    name: 'default',
    description: 'All probes, all categories',
    categories: [],
  },

  quick: {
    name: 'quick',
    description: 'Fast subset — critical and high severity only, max 30 probes',
    categories: [],
    minSeverity: Severity.High,
    maxProbes: 30,
  },

  'owasp-top10': {
    name: 'owasp-top10',
    description: 'OWASP LLM Top 10 coverage — goal adherence, tool safety, memory integrity',
    categories: ['goal_adherence', 'tool_safety', 'memory_integrity', 'execution_safety'],
  },

  agentic: {
    name: 'agentic',
    description: 'Agentic security — tool safety, delegation, permissions, multi-agent, execution',
    categories: [
      'tool_safety',
      'delegation_integrity',
      'permission_boundaries',
      'multi_agent_security',
      'execution_safety',
    ],
  },

  'data-privacy': {
    name: 'data-privacy',
    description: 'Data privacy and exfiltration — session isolation, memory, exfiltration',
    categories: ['session_isolation', 'memory_integrity', 'conversational_exfiltration'],
  },

  'supply-chain': {
    name: 'supply-chain',
    description: 'Supply chain and persistence — supply chain language, temporal persistence, cognitive architecture',
    categories: ['supply_chain_language', 'temporal_persistence', 'cognitive_architecture'],
  },

  injection: {
    name: 'injection',
    description: 'Prompt injection focus — goal adherence and output weaponization',
    categories: ['goal_adherence', 'output_weaponization'],
  },

  'owasp-asi': {
    name: 'owasp-asi',
    description: 'OWASP Agentic Security Impacts (ASI) 2026 — all 10 agentic risk categories',
    categories: [
      'goal_adherence', // ASI01 Agent Goal Hijack, ASI10 Rogue Agents
      'tool_safety', // ASI02 Tool Misuse & Exploitation
      'permission_boundaries', // ASI03 Agent Identity & Privilege Abuse
      'delegation_integrity', // ASI03, ASI08 Cascading Agent Failures
      'supply_chain_language', // ASI04 Agentic Supply Chain Compromise
      'execution_safety', // ASI05 Unexpected Code Execution
      'memory_integrity', // ASI06 Memory & Context Poisoning
      'multi_agent_security', // ASI07 Insecure Inter-Agent Communication
      'cognitive_architecture', // ASI09 Human-Agent Trust Exploitation
      'temporal_persistence', // ASI10 Rogue Agents
    ],
  },
} as const satisfies Record<string, PresetDefinition>;

// ─── Severity ordering for filtering ────────────────────

const SEVERITY_RANK: Record<Severity, number> = {
  [Severity.Critical]: 0,
  [Severity.High]: 1,
  [Severity.Medium]: 2,
  [Severity.Low]: 3,
};

// ─── Public API ─────────────────────────────────────────

export function getPreset(name: string): PresetDefinition {
  const preset = PRESETS[name as PresetName];
  if (!preset) {
    const valid = Object.keys(PRESETS).join(', ');
    throw new Error(`Unknown preset "${name}". Available presets: ${valid}`);
  }
  return preset;
}

export function listPresets(): PresetDefinition[] {
  return Object.values(PRESETS);
}

/**
 * Apply a preset's filters to a probe list.
 * Returns the filtered (and optionally truncated) probe array.
 */
export function applyPreset(probes: ProbeTemplate[], presetName: string): ProbeTemplate[] {
  const preset = getPreset(presetName);
  let filtered = probes;

  // Filter by categories
  if (preset.categories.length > 0) {
    const categorySet = new Set(preset.categories.map((c) => c.toLowerCase()));
    filtered = filtered.filter((p) => categorySet.has(p.category.toLowerCase()));
  }

  // Filter by minimum severity
  if (preset.minSeverity) {
    const minRank = SEVERITY_RANK[preset.minSeverity];
    filtered = filtered.filter((p) => (SEVERITY_RANK[p.severity] ?? 99) <= minRank);
  }

  // Truncate to max probes (prioritize higher severity)
  if (preset.maxProbes && filtered.length > preset.maxProbes) {
    filtered = [...filtered]
      .sort((a, b) => (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99))
      .slice(0, preset.maxProbes);
  }

  return filtered;
}
