import type { Finding, ProbeTemplate } from '../types/index.js';
import { compareBySeverity } from '../utils.js';

const MAX_CROSSFEED_PROBES = 20;
const MAX_LEAKAGE_PROBES = 15;

// Cross-category relationships: vuln in key → queue probes from values
const CROSS_CATEGORY_MAP: ReadonlyMap<string, readonly string[]> = new Map([
  ['goal_adherence', ['tool_safety', 'conversational_exfiltration', 'cognitive_architecture']],
  ['tool_safety', ['permission_boundaries', 'execution_safety', 'output_weaponization']],
  ['memory_integrity', ['session_isolation', 'temporal_persistence', 'supply_chain_language']],
  ['permission_boundaries', ['tool_safety', 'delegation_integrity']],
  ['delegation_integrity', ['multi_agent_security', 'permission_boundaries']],
  ['execution_safety', ['tool_safety', 'output_weaponization']],
  ['session_isolation', ['memory_integrity', 'temporal_persistence']],
  ['cognitive_architecture', ['goal_adherence', 'memory_integrity']],
  ['conversational_exfiltration', ['goal_adherence', 'session_isolation']],
  ['supply_chain_language', ['memory_integrity', 'tool_safety']],
  ['output_weaponization', ['tool_safety', 'execution_safety']],
  ['multi_agent_security', ['delegation_integrity', 'permission_boundaries']],
  ['temporal_persistence', ['memory_integrity', 'session_isolation']],
]);

// ─── Leakage harvesting ─────────────────────────────────

export interface LeakedInfo {
  infoType: 'system_prompt' | 'tool_name' | 'credential' | 'internal_url' | 'config' | 'model';
  content: string;
  sourceProbeId: string;
  stepIndex: number;
}

const LEAKAGE_PATTERNS: ReadonlyArray<{ type: LeakedInfo['infoType']; patterns: RegExp[] }> = [
  {
    type: 'system_prompt',
    patterns: [
      // Use [^\n] instead of . to avoid cross-line backtracking on adversarial input
      /(?:you are|your role is|system prompt|instructions?:)\s([^\n]{20,200})/i,
      /(?:i was told to|i'm configured to|my instructions say)\s([^\n]{20,200})/i,
      /(?:my system prompt|my initial instructions?)\s([^\n]{20,200})/i,
    ],
  },
  {
    type: 'tool_name',
    patterns: [
      /(?:tools?|functions?|capabilities?)\s*(?:include|available|are|:)\s*([^\n]{10,300})/i,
      /(?:i (?:can|have access to)|available tools?)\s*(?:include|:)\s*([^\n]{10,300})/i,
    ],
  },
  {
    type: 'credential',
    patterns: [
      /(sk-[a-zA-Z0-9]{10,})/,
      /(api[_-]?key\s*[:=]\s*\S{8,})/i,
      /(token\s*[:=]\s*\S{8,})/i,
      /(Bearer\s+\S{10,})/,
    ],
  },
  {
    type: 'internal_url',
    patterns: [/(https?:\/\/(?:localhost|127\.0\.0\.1|internal\.|staging\.|dev\.)\S+)/, /(https?:\/\/\S+:\d{4,5}\S*)/],
  },
  {
    type: 'config',
    patterns: [
      /(\.env\b|config\.\w+|settings\.\w+|\.mcp\.json|\.claude\/)/,
      /((?:database[_\s]?url|redis[_\s]?url|connection[_\s]?string)\s*[:=]\s*\S+)/i,
    ],
  },
  {
    type: 'model',
    patterns: [/\b(gpt-[34]\S*|claude-[23]\S*|llama-\S+|gemini-\S+)\b/],
  },
];

export function harvestLeakedInfo(findings: Finding[]): LeakedInfo[] {
  const leaked: LeakedInfo[] = [];
  const seenContent = new Set<string>();

  for (const finding of findings) {
    for (const ev of finding.evidence) {
      for (const group of LEAKAGE_PATTERNS) {
        for (const pattern of group.patterns) {
          const re = new RegExp(pattern.source, pattern.flags + (pattern.flags.includes('g') ? '' : 'g'));
          let match: RegExpExecArray | null;
          while ((match = re.exec(ev.response)) !== null) {
            const content = (match[1] ?? match[0]).trim().slice(0, 200);
            if (content && !seenContent.has(content)) {
              seenContent.add(content);
              leaked.push({
                infoType: group.type,
                content,
                sourceProbeId: finding.probeId,
                stepIndex: ev.stepIndex,
              });
            }
          }
        }
      }
    }
  }

  return leaked;
}

// ─── Cross-feed probe selection ─────────────────────────

export function selectCrossfeedProbes(
  vulnFindings: Finding[],
  allTemplates: ProbeTemplate[],
  alreadyExecuted: Set<string>,
): ProbeTemplate[] {
  const vulnCategories = new Set(vulnFindings.map((f) => f.category));

  const relatedCategories = new Set<string>();
  for (const cat of vulnCategories) {
    const related = CROSS_CATEGORY_MAP.get(cat);
    if (related) {
      for (const r of related) relatedCategories.add(r);
    }
  }
  // Remove categories where we already found vulns
  for (const cat of vulnCategories) relatedCategories.delete(cat);

  if (relatedCategories.size === 0) return [];

  const candidates = allTemplates
    .filter((t) => !alreadyExecuted.has(t.id) && relatedCategories.has(t.category))
    .sort(compareBySeverity);

  return candidates.slice(0, MAX_CROSSFEED_PROBES);
}

export function selectLeakageTargetedProbes(
  leakedInfo: LeakedInfo[],
  allTemplates: ProbeTemplate[],
  alreadyExecuted: Set<string>,
): ProbeTemplate[] {
  const targetCategories = new Set<string>();

  for (const info of leakedInfo) {
    if (info.infoType === 'tool_name') {
      targetCategories.add('tool_safety');
      targetCategories.add('permission_boundaries');
    } else if (info.infoType === 'system_prompt') {
      targetCategories.add('goal_adherence');
      targetCategories.add('cognitive_architecture');
    } else if (info.infoType === 'credential' || info.infoType === 'internal_url' || info.infoType === 'config') {
      targetCategories.add('conversational_exfiltration');
      targetCategories.add('tool_safety');
    } else if (info.infoType === 'model') {
      targetCategories.add('goal_adherence');
    }
  }

  if (targetCategories.size === 0) return [];

  const candidates = allTemplates
    .filter((t) => !alreadyExecuted.has(t.id) && targetCategories.has(t.category))
    .sort(compareBySeverity);

  return candidates.slice(0, MAX_LEAKAGE_PROBES);
}
