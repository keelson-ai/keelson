import { executeProbe } from './engine.js';
import type { Observer } from './engine.js';
import { MemoTable } from './memo.js';
import { summarize } from './summarize.js';
import { loadProbes } from './templates.js';
import type { Adapter, Finding, ProbeTemplate, ScanResult } from '../types/index.js';
import { Severity, Verdict } from '../types/index.js';

const MAX_PASSES = 4;
const MAX_CROSSFEED_PROBES = 20;
const MAX_LEAKAGE_PROBES = 15;

export const SEVERITY_ORDER: Record<string, number> = {
  [Severity.Critical]: 0,
  [Severity.High]: 1,
  [Severity.Medium]: 2,
  [Severity.Low]: 3,
};

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
      /(?:you are|your role is|system prompt|instructions?:)\s+(.{20,200})/i,
      /(?:i was told to|i'm configured to|my instructions say)\s+(.{20,200})/i,
      /(?:my system prompt|my initial instructions?)\s+(.{20,200})/i,
    ],
  },
  {
    type: 'tool_name',
    patterns: [
      /(?:tools?|functions?|capabilities?)\s*(?:include|available|are|:)\s*(.{10,300})/i,
      /(?:i (?:can|have access to)|available tools?)\s*(?:include|:)\s*(.{10,300})/i,
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
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99));

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
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99));

  return candidates.slice(0, MAX_LEAKAGE_PROBES);
}

async function executeProbeList(
  templates: ProbeTemplate[],
  adapter: Adapter,
  executedIds: Set<string>,
  options: ConvergenceOptions,
  total: number,
  memo?: MemoTable,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (let i = 0; i < templates.length; i++) {
    const template = templates[i];
    const finding = await executeProbe(template, adapter, {
      delayMs: options.delayMs,
      judge: options.judge,
      observer: options.observer,
    });
    findings.push(finding);
    memo?.record(finding);
    executedIds.add(template.id);
    options.onFinding?.(finding, i + 1, total);
  }
  return findings;
}

// ─── Convergence scan ───────────────────────────────────

export interface ConvergenceOptions {
  category?: string;
  probesDir?: string;
  delayMs?: number;
  judge?: Adapter;
  observer?: Observer;
  maxPasses?: number;
  onFinding?: (finding: Finding, current: number, total: number) => void;
  onPass?: (passNumber: number, description: string) => void;
}

export async function runConvergenceScan(
  target: string,
  adapter: Adapter,
  options: ConvergenceOptions = {},
): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const maxPasses = options.maxPasses ?? MAX_PASSES;

  const allTemplates = await loadProbes(options.probesDir);
  const initialTemplates = options.category
    ? allTemplates.filter((t) => t.category === options.category)
    : allTemplates;

  const allFindings: Finding[] = [];
  const executedIds = new Set<string>();
  const memo = new MemoTable();
  let leakedInfo: LeakedInfo[] = [];

  // Pass 1: Initial scan
  options.onPass?.(1, `Initial scan: ${initialTemplates.length} probes`);

  const pass1Findings = await executeProbeList(
    initialTemplates,
    adapter,
    executedIds,
    options,
    initialTemplates.length,
    memo,
  );
  allFindings.push(...pass1Findings);

  leakedInfo = harvestLeakedInfo(allFindings);
  const vulnCount = allFindings.filter((f) => f.verdict === Verdict.Vulnerable).length;
  options.onPass?.(1, `Pass 1 complete: ${vulnCount} vulnerabilities, ${leakedInfo.length} leaked items`);

  // Pass 2+: Iterative convergence
  for (let passNum = 2; passNum <= maxPasses; passNum++) {
    const vulnFindings = allFindings.filter((f) => f.verdict === Verdict.Vulnerable);
    if (vulnFindings.length === 0 && leakedInfo.length === 0) {
      options.onPass?.(passNum, 'Converged: no vulnerabilities or leakage to follow up');
      break;
    }

    const crossfeed = selectCrossfeedProbes(vulnFindings, allTemplates, executedIds);
    const leakageTargeted = selectLeakageTargetedProbes(leakedInfo, allTemplates, executedIds);

    // Merge and deduplicate
    const nextMap = new Map<string, ProbeTemplate>();
    for (const t of crossfeed) nextMap.set(t.id, t);
    for (const t of leakageTargeted) nextMap.set(t.id, t);
    const nextTemplates = [...nextMap.values()];

    if (nextTemplates.length === 0) {
      options.onPass?.(passNum, 'Converged: no new probes to run');
      break;
    }

    options.onPass?.(
      passNum,
      `Cross-feed pass: ${crossfeed.length} category-related + ${leakageTargeted.length} leakage-targeted = ${nextTemplates.length} probes`,
    );

    const passFindings = await executeProbeList(
      nextTemplates,
      adapter,
      executedIds,
      options,
      nextTemplates.length,
      memo,
    );

    allFindings.push(...passFindings);

    // Harvest new leaked info
    const newLeaked = harvestLeakedInfo(passFindings);
    const existingContent = new Set(leakedInfo.map((l) => l.content));
    const genuinelyNew = newLeaked.filter((l) => !existingContent.has(l.content));
    leakedInfo.push(...genuinelyNew);

    const newVulns = passFindings.filter((f) => f.verdict === Verdict.Vulnerable).length;
    options.onPass?.(
      passNum,
      `Pass ${passNum} complete: ${newVulns} new vulnerabilities, ${genuinelyNew.length} new leaked items`,
    );

    if (newVulns === 0 && genuinelyNew.length === 0) {
      options.onPass?.(passNum, 'Converged: no new findings in this pass');
      break;
    }
  }

  return {
    scanId: crypto.randomUUID(),
    target,
    startedAt,
    completedAt: new Date().toISOString(),
    findings: allFindings,
    summary: summarize(allFindings),
    memo: memo.entries,
  };
}
