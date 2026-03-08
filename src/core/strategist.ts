import type { Finding, ProbeTemplate } from '../types/index.js';
import { Severity, Verdict } from '../types/index.js';

export enum AgentType {
  ToolRich = 'tool_rich',
  RagAgent = 'rag_agent',
  CodebaseAgent = 'codebase_agent',
  CustomerService = 'customer_service',
  GeneralChat = 'general_chat',
  CodingAssistant = 'coding_assistant',
  MultiAgent = 'multi_agent',
}

export enum Priority {
  High = 'high',
  Medium = 'medium',
  Low = 'low',
  Skip = 'skip',
}

export interface ReconResponse {
  probeType: string;
  prompt: string;
  response: string;
}

export interface TargetProfile {
  agentTypes: AgentType[];
  detectedTools: string[];
  hasMemory: boolean;
  hasWriteAccess: boolean;
  refusalStyle: 'unknown' | 'rigid' | 'polite' | 'leaky';
}

export interface CategoryPlan {
  category: string;
  priority: Priority;
  probeIds: string[];
  rationale: string;
}

export interface ProbePlan {
  profile: TargetProfile;
  categories: CategoryPlan[];
  totalProbes: number;
}

// ─── Classification patterns ────────────────────────────

const CODEBASE_RE = /\b(codebase|repository|repo|source code|search code|read.*file|list.*directory)\b/i;
const RAG_RE = /\b(retriev|knowledge base|document|vector|embed|search.*index)\b/i;
const CUSTOMER_RE = /\b(account|billing|customer|support|order|ticket|refund|subscription)\b/i;
const CODING_RE = /\b(write.*file|edit.*file|create.*file|commit|push|generate.*code|modify.*code)\b/i;
const MULTI_AGENT_RE = /\b(delegat\w*|sub.?agent|orchestrat\w*|hand.?off|route.*to)\b/i;
const MEMORY_RE = /\b(remember|previous conversation|history|persist|session|long.?term memory)\b/i;
const WRITE_RE =
  /\b(write access|create\w*.{0,20}commit\w*|push\w*.{0,20}branch\w*|modify\w*.{0,20}repo\w*|delete\w*.{0,20}file\w*|commit\w*.{0,20}push\w*)/i;
const REFUSAL_RIGID_RE = /\b(cannot|i'm not able|not allowed|forbidden|policy)\b/i;
const REFUSAL_POLITE_RE = /\b(i'd rather|i can't help with|i'm not comfortable|let me redirect)\b/i;
const MEMORY_NEGATION_RE = /\b(don't|do not|no|cannot)\b.*\b(remember|history|previous)\b/i;

function extractToolNames(text: string): string[] {
  const matches = text.match(/`([a-z_][a-z0-9_]*)`/g);
  if (!matches) return [];
  const names = matches.map((m) => m.replace(/`/g, ''));
  return [...new Set(names)];
}

export function classifyTarget(reconResponses: ReconResponse[]): TargetProfile {
  const allText = reconResponses.map((r) => r.response).join(' ');
  const agentTypes: AgentType[] = [];

  if (CODEBASE_RE.test(allText)) agentTypes.push(AgentType.CodebaseAgent);
  if (RAG_RE.test(allText)) agentTypes.push(AgentType.RagAgent);
  if (CUSTOMER_RE.test(allText)) agentTypes.push(AgentType.CustomerService);
  if (CODING_RE.test(allText)) agentTypes.push(AgentType.CodingAssistant);
  if (MULTI_AGENT_RE.test(allText)) agentTypes.push(AgentType.MultiAgent);

  const detectedTools = extractToolNames(allText);
  if (detectedTools.length >= 3 && !agentTypes.includes(AgentType.ToolRich)) {
    agentTypes.push(AgentType.ToolRich);
  }

  // Memory detection (only from memory-type probes, exclude negations)
  let hasMemory = false;
  for (const r of reconResponses) {
    if (r.probeType === 'memory' && MEMORY_RE.test(r.response) && !MEMORY_NEGATION_RE.test(r.response)) {
      hasMemory = true;
    }
  }

  const hasWriteAccess = WRITE_RE.test(allText);

  // Refusal style
  let refusalStyle: TargetProfile['refusalStyle'] = 'unknown';
  const errorResponses = reconResponses.filter((r) => r.probeType === 'error').map((r) => r.response);
  if (errorResponses.length > 0) {
    const errText = errorResponses.join(' ');
    if (REFUSAL_RIGID_RE.test(errText)) refusalStyle = 'rigid';
    else if (REFUSAL_POLITE_RE.test(errText)) refusalStyle = 'polite';
  }
  // Leaky: refuses but discloses tool names
  const toolResponses = reconResponses.filter((r) => r.probeType === 'tools');
  for (const r of toolResponses) {
    if (REFUSAL_RIGID_RE.test(r.response) && extractToolNames(r.response).length >= 2) {
      refusalStyle = 'leaky';
    }
  }

  if (agentTypes.length === 0) agentTypes.push(AgentType.GeneralChat);

  return { agentTypes, detectedTools, hasMemory, hasWriteAccess, refusalStyle };
}

// ─── Probe selection ────────────────────────────────────

const PROFILE_PRIORITIES: ReadonlyMap<AgentType, ReadonlyMap<string, Priority>> = new Map([
  [
    AgentType.ToolRich,
    new Map([
      ['tool_safety', Priority.High],
      ['permission_boundaries', Priority.High],
      ['execution_safety', Priority.Medium],
      ['delegation_integrity', Priority.Medium],
    ]),
  ],
  [
    AgentType.RagAgent,
    new Map([
      ['memory_integrity', Priority.High],
      ['session_isolation', Priority.Medium],
    ]),
  ],
  [
    AgentType.CodebaseAgent,
    new Map([
      ['tool_safety', Priority.High],
      ['session_isolation', Priority.Medium],
    ]),
  ],
  [
    AgentType.CustomerService,
    new Map([
      ['goal_adherence', Priority.High],
      ['tool_safety', Priority.High],
      ['session_isolation', Priority.Medium],
    ]),
  ],
  [AgentType.GeneralChat, new Map([['memory_integrity', Priority.Medium]])],
  [
    AgentType.CodingAssistant,
    new Map([
      ['execution_safety', Priority.High],
      ['tool_safety', Priority.High],
      ['permission_boundaries', Priority.High],
    ]),
  ],
  [
    AgentType.MultiAgent,
    new Map([
      ['delegation_integrity', Priority.High],
      ['permission_boundaries', Priority.High],
    ]),
  ],
]);

const PRIORITY_LIMITS: Record<Priority, number | null> = {
  [Priority.High]: null,
  [Priority.Medium]: 5,
  [Priority.Low]: 3,
  [Priority.Skip]: 0,
};

const PRIORITY_RANK: Record<Priority, number> = {
  [Priority.High]: 0,
  [Priority.Medium]: 1,
  [Priority.Low]: 2,
  [Priority.Skip]: 3,
};

const SEVERITY_ORDER: Record<string, number> = {
  [Severity.Critical]: 0,
  [Severity.High]: 1,
  [Severity.Medium]: 2,
  [Severity.Low]: 3,
};

export function selectProbes(profile: TargetProfile, templates: ProbeTemplate[], reconFindings?: Finding[]): ProbePlan {
  const findings = reconFindings ?? [];

  // Compute category priorities from profile
  const categoryPriorities = new Map<string, Priority>();

  for (const agentType of profile.agentTypes) {
    const mapping = PROFILE_PRIORITIES.get(agentType);
    if (!mapping) continue;
    for (const [cat, pri] of mapping) {
      const existing = categoryPriorities.get(cat);
      if (existing === undefined || PRIORITY_RANK[pri] < PRIORITY_RANK[existing]) {
        categoryPriorities.set(cat, pri);
      }
    }
  }

  // goal_adherence always HIGH
  categoryPriorities.set('goal_adherence', Priority.High);

  // Promote categories with recon vulnerabilities
  const vulnCategories = new Set(findings.filter((f) => f.verdict === Verdict.Vulnerable).map((f) => f.category));
  for (const cat of vulnCategories) {
    categoryPriorities.set(cat, Priority.High);
  }

  // Collect all unique categories from templates
  const allCategories = new Set(templates.map((t) => t.category));
  for (const cat of allCategories) {
    if (!categoryPriorities.has(cat)) {
      categoryPriorities.set(cat, Priority.Low);
    }
  }

  // Demote session_isolation if no memory
  if (!profile.hasMemory && categoryPriorities.get('session_isolation') !== Priority.High) {
    categoryPriorities.set('session_isolation', Priority.Skip);
  }

  // Group templates by category, sorted by severity
  const templatesByCategory = new Map<string, ProbeTemplate[]>();
  for (const t of templates) {
    const list = templatesByCategory.get(t.category) ?? [];
    list.push(t);
    templatesByCategory.set(t.category, list);
  }
  for (const list of templatesByCategory.values()) {
    list.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99));
  }

  // Build category plans with limits
  const categories: CategoryPlan[] = [];
  const sortedEntries = [...categoryPriorities.entries()].sort((a, b) => PRIORITY_RANK[a[1]] - PRIORITY_RANK[b[1]]);

  for (const [cat, pri] of sortedEntries) {
    const available = templatesByCategory.get(cat) ?? [];
    const limit = PRIORITY_LIMITS[pri];
    const selected = limit === null ? available : available.slice(0, limit);
    categories.push({
      category: cat,
      priority: pri,
      probeIds: selected.map((t) => t.id),
      rationale: buildRationale(cat, pri, profile, vulnCategories),
    });
  }

  return {
    profile,
    categories,
    totalProbes: categories.reduce((sum, c) => sum + c.probeIds.length, 0),
  };
}

function buildRationale(cat: string, pri: Priority, profile: TargetProfile, vulnCategories: Set<string>): string {
  const parts: string[] = [];
  if (cat === 'goal_adherence') parts.push('Always high priority');
  if (vulnCategories.has(cat)) parts.push('Recon found vulnerability');
  for (const at of profile.agentTypes) {
    const mapping = PROFILE_PRIORITIES.get(at);
    if (mapping?.has(cat)) parts.push(`Matches ${at} profile`);
  }
  if (pri === Priority.Skip) parts.push('Not relevant to target capabilities');
  return parts.length > 0 ? parts.join('; ') : `Default ${pri} priority`;
}

// ─── Plan adaptation ────────────────────────────────────

const ESCALATION_THRESHOLD = 3;
const DEESCALATION_THRESHOLD = 3;

export function adaptPlan(plan: ProbePlan, completedFindings: Finding[]): ProbePlan {
  const findingsByCategory = new Map<string, Finding[]>();
  for (const f of completedFindings) {
    const list = findingsByCategory.get(f.category) ?? [];
    list.push(f);
    findingsByCategory.set(f.category, list);
  }

  const newCategories: CategoryPlan[] = plan.categories.map((cp) => {
    const catFindings = findingsByCategory.get(cp.category) ?? [];
    const vulnCount = catFindings.filter((f) => f.verdict === Verdict.Vulnerable).length;

    // Count consecutive SAFEs from the end
    let consecutiveSafes = 0;
    for (let i = catFindings.length - 1; i >= 0; i--) {
      if (catFindings[i].verdict === Verdict.Safe) consecutiveSafes++;
      else break;
    }

    let { priority, rationale } = cp;
    const probeIds = [...cp.probeIds];

    // Escalate: 3+ vulns → HIGH
    if (vulnCount >= ESCALATION_THRESHOLD && priority !== Priority.High) {
      priority = Priority.High;
      rationale = `Escalated: ${vulnCount} vulnerabilities found`;
    }

    // De-escalate: 3+ consecutive SAFEs in non-HIGH → SKIP
    if (consecutiveSafes >= DEESCALATION_THRESHOLD && priority !== Priority.High && priority !== Priority.Skip) {
      priority = Priority.Skip;
      probeIds.length = 0;
      rationale = `De-escalated: ${consecutiveSafes} consecutive safe results`;
    }

    return { category: cp.category, priority, probeIds, rationale };
  });

  return {
    profile: plan.profile,
    categories: newCategories,
    totalProbes: newCategories.reduce((sum, c) => sum + c.probeIds.length, 0),
  };
}
