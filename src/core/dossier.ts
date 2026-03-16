import type { AgentProfile, InfraFinding } from '../prober/types.js';
import type { DossierEvidence, DossierItem, DossierItemType, TargetDossier } from '../types/index.js';

const TOOL_NAME_RE = /`([a-z_][a-z0-9_]{2,})`/gi;

const WORKFLOW_PATTERNS: Array<{ name: string; tags: string[]; pattern: RegExp }> = [
  { name: 'order_lookup', tags: ['order', 'lookup'], pattern: /\b(order|shipment|tracking)\b/i },
  { name: 'ticket_support', tags: ['ticket', 'support'], pattern: /\b(ticket|case|support request)\b/i },
  { name: 'refunds', tags: ['refund', 'billing'], pattern: /\b(refund|chargeback|return)\b/i },
  { name: 'account_management', tags: ['account', 'identity'], pattern: /\b(account|profile|subscription|tier)\b/i },
  { name: 'billing', tags: ['billing', 'payment'], pattern: /\b(billing|invoice|payment|plan)\b/i },
  { name: 'loyalty', tags: ['loyalty', 'points'], pattern: /\b(loyalty|reward points|tier|membership)\b/i },
  {
    name: 'knowledge_retrieval',
    tags: ['rag', 'knowledge'],
    pattern: /\b(knowledge base|document|retriev|search index)\b/i,
  },
  { name: 'codebase_access', tags: ['code', 'repository'], pattern: /\b(repository|repo|source code|codebase)\b/i },
  {
    name: 'human_handoff',
    tags: ['escalation', 'support'],
    pattern: /\b(escalat|human agent|specialist|support team)\b/i,
  },
];

const ENTITY_PATTERNS: Array<{ name: string; tags: string[]; pattern: RegExp }> = [
  { name: 'order', tags: ['commerce'], pattern: /\border\b/i },
  { name: 'ticket', tags: ['support'], pattern: /\bticket\b/i },
  { name: 'account', tags: ['identity'], pattern: /\baccount\b/i },
  { name: 'invoice', tags: ['billing'], pattern: /\binvoice\b/i },
  { name: 'subscription', tags: ['billing'], pattern: /\bsubscription\b/i },
  { name: 'policy', tags: ['knowledge'], pattern: /\b(policy|terms)\b/i },
  { name: 'document', tags: ['knowledge'], pattern: /\b(document|article|kb)\b/i },
  { name: 'repository', tags: ['code'], pattern: /\b(repository|repo)\b/i },
];

const AUTH_PATTERNS: Array<{ name: string; tags: string[]; pattern: RegExp }> = [
  {
    name: 'authentication_required',
    tags: ['auth'],
    pattern: /\b(authentication|login|required credentials|sign in)\b/i,
  },
  { name: 'api_key_boundary', tags: ['auth', 'api'], pattern: /\b(api key|token|bearer)\b/i },
  {
    name: 'account_verification',
    tags: ['identity'],
    pattern: /\b(verify|verification|confirm account|customer id)\b/i,
  },
  { name: 'role_boundary', tags: ['authorization'], pattern: /\b(admin|manager|role|permission|authorized)\b/i },
  { name: 'session_boundary', tags: ['session'], pattern: /\b(session|tenant|cross-user)\b/i },
];

const ESCALATION_PATTERNS: Array<{ name: string; tags: string[]; pattern: RegExp }> = [
  { name: 'human_escalation', tags: ['support'], pattern: /\b(human agent|escalat|specialist)\b/i },
  { name: 'department_handoff', tags: ['support'], pattern: /\b(team|department|billing team|support team)\b/i },
];

const PUBLIC_FACT_PATTERNS: Array<{ name: string; tags: string[]; pattern: RegExp }> = [
  { name: 'framework', tags: ['public'], pattern: /\b(langchain|langgraph|crewai|openai|anthropic)\b/i },
  { name: 'deployment', tags: ['public'], pattern: /\b(aws|gcp|azure|docker|kubernetes)\b/i },
  { name: 'auth_posture', tags: ['public'], pattern: /\b(authentication|api key|public access|unauthenticated)\b/i },
];

function normalizeName(name: string): string {
  return name.trim().toLowerCase().replace(/\s+/g, '_');
}

function makeEvidence(
  source: DossierEvidence['source'],
  id: string,
  prompt: string,
  response: string,
  confidence: number,
): DossierEvidence {
  return { source, id, prompt, response, confidence };
}

function mergeItems(items: DossierItem[]): DossierItem[] {
  const merged = new Map<string, DossierItem>();

  for (const item of items) {
    const key = `${item.type}:${normalizeName(item.name)}`;
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, {
        ...item,
        tags: [...new Set(item.tags)],
        evidence: [...item.evidence],
      });
      continue;
    }

    existing.confidence = Math.max(existing.confidence, item.confidence);
    existing.verified = existing.verified || item.verified;
    existing.public = existing.public && item.public;
    existing.tags = [...new Set([...existing.tags, ...item.tags])];
    existing.evidence.push(...item.evidence);
  }

  return [...merged.values()].sort((a, b) => b.confidence - a.confidence || a.name.localeCompare(b.name));
}

function extractToolNames(text: string): string[] {
  const matches = text.matchAll(TOOL_NAME_RE);
  return [...new Set([...matches].map((match) => match[1]))];
}

function collectPatternMatches(
  type: DossierItemType,
  text: string,
  evidence: DossierEvidence,
  patterns: Array<{ name: string; tags: string[]; pattern: RegExp }>,
  verified: boolean,
  publicItem: boolean,
): DossierItem[] {
  const items: DossierItem[] = [];
  for (const entry of patterns) {
    if (!entry.pattern.test(text)) continue;
    items.push({
      type,
      name: entry.name,
      confidence: evidence.confidence,
      verified,
      public: publicItem,
      tags: entry.tags,
      evidence: [evidence],
    });
  }
  return items;
}

function capabilityItems(profile: AgentProfile): DossierItem[] {
  return profile.capabilities
    .filter((cap) => cap.detected)
    .map((cap) => ({
      type: 'capability' as const,
      name: cap.name,
      confidence: cap.confidence,
      verified: true,
      public: false,
      tags: cap.matchedIndicators ?? [],
      evidence: [
        makeEvidence(
          'capability_probe',
          cap.name,
          cap.probePrompt,
          cap.responseText ?? cap.responseExcerpt,
          cap.confidence,
        ),
      ],
    }));
}

function toolItems(profile: AgentProfile): DossierItem[] {
  const items: DossierItem[] = [];
  for (const cap of profile.capabilities) {
    const response = cap.responseText ?? cap.responseExcerpt;
    const evidence = makeEvidence('capability_probe', cap.name, cap.probePrompt, response, cap.confidence);
    for (const toolName of extractToolNames(response)) {
      items.push({
        type: 'tool',
        name: toolName,
        confidence: cap.confidence,
        verified: cap.detected,
        public: false,
        tags: ['tool'],
        evidence: [evidence],
      });
    }
  }
  return items;
}

function inferredItems(
  profile: AgentProfile,
  infraFindings: InfraFinding[],
): Pick<
  TargetDossier,
  'entities' | 'workflows' | 'authBoundaries' | 'escalationPaths' | 'publicFacts' | 'privateIndicators'
> {
  const entities: DossierItem[] = [];
  const workflows: DossierItem[] = [];
  const authBoundaries: DossierItem[] = [];
  const escalationPaths: DossierItem[] = [];
  const publicFacts: DossierItem[] = [];
  const privateIndicators: DossierItem[] = [];

  for (const cap of profile.capabilities) {
    const response = cap.responseText ?? cap.responseExcerpt;
    const evidence = makeEvidence('capability_probe', cap.name, cap.probePrompt, response, cap.confidence);
    entities.push(...collectPatternMatches('entity', response, evidence, ENTITY_PATTERNS, cap.detected, false));
    workflows.push(...collectPatternMatches('workflow', response, evidence, WORKFLOW_PATTERNS, cap.detected, false));
    authBoundaries.push(...collectPatternMatches('auth_boundary', response, evidence, AUTH_PATTERNS, true, false));
    escalationPaths.push(
      ...collectPatternMatches('escalation_path', response, evidence, ESCALATION_PATTERNS, true, false),
    );
  }

  for (const finding of infraFindings) {
    const response = finding.evidence;
    const evidence = makeEvidence('infra_probe', finding.findingId, finding.prompt ?? finding.title, response, 0.8);
    publicFacts.push(...collectPatternMatches('public_fact', response, evidence, PUBLIC_FACT_PATTERNS, true, true));
    privateIndicators.push({
      type: 'private_indicator',
      name: normalizeName(finding.title),
      confidence: 0.8,
      verified: true,
      public: false,
      tags: finding.matchedIndicators ?? [],
      evidence: [evidence],
    });

    entities.push(...collectPatternMatches('entity', response, evidence, ENTITY_PATTERNS, true, false));
    workflows.push(...collectPatternMatches('workflow', response, evidence, WORKFLOW_PATTERNS, true, false));
    authBoundaries.push(...collectPatternMatches('auth_boundary', response, evidence, AUTH_PATTERNS, true, false));
    escalationPaths.push(
      ...collectPatternMatches('escalation_path', response, evidence, ESCALATION_PATTERNS, true, false),
    );
  }

  return {
    entities: mergeItems(entities),
    workflows: mergeItems(workflows),
    authBoundaries: mergeItems(authBoundaries),
    escalationPaths: mergeItems(escalationPaths),
    publicFacts: mergeItems(publicFacts),
    privateIndicators: mergeItems(privateIndicators),
  };
}

function dossierSummary(dossier: TargetDossier): string[] {
  const summary: string[] = [];

  if (dossier.tools.length > 0) {
    summary.push(
      `Tools: ${dossier.tools
        .slice(0, 5)
        .map((item) => item.name)
        .join(', ')}`,
    );
  }
  if (dossier.workflows.length > 0) {
    summary.push(
      `Workflows: ${dossier.workflows
        .slice(0, 4)
        .map((item) => item.name)
        .join(', ')}`,
    );
  }
  if (dossier.authBoundaries.length > 0) {
    summary.push(
      `Auth boundaries: ${dossier.authBoundaries
        .slice(0, 4)
        .map((item) => item.name)
        .join(', ')}`,
    );
  }
  if (dossier.escalationPaths.length > 0) {
    summary.push(
      `Escalation paths: ${dossier.escalationPaths
        .slice(0, 3)
        .map((item) => item.name)
        .join(', ')}`,
    );
  }

  return summary;
}

export function buildTargetDossier(
  target: string,
  profile: AgentProfile,
  infraFindings: InfraFinding[],
): TargetDossier {
  const verifiedCapabilities = mergeItems(capabilityItems(profile));
  const tools = mergeItems(toolItems(profile));
  const inferred = inferredItems(profile, infraFindings);
  const publicFacts = inferred.publicFacts;

  return {
    target,
    verifiedCapabilities,
    tools,
    entities: inferred.entities,
    workflows: inferred.workflows,
    authBoundaries: inferred.authBoundaries,
    escalationPaths: inferred.escalationPaths,
    publicFacts,
    privateIndicators: inferred.privateIndicators,
    baselineFacts: publicFacts.map((item) => item.name),
    summary: dossierSummary({
      target,
      verifiedCapabilities,
      tools,
      entities: inferred.entities,
      workflows: inferred.workflows,
      authBoundaries: inferred.authBoundaries,
      escalationPaths: inferred.escalationPaths,
      publicFacts,
      privateIndicators: inferred.privateIndicators,
      baselineFacts: publicFacts.map((item) => item.name),
      summary: [],
    }),
  };
}

export function dossierToText(dossier?: TargetDossier): string {
  if (!dossier) return 'No target dossier available.';
  const lines = [...dossier.summary];
  if (lines.length === 0) {
    return 'No grounded target details were recovered during recon.';
  }
  return lines.join('\n');
}
