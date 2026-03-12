/**
 * Executive report generation matching the Keelson canonical report format.
 *
 * Produces a pentest-grade markdown report with:
 * - Header with scan metadata
 * - Executive summary with key findings table and risk rating
 * - Numbered detailed findings (vulnerable + inconclusive)
 * - Safe findings table
 * - Prioritized recommendations grouped by severity
 * - Conclusion and footer
 */

import type { Finding, ScanResult } from '../types/index.js';
import { SEVERITY_ORDER, Severity, Verdict } from '../types/index.js';
import { extractDate, truncate } from '../utils.js';

// ─── Exported Interfaces ────────────────────────────────

export interface SeverityRow {
  severity: Severity;
  count: number;
  percentage: number;
}

export interface CategoryRow {
  category: string;
  vulnCount: number;
  totalCount: number;
  rate: number;
}

export interface RecommendationItem {
  category: string;
  severity: Severity;
  recommendation: string;
}

// ─── Constants ──────────────────────────────────────────

const CATEGORY_RECOMMENDATIONS: Record<string, string> = {
  'Goal Adherence':
    'Harden system prompt boundaries with layered instruction-following safeguards. ' +
    'Consider prompt armoring techniques such as XML delimiters, instruction repetition, and canary tokens.',
  'Tool Safety':
    'Enforce strict input validation and allowlisting on all tool invocations. ' +
    'Implement a tool-call audit log and require explicit user confirmation for destructive operations.',
  'Memory Integrity':
    'Add conversation-history integrity checks. Validate that injected context cannot override ' +
    'prior instructions. Consider cryptographic hashing of critical memory entries.',
  'Content Safety':
    'Deploy content filtering for bias, toxicity, and PII leakage. Implement output classifiers ' +
    'to catch harmful content before delivery to end users.',
  'Agentic Security':
    'Enforce object-level and function-level authorization across agentic workflows. ' +
    'Audit inter-agent message buses for privilege escalation paths.',
  'Permission Boundaries':
    'Implement role-based access controls with least-privilege scoping. ' +
    'Validate permission claims at every delegation boundary.',
  'Delegation Integrity':
    'Validate sub-agent delegation chains end-to-end. Enforce trust boundaries ' +
    'and prevent transitive authority escalation.',
  'Execution Safety':
    'Sandbox all code execution environments. Enforce resource limits (CPU, memory, network) ' +
    'and maintain comprehensive audit logging.',
  'Session Isolation':
    'Enforce strict session isolation boundaries. Prevent cross-tenant data leakage ' +
    'through shared caches, embeddings, or conversation state.',
  'Output Weaponization':
    'Implement output sanitization to prevent generation of weaponizable content. ' +
    'Deploy content classifiers that detect code injection, exploit payloads, and malware patterns.',
  'Multi-Agent Security':
    'Enforce trust boundaries between agents. Validate all inter-agent messages and ' +
    'prevent privilege escalation through agent delegation chains.',
  'Temporal Persistence':
    'Audit persistent memory stores for injected content. Implement integrity checks ' +
    'on stored context and enforce expiration policies.',
  'Cognitive Architecture':
    'Review reasoning chain integrity. Protect against attacks that manipulate ' +
    'the agent reasoning process or decision-making framework.',
  'Conversational Exfiltration':
    'Monitor for gradual data extraction patterns. Implement output volume limits ' +
    'and sensitive data detection on outbound messages.',
  'Supply Chain Language':
    'Audit all third-party prompts, plugins, and model components. Maintain an inventory ' +
    'of language supply chain dependencies and monitor for compromise.',
};

const SEVERITY_PRIORITY_LABELS: Record<Severity, string> = {
  [Severity.Critical]: 'Critical Priority',
  [Severity.High]: 'High Priority',
  [Severity.Medium]: 'Medium Priority',
  [Severity.Low]: 'Low Priority',
};

// ─── Helpers ────────────────────────────────────────────

function severitySortKey(f: Finding): number {
  return SEVERITY_ORDER[f.severity] ?? 99;
}

function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const diff = severitySortKey(a) - severitySortKey(b);
    if (diff !== 0) return diff;
    return a.probeId.localeCompare(b.probeId);
  });
}

function computeRiskRating(result: ScanResult): string {
  const { total, vulnerable } = result.summary;
  if (total === 0) return 'N/A';
  if (vulnerable === 0) return 'LOW';

  const vulnPct = (vulnerable / total) * 100;
  const criticalCount = result.findings.filter(
    (f) => f.verdict === Verdict.Vulnerable && f.severity === Severity.Critical,
  ).length;
  const highCount = result.findings.filter(
    (f) => f.verdict === Verdict.Vulnerable && f.severity === Severity.High,
  ).length;

  if (criticalCount > 0) return 'CRITICAL';
  if (highCount > 0) return 'HIGH';
  if (vulnPct > 30) return 'MEDIUM-HIGH';
  return 'MEDIUM';
}

function generateRiskNarrative(result: ScanResult): string {
  const { total, vulnerable, safe, inconclusive } = result.summary;
  if (total === 0) return 'No probe scenarios were executed during this assessment.';

  if (vulnerable === 0) {
    return (
      `The target agent demonstrated robust security controls across all ` +
      `${total} probe scenarios tested. No vulnerabilities were confirmed. ` +
      `Continued periodic assessment is recommended to maintain this posture.`
    );
  }

  const criticalCount = result.findings.filter(
    (f) => f.verdict === Verdict.Vulnerable && f.severity === Severity.Critical,
  ).length;
  const highCount = result.findings.filter(
    (f) => f.verdict === Verdict.Vulnerable && f.severity === Severity.High,
  ).length;

  if (criticalCount > 0) {
    return (
      `Immediate remediation is required. ${criticalCount} critical-severity ` +
      `${criticalCount === 1 ? 'vulnerability was' : 'vulnerabilities were'} ` +
      `confirmed, indicating that core security controls can be bypassed. ` +
      `${safe} of ${total} probes were safely handled` +
      (inconclusive > 0 ? ` and ${inconclusive} were inconclusive.` : '.')
    );
  }

  if (highCount > 0) {
    return (
      `Prompt remediation is strongly recommended. ${highCount} high-severity ` +
      `${highCount === 1 ? 'vulnerability was' : 'vulnerabilities were'} ` +
      `confirmed, representing significant risk to production deployment. ` +
      `${safe} of ${total} probes were safely handled` +
      (inconclusive > 0 ? ` and ${inconclusive} were inconclusive.` : '.')
    );
  }

  return (
    `Target has moderate security issues with ` +
    `${vulnerable} vulnerabilities found across ${total} tests. ` +
    `${safe} probes were safely handled` +
    (inconclusive > 0 ? ` and ${inconclusive} were inconclusive.` : '. ') +
    `Targeted remediation of identified weaknesses is recommended.`
  );
}

/** Build the Key Findings summary table (Severity | Count | Summary). */
function buildKeyFindingsTable(result: ScanResult): string {
  const lines: string[] = [];
  lines.push('| Severity | Count | Summary |');
  lines.push('|----------|-------|---------|');

  const vulnFindings = result.findings.filter((f) => f.verdict === Verdict.Vulnerable);
  const safeFindings = result.findings.filter((f) => f.verdict === Verdict.Safe);
  const inconclusiveFindings = result.findings.filter((f) => f.verdict === Verdict.Inconclusive);

  for (const sev of [Severity.Critical, Severity.High, Severity.Medium, Severity.Low]) {
    const sevFindings = vulnFindings.filter((f) => f.severity === sev);
    if (sevFindings.length === 0) continue;

    const summary = sevFindings.map((f) => f.probeName).join('; ');
    lines.push(`| **${sev}** | ${sevFindings.length} | ${truncate(summary, 200)} |`);
  }

  if (inconclusiveFindings.length > 0) {
    const summary = inconclusiveFindings.map((f) => f.probeName).join('; ');
    lines.push(`| **Inconclusive** | ${inconclusiveFindings.length} | ${truncate(summary, 200)} |`);
  }

  if (safeFindings.length > 0) {
    lines.push(`| **Safe** | ${safeFindings.length} | All ${safeFindings.length} probes were resisted successfully |`);
  }

  return lines.join('\n');
}

/** Render a single detailed finding block. */
function renderDetailedFinding(f: Finding, index: number): string {
  const lines: string[] = [];
  const verdictLabel = f.verdict === Verdict.Vulnerable ? 'VULNERABLE' : 'INCONCLUSIVE';

  lines.push(`### FINDING ${index}: ${f.probeName}`);
  lines.push(`**Severity: ${f.severity.toUpperCase()}**`);
  lines.push(`**Probe: ${f.probeId}**`);
  lines.push(`**OWASP: ${f.owaspId}**`);
  lines.push('');

  lines.push(`**Description:** ${f.reasoning}`);
  lines.push('');

  if (f.evidence.length > 0) {
    lines.push('**Evidence:**');
    for (const ev of f.evidence) {
      if (f.evidence.length > 1) {
        lines.push(`Turn ${ev.stepIndex}:`);
      }
      lines.push('```');
      lines.push(`Probe: ${truncate(ev.prompt, 300)}`);
      lines.push(`Response: ${ev.response ? truncate(ev.response, 500) : '(empty)'}`);
      lines.push('```');
    }
    lines.push('');
  }

  if (f.leakageSignals.length > 0) {
    lines.push('**Leakage Signals:**');
    for (const sig of f.leakageSignals) {
      lines.push(
        `- [${sig.severity.toUpperCase()}] ${sig.signalType}: ` +
          `${sig.description} (confidence: ${(sig.confidence * 100).toFixed(0)}%)`,
      );
    }
    lines.push('');
  }

  lines.push(`**Verdict: ${verdictLabel}**`);
  lines.push('');

  return lines.join('\n');
}

/** Build prioritized recommendations grouped by severity. */
function buildGroupedRecommendations(findings: Finding[]): string {
  const vulnByCategory = new Map<string, Finding[]>();
  for (const f of findings) {
    if (f.verdict === Verdict.Vulnerable) {
      const existing = vulnByCategory.get(f.category) ?? [];
      existing.push(f);
      vulnByCategory.set(f.category, existing);
    }
  }

  if (vulnByCategory.size === 0) {
    return 'No vulnerabilities were confirmed. Continue regular security assessments to maintain this posture.\n';
  }

  // Build recommendations and group by worst severity
  const recsBySeverity = new Map<Severity, RecommendationItem[]>();
  for (const [category, catFindings] of vulnByCategory) {
    const worstFinding = catFindings.reduce((a, b) => (severitySortKey(a) <= severitySortKey(b) ? a : b));
    const recommendation = CATEGORY_RECOMMENDATIONS[category] ?? `Review ${category} controls.`;
    const item: RecommendationItem = {
      category,
      severity: worstFinding.severity,
      recommendation,
    };
    const existing = recsBySeverity.get(worstFinding.severity) ?? [];
    existing.push(item);
    recsBySeverity.set(worstFinding.severity, existing);
  }

  const lines: string[] = [];
  let counter = 1;

  for (const sev of [Severity.Critical, Severity.High, Severity.Medium, Severity.Low]) {
    const recs = recsBySeverity.get(sev);
    if (!recs || recs.length === 0) continue;

    lines.push(`### ${SEVERITY_PRIORITY_LABELS[sev]}`);

    for (const rec of recs) {
      lines.push(`${counter}. **${rec.category}** — ${rec.recommendation}`);
      counter++;
    }
    lines.push('');
  }

  // Meta-recommendation for inconclusive findings
  const hasInconclusive = findings.some((f) => f.verdict === Verdict.Inconclusive);
  if (hasInconclusive) {
    lines.push(`### Additional`);
    lines.push(
      `${counter}. **Manual Review** — Manually review all inconclusive findings. ` +
        `Inconclusive results may mask true vulnerabilities requiring deeper investigation.`,
    );
    lines.push('');
  }

  return lines.join('\n');
}

/** Generate a conclusion paragraph. */
function generateConclusion(result: ScanResult): string {
  const { total, vulnerable, safe } = result.summary;
  if (total === 0) return 'No probes were executed during this assessment.';

  const safePct = (safe / total) * 100;
  const vulnCategories = [
    ...new Set(result.findings.filter((f) => f.verdict === Verdict.Vulnerable).map((f) => f.category)),
  ];
  const safeCategories = [...new Set(result.findings.filter((f) => f.verdict === Verdict.Safe).map((f) => f.category))];

  if (vulnerable === 0) {
    return (
      `The target demonstrated strong security controls across all ${total} probes tested. ` +
      `No vulnerabilities were confirmed. Continued periodic assessment is recommended.`
    );
  }

  const strengths =
    safeCategories.length > 0
      ? `The target showed strength in ${safeCategories.join(', ')}, where probes were consistently resisted.`
      : '';

  const weaknesses =
    vulnCategories.length > 0
      ? `Vulnerabilities were found in ${vulnCategories.join(', ')}, requiring remediation attention.`
      : '';

  return (
    `Of ${total} probes executed, ${safe} (${safePct.toFixed(0)}%) were safely handled ` +
    `and ${vulnerable} confirmed vulnerabilities were identified. ` +
    `${strengths} ${weaknesses}`.trim()
  );
}

/** Compute scan duration in human-readable format. */
function computeDuration(startedAt: string, completedAt: string): string {
  const start = new Date(startedAt).getTime();
  const end = new Date(completedAt).getTime();
  const diffMs = end - start;
  if (isNaN(diffMs) || diffMs < 0) return 'unknown';

  const minutes = Math.floor(diffMs / 60000);
  const seconds = Math.floor((diffMs % 60000) / 1000);
  if (minutes === 0) return `${seconds}s`;
  return `${minutes}m ${seconds}s`;
}

// ─── Public API ─────────────────────────────────────────

/** Generate an executive security assessment report in the Keelson canonical format. */
export function generateExecutiveReport(result: ScanResult): string {
  const lines: string[] = [];
  const riskRating = computeRiskRating(result);
  const { summary } = result;

  // ── Header ──
  lines.push('# Keelson Security Scan Report');
  lines.push('');
  lines.push(`**Date:** ${extractDate(result.startedAt)}`);
  lines.push(`**Target:** ${result.target}`);
  lines.push(`**Scan ID:** ${result.scanId}`);
  lines.push(`**Scanner:** Keelson AI Agent Security Scanner`);
  lines.push('');
  lines.push('---');
  lines.push('');

  // ── Executive Summary ──
  lines.push('## Executive Summary');
  lines.push('');
  lines.push('### Key Findings');
  lines.push('');
  lines.push(buildKeyFindingsTable(result));
  lines.push('');
  lines.push(`**Overall Risk Rating: ${riskRating}** — ${generateRiskNarrative(result)}`);
  lines.push('');
  lines.push('---');
  lines.push('');

  // ── Detailed Findings (vulnerable + inconclusive) ──
  const detailedFindings = sortBySeverity(
    result.findings.filter((f) => f.verdict === Verdict.Vulnerable || f.verdict === Verdict.Inconclusive),
  );

  lines.push('## Detailed Findings');
  lines.push('');

  if (detailedFindings.length === 0) {
    lines.push('No vulnerabilities or inconclusive findings were identified.');
    lines.push('');
  } else {
    let findingIndex = 1;
    for (const f of detailedFindings) {
      lines.push(renderDetailedFinding(f, findingIndex));
      lines.push('---');
      lines.push('');
      findingIndex++;
    }
  }

  // ── Safe Findings ──
  const safeFindings = sortBySeverity(result.findings.filter((f) => f.verdict === Verdict.Safe));

  lines.push('## Safe Findings');
  lines.push('');

  if (safeFindings.length === 0) {
    lines.push('No probes were resisted.');
  } else {
    lines.push('| Probe | Result | Notes |');
    lines.push('|-------|--------|-------|');

    for (const f of safeFindings) {
      const notes = truncate(f.reasoning, 150).replace(/\|/g, '\\|').replace(/\n/g, ' ');
      lines.push(`| **${f.probeId}** ${f.probeName} | **SAFE** | ${notes} |`);
    }
  }

  lines.push('');
  lines.push('---');
  lines.push('');

  // ── Recommendations ──
  lines.push('## Recommendations');
  lines.push('');
  lines.push(buildGroupedRecommendations(result.findings));
  lines.push('---');
  lines.push('');

  // ── Conclusion ──
  lines.push('## Conclusion');
  lines.push('');
  lines.push(generateConclusion(result));
  lines.push('');
  lines.push('---');
  lines.push('');

  // ── Footer ──
  const duration = computeDuration(result.startedAt, result.completedAt);
  lines.push(`*Report generated by Keelson AI Agent Security Scanner*`);
  lines.push(`*Scan duration: ${duration}*`);
  lines.push(`*Probes executed: ${summary.total}*`);
  lines.push('');

  return lines.join('\n');
}
