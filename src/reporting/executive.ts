/**
 * Executive report generation with risk scoring and remediation priorities.
 *
 * Produces a pentest-grade markdown report with executive summary,
 * severity breakdown, PoC evidence, and prioritized recommendations.
 */

import type { Finding, ScanResult } from '../types/index.js';
import { SEVERITY_ORDER, Severity, Verdict } from '../types/index.js';
import { extractDate, groupBy, truncate } from '../utils.js';

// ─── Interfaces ─────────────────────────────────────────

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

// ─── Helpers ────────────────────────────────────────────

function severitySortKey(f: Finding): number {
  return SEVERITY_ORDER[f.severity] ?? 99;
}

function computeRiskScore(result: ScanResult): number {
  const { total, vulnerable } = result.summary;
  if (total === 0) return 0;
  return (vulnerable / total) * 100;
}

function generateRiskAssessment(result: ScanResult): string {
  const { total, vulnerable } = result.summary;
  if (total === 0) return 'No probe scenarios were executed during this assessment.';

  if (vulnerable === 0) {
    return (
      `The target agent demonstrated robust security controls across all ` +
      `${total} probe scenarios tested. No vulnerabilities were confirmed. ` +
      `Continued periodic assessment is recommended to maintain this posture.`
    );
  }

  const vulnPct = (vulnerable / total) * 100;
  const criticalCount = result.findings.filter(
    (f) => f.verdict === Verdict.Vulnerable && f.severity === Severity.Critical,
  ).length;
  const highCount = result.findings.filter(
    (f) => f.verdict === Verdict.Vulnerable && f.severity === Severity.High,
  ).length;

  let riskLevel: string;
  let urgency: string;

  if (criticalCount > 0) {
    riskLevel = 'CRITICAL';
    urgency =
      `Immediate remediation is required. ${criticalCount} critical-severity ` +
      `${criticalCount === 1 ? 'vulnerability was' : 'vulnerabilities were'} ` +
      `confirmed, indicating that core security controls can be bypassed.`;
  } else if (highCount > 0) {
    riskLevel = 'HIGH';
    urgency =
      `Prompt remediation is strongly recommended. ${highCount} high-severity ` +
      `${highCount === 1 ? 'vulnerability was' : 'vulnerabilities were'} ` +
      `confirmed, representing significant risk to production deployment.`;
  } else if (vulnPct > 30) {
    riskLevel = 'ELEVATED';
    urgency =
      'A substantial proportion of probe scenarios succeeded. ' +
      'Systematic hardening of the agent defensive controls is recommended ' +
      'before production exposure.';
  } else {
    riskLevel = 'MODERATE';
    urgency =
      'A limited number of probe scenarios succeeded. Targeted remediation ' +
      'of the identified weaknesses is recommended.';
  }

  return (
    `**Overall Risk Level: ${riskLevel}** — ` +
    `Out of ${total} probe scenarios executed, ${vulnerable} ` +
    `(${vulnPct.toFixed(0)}%) resulted in confirmed vulnerabilities. ` +
    urgency
  );
}

function computeSeverityRows(findings: Finding[]): SeverityRow[] {
  const vulnFindings = findings.filter((f) => f.verdict === Verdict.Vulnerable);
  const total = vulnFindings.length;
  const rows: SeverityRow[] = [];

  for (const sev of [Severity.Critical, Severity.High, Severity.Medium, Severity.Low]) {
    const count = vulnFindings.filter((f) => f.severity === sev).length;
    rows.push({
      severity: sev,
      count,
      percentage: total > 0 ? (count / total) * 100 : 0,
    });
  }
  return rows;
}

function computeCategoryRows(findings: Finding[]): CategoryRow[] {
  const byCategory = groupBy(findings, (f) => f.category);

  const rows: CategoryRow[] = [];
  for (const [category, catFindings] of byCategory) {
    const vulnCount = catFindings.filter((f) => f.verdict === Verdict.Vulnerable).length;
    rows.push({
      category,
      vulnCount,
      totalCount: catFindings.length,
      rate: catFindings.length > 0 ? (vulnCount / catFindings.length) * 100 : 0,
    });
  }

  // Sort by vulnerability rate descending
  rows.sort((a, b) => b.rate - a.rate);
  return rows;
}

function buildRecommendations(findings: Finding[]): RecommendationItem[] {
  const vulnByCategory = new Map<string, Finding[]>();
  for (const f of findings) {
    if (f.verdict === Verdict.Vulnerable) {
      const existing = vulnByCategory.get(f.category) ?? [];
      existing.push(f);
      vulnByCategory.set(f.category, existing);
    }
  }

  const recs: RecommendationItem[] = [];

  if (vulnByCategory.size === 0) {
    recs.push({
      category: 'General',
      severity: Severity.Low,
      recommendation:
        'No vulnerabilities were confirmed. Continue regular security assessments to maintain this posture.',
    });
  } else {
    // Sort categories by worst severity
    const sorted = [...vulnByCategory.entries()].sort((a, b) => {
      const worstA = Math.min(...a[1].map((f) => severitySortKey(f)));
      const worstB = Math.min(...b[1].map((f) => severitySortKey(f)));
      if (worstA !== worstB) return worstA - worstB;
      return b[1].length - a[1].length;
    });

    for (const [category, catFindings] of sorted) {
      const worstFinding = catFindings.reduce((a, b) => (severitySortKey(a) <= severitySortKey(b) ? a : b));
      const recommendation = CATEGORY_RECOMMENDATIONS[category] ?? `Review ${category} controls.`;
      const probeIds = [...new Set(catFindings.map((f) => f.probeId))].sort().join(', ');
      recs.push({
        category,
        severity: worstFinding.severity,
        recommendation: `${recommendation} (Affected: ${probeIds})`,
      });
    }
  }

  // Meta-recommendation: critical-severity vulnerable findings
  const hasCriticalVulnerable = findings.some(
    (f) => f.verdict === Verdict.Vulnerable && f.severity === Severity.Critical,
  );
  if (hasCriticalVulnerable) {
    recs.push({
      category: 'Critical Findings',
      severity: Severity.Critical,
      recommendation:
        'Address all critical-severity findings before any production deployment. Critical findings indicate fundamental security control bypasses.',
    });
  }

  // Meta-recommendation: inconclusive findings
  const hasInconclusive = findings.some((f) => f.verdict === Verdict.Inconclusive);
  if (hasInconclusive) {
    recs.push({
      category: 'Manual Review',
      severity: Severity.Medium,
      recommendation:
        'Manually review all inconclusive findings. Inconclusive results may mask true vulnerabilities requiring deeper investigation.',
    });
  }

  return recs;
}

// ─── Public API ─────────────────────────────────────────

/** Generate an executive security assessment report in markdown. */
export function generateExecutiveReport(result: ScanResult): string {
  const lines: string[] = [];
  const riskScore = computeRiskScore(result);
  const severityRows = computeSeverityRows(result.findings);
  const categoryRows = computeCategoryRows(result.findings);
  const recommendations = buildRecommendations(result.findings);

  const vulnerable = result.findings
    .filter((f) => f.verdict === Verdict.Vulnerable)
    .sort((a, b) => severitySortKey(a) - severitySortKey(b));
  const inconclusive = result.findings
    .filter((f) => f.verdict === Verdict.Inconclusive)
    .sort((a, b) => severitySortKey(a) - severitySortKey(b));

  // Header
  lines.push('# AI Agent Security Assessment Report');
  lines.push('');
  lines.push('---');
  lines.push('');

  // Executive Summary
  lines.push('## Executive Summary');
  lines.push('');
  lines.push('| Field | Value |');
  lines.push('|-------|-------|');
  lines.push(`| **Target** | ${result.target} |`);
  lines.push(`| **Scan ID** | ${result.scanId} |`);
  lines.push(`| **Date** | ${extractDate(result.startedAt)} |`);
  lines.push(`| **Probes Executed** | ${result.summary.total} |`);
  lines.push(`| **Risk Score** | ${riskScore.toFixed(1)}% |`);
  lines.push('');
  lines.push(generateRiskAssessment(result));
  lines.push('');

  // Severity Breakdown
  lines.push('### Severity Breakdown');
  lines.push('');
  lines.push('| Severity | Count | Percentage |');
  lines.push('|----------|------:|-----------:|');
  for (const row of severityRows) {
    const bar = row.count > 0 ? '\u2588'.repeat(row.count) : '-';
    lines.push(`| **${row.severity}** | ${row.count} | ${bar} ${row.percentage.toFixed(0)}% |`);
  }
  lines.push(`| **Total Vulnerable** | **${result.summary.vulnerable}** | |`);
  lines.push('');

  // Category Breakdown
  lines.push('---');
  lines.push('');
  lines.push('## Category Breakdown');
  lines.push('');
  lines.push('| Category | Vulnerable | Total | Rate |');
  lines.push('|----------|----------:|------:|-----:|');
  for (const row of categoryRows) {
    lines.push(`| ${row.category} | ${row.vulnCount} | ${row.totalCount} | ${row.rate.toFixed(0)}% |`);
  }
  lines.push('');

  // Probe Coverage
  lines.push('---');
  lines.push('');
  lines.push('## Probe Coverage');
  lines.push('');
  lines.push('| Category | Tested | Vulnerable | Safe | Inconclusive |');
  lines.push('|----------|-------:|----------:|-----:|-------------:|');

  const coverageByCategory = new Map<string, Finding[]>();
  for (const f of result.findings) {
    const existing = coverageByCategory.get(f.category) ?? [];
    existing.push(f);
    coverageByCategory.set(f.category, existing);
  }
  for (const [category, catFindings] of coverageByCategory) {
    const tested = catFindings.length;
    const vulnCount = catFindings.filter((f) => f.verdict === Verdict.Vulnerable).length;
    const safeCount = catFindings.filter((f) => f.verdict === Verdict.Safe).length;
    const inconclusiveCount = catFindings.filter((f) => f.verdict === Verdict.Inconclusive).length;
    lines.push(`| ${category} | ${tested} | ${vulnCount} | ${safeCount} | ${inconclusiveCount} |`);
  }
  lines.push('');

  // Confirmed Vulnerabilities
  lines.push('---');
  lines.push('');
  lines.push('## Confirmed Vulnerabilities');
  lines.push('');

  if (vulnerable.length === 0) {
    lines.push('No confirmed vulnerabilities were found during this assessment.');
  } else {
    for (const f of vulnerable) {
      lines.push(`### ${f.probeId}: ${f.probeName} — VULNERABLE`);
      lines.push('');
      lines.push(`**Severity**: ${f.severity} | **Category**: ${f.category} | **OWASP**: ${f.owaspId}`);
      lines.push('');
      lines.push(`**Analysis**: ${f.reasoning}`);
      lines.push('');

      if (f.evidence.length > 0) {
        lines.push('**Proof of Concept**:');
        lines.push('');
        for (const ev of f.evidence) {
          if (f.evidence.length > 1) {
            lines.push(`**Turn ${ev.stepIndex}**:`);
          }
          lines.push(`**Probe**: *"${truncate(ev.prompt, 200)}"*`);
          lines.push(`**Response**: ${ev.response ? `*"${truncate(ev.response, 500)}"*` : '"(empty)"'}`);
          lines.push('');
        }
      }

      if (f.leakageSignals.length > 0) {
        lines.push('**Leakage Signals Detected**:');
        for (const sig of f.leakageSignals) {
          const confLabel = sig.confidence ? ` (confidence: ${(sig.confidence * 100).toFixed(0)}%)` : '';
          lines.push(
            `- [${sig.severity.toUpperCase()}] ${sig.signalType}: ` + `${sig.description} ${confLabel}`.trim(),
          );
        }
        lines.push('');
      }

      lines.push('---');
      lines.push('');
    }
  }
  lines.push('');

  // Inconclusive Findings
  lines.push('## Inconclusive Findings');
  lines.push('');
  if (inconclusive.length === 0) {
    lines.push('No inconclusive findings.');
  } else {
    lines.push('| ID | Name | Severity | Category | OWASP |');
    lines.push('|----|------|----------|----------|-------|');
    for (const f of inconclusive) {
      lines.push(`| ${f.probeId} | ${f.probeName} | ${f.severity} | ${f.category} | ${f.owaspId} |`);
    }
    lines.push('');
    lines.push(
      '> Inconclusive findings could not be definitively classified as vulnerable or safe. ' +
        'Manual review is recommended, particularly for high-severity items.',
    );
  }
  lines.push('');

  // Recommendations
  lines.push('---');
  lines.push('');
  lines.push('## Recommendations');
  lines.push('');
  for (let i = 0; i < recommendations.length; i++) {
    const rec = recommendations[i];
    lines.push(`${i + 1}. **[${rec.severity}]** ${rec.recommendation}`);
  }
  lines.push('');

  // Methodology
  lines.push('---');
  lines.push('');
  lines.push('## Methodology');
  lines.push('');
  lines.push('- **Scanner**: Keelson AI Agent Security Scanner');
  lines.push(`- **Probes**: ${result.summary.total} from Keelson's probe library`);
  lines.push('- **Evaluation**: Semantic analysis of agent responses (LLM-as-judge)');
  lines.push('');
  lines.push(`*Report generated by Keelson AI Agent Security Scanner on ${result.completedAt}.*`);
  lines.push('');

  return lines.join('\n');
}
