/**
 * Markdown report generation from scan results.
 *
 * Produces a detailed markdown report matching the Keelson scan report format:
 * - Header with inline stats
 * - Summary narrative
 * - Critical findings (vulnerable) highlighted separately
 * - Detailed results grouped by category
 * - Methodology footer
 */

import type { EvidenceItem, Finding, ScanResult } from '../types/index.js';
import { SEVERITY_ORDER, Verdict } from '../types/index.js';
import { extractDate, groupBy, truncate } from '../utils.js';

// ─── Constants ──────────────────────────────────────────

const VERDICT_LABELS: Record<Verdict, string> = {
  [Verdict.Vulnerable]: 'VULNERABLE',
  [Verdict.Safe]: 'SAFE',
  [Verdict.Inconclusive]: 'INCONCLUSIVE',
};

/** Map category display names to short prefixes for section headers. */
const CATEGORY_PREFIXES: Record<string, string> = {
  'Goal Adherence': 'GA',
  'Tool Safety': 'TS',
  'Memory Integrity': 'MI',
  'Content Safety': 'CS',
  'Agentic Security': 'AS',
  'Permission Boundaries': 'PB',
  'Delegation Integrity': 'DI',
  'Execution Safety': 'ES',
  'Session Isolation': 'SI',
  'Output Weaponization': 'OW',
  'Multi-Agent Security': 'MA',
  'Temporal Persistence': 'TP',
  'Cognitive Architecture': 'CA',
  'Conversational Exfiltration': 'EX',
  'Supply Chain Language': 'SL',
};

function escapeMarkdown(text: string): string {
  return text.replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

/** Format evidence items as Probe/Response pairs matching scan report style. */
export function formatEvidence(evidence: EvidenceItem[]): string {
  if (evidence.length === 0) return '_No evidence collected._\n';

  return evidence
    .map((ev) => {
      const promptText = truncate(ev.prompt, 200);
      const responseText = truncate(ev.response, 300);
      const lines: string[] = [];

      if (evidence.length > 1) {
        lines.push(`**Turn ${ev.stepIndex}**:`);
      }

      lines.push(`**Probe**: *"${promptText}"*`);
      lines.push(`**Response**: ${responseText ? `*"${responseText}"*` : '"(empty)"'}`);

      return lines.join('\n');
    })
    .join('\n\n');
}

function generateSummaryText(result: ScanResult): string {
  const { total, vulnerable, safe, inconclusive } = result.summary;
  if (total === 0) return 'No probes were executed.';

  const vulnPct = (vulnerable / total) * 100;
  const safePct = (safe / total) * 100;

  if (vulnPct === 0) {
    return (
      `Target passed all security tests with no vulnerabilities detected across ${total} probes. ` +
      `${safe} probes returned safe results` +
      (inconclusive > 0 ? ` and ${inconclusive} were inconclusive.` : '.')
    );
  } else if (vulnPct < 15) {
    return (
      `Target demonstrates a strong overall security posture. ` +
      `Of ${total} probes executed, ${safe} were safe (${safePct.toFixed(0)}%), ` +
      `${vulnerable} confirmed vulnerabilities, and ${inconclusive} were inconclusive.`
    );
  } else if (vulnPct < 40) {
    return (
      `Target has moderate security issues with ` +
      `${vulnerable} vulnerabilities found across ${total} tests (${vulnPct.toFixed(0)}%). ` +
      `Remediation recommended.`
    );
  } else {
    return (
      `Target has significant security weaknesses with ` +
      `${vulnerable} vulnerabilities found across ${total} tests (${vulnPct.toFixed(0)}%). ` +
      `Immediate remediation required.`
    );
  }
}

function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const sa = SEVERITY_ORDER[a.severity] ?? 99;
    const sb = SEVERITY_ORDER[b.severity] ?? 99;
    if (sa !== sb) return sa - sb;
    return a.probeId.localeCompare(b.probeId);
  });
}

function groupByCategory(findings: Finding[]): Map<string, Finding[]> {
  return groupBy(findings, (f) => f.category);
}

/** Render a single finding block in the detailed results format. */
function renderFinding(f: Finding): string {
  const lines: string[] = [];
  const verdictLabel = VERDICT_LABELS[f.verdict];

  lines.push(`#### ${f.probeId}: ${f.probeName} — ${verdictLabel}`);
  lines.push('');
  lines.push(`**Severity**: ${f.severity} | **OWASP**: ${f.owaspId}`);
  lines.push('');

  if (f.evidence.length > 0) {
    lines.push(formatEvidence(f.evidence));
  }

  lines.push(`**Reasoning**: ${f.reasoning}`);
  lines.push('');

  if (f.remediation) {
    lines.push(`**Remediation**: ${f.remediation}`);
    lines.push('');
  }

  if (f.leakageSignals.length > 0) {
    lines.push('**Leakage Signals**:');
    lines.push('');
    for (const sig of f.leakageSignals) {
      lines.push(
        `- [${sig.severity.toUpperCase()}] ${sig.signalType}: ` +
          `${escapeMarkdown(sig.description)} ` +
          `(confidence: ${(sig.confidence * 100).toFixed(0)}%)`,
      );
    }
    lines.push('');
  }

  return lines.join('\n');
}

// ─── Public API ─────────────────────────────────────────

/** Generate a full markdown report from scan results. */
export function generateMarkdownReport(result: ScanResult): string {
  const { summary } = result;
  const lines: string[] = [];

  // ── Header ──
  lines.push('# Keelson Security Scan Report');
  lines.push('');
  lines.push(`**Target**: ${result.target}`);
  lines.push(`**Date**: ${extractDate(result.startedAt)}`);
  lines.push(`**Status**: Complete`);
  lines.push(
    `**Probes Run**: ${summary.total} | ` +
      `**Vulnerable**: ${summary.vulnerable} | ` +
      `**Safe**: ${summary.safe} | ` +
      `**Inconclusive**: ${summary.inconclusive}`,
  );
  lines.push('');
  lines.push('---');
  lines.push('');

  // ── Summary ──
  lines.push('## Summary');
  lines.push('');
  lines.push(generateSummaryText(result));
  lines.push('');
  lines.push('---');
  lines.push('');

  // ── Critical Findings (vulnerable only) ──
  const vulnerableFindings = sortBySeverity(result.findings.filter((f) => f.verdict === Verdict.Vulnerable));

  if (vulnerableFindings.length > 0) {
    lines.push('## Critical Findings');
    lines.push('');

    for (const f of vulnerableFindings) {
      renderCriticalFinding(f, lines);
    }

    lines.push('---');
    lines.push('');
  }

  // ── Detailed Results (all findings, grouped by category) ──
  lines.push('## Detailed Results');
  lines.push('');

  if (result.findings.length === 0) {
    lines.push('No probes were executed.');
    lines.push('');
  } else {
    const grouped = groupByCategory(result.findings);

    for (const [category, findings] of grouped) {
      const prefix = CATEGORY_PREFIXES[category] ?? '';
      const prefixLabel = prefix ? ` (${prefix})` : '';
      const probeWord = findings.length === 1 ? 'probe' : 'probes';

      lines.push(`### ${category}${prefixLabel} — ${findings.length} ${probeWord}`);
      lines.push('');

      const sorted = sortBySeverity(findings);
      for (const f of sorted) {
        lines.push(renderFinding(f));
      }
    }
  }

  lines.push('---');
  lines.push('');

  // ── Methodology ──
  lines.push('## Methodology');
  lines.push('');
  lines.push('- **Scanner**: Keelson AI Agent Security Scanner');
  lines.push(`- **Probes**: ${summary.total} from Keelson's probe library`);
  lines.push('- **Evaluation**: Semantic analysis of agent responses (LLM-as-judge)');
  lines.push('');
  lines.push(`*Report generated by Keelson AI Agent Security Scanner on ${result.completedAt}.*`);
  lines.push('');

  return lines.join('\n');
}

/** Render a vulnerable finding in the prominent "Critical Findings" format. */
function renderCriticalFinding(f: Finding, lines: string[]): void {
  const lines2: string[] = [];

  lines2.push(`### Finding ${f.probeId}: ${f.probeName} — VULNERABLE`);
  lines2.push('');
  lines2.push(`**Severity**: ${f.severity}`);
  lines2.push(`**OWASP**: ${f.owaspId}`);
  lines2.push('');

  if (f.evidence.length > 0) {
    lines2.push(formatEvidence(f.evidence));
    lines2.push('');
  }

  lines2.push(`**Reasoning**: ${f.reasoning}`);
  lines2.push('');

  if (f.remediation) {
    lines2.push(`**Remediation**: ${f.remediation}`);
    lines2.push('');
  }

  if (f.leakageSignals.length > 0) {
    lines2.push('**Leakage Signals**:');
    lines2.push('');
    for (const sig of f.leakageSignals) {
      lines2.push(
        `- [${sig.severity.toUpperCase()}] ${sig.signalType}: ` +
          `${escapeMarkdown(sig.description)} ` +
          `(confidence: ${(sig.confidence * 100).toFixed(0)}%)`,
      );
    }
    lines2.push('');
  }

  lines.push(...lines2);
}
