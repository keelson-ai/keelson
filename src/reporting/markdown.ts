/**
 * Markdown report generation from scan results.
 *
 * Produces a detailed markdown report with summary statistics,
 * findings grouped by severity, evidence sections, and recommendations.
 */

import type { EvidenceItem, Finding, ScanResult } from '../types/index.js';
import { Severity, Verdict } from '../types/index.js';

// ─── Constants ──────────────────────────────────────────

const VERDICT_ICONS: Record<Verdict, string> = {
  [Verdict.Vulnerable]: '\u274C', // red X
  [Verdict.Safe]: '\u2705',       // green check
  [Verdict.Inconclusive]: '\u2753', // question mark
};

const SEVERITY_ORDER: Record<Severity, number> = {
  [Severity.Critical]: 0,
  [Severity.High]: 1,
  [Severity.Medium]: 2,
  [Severity.Low]: 3,
};

// ─── Helpers ────────────────────────────────────────────

function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen) + '...';
}

function escapeMarkdown(text: string): string {
  return text.replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

/** Format evidence items as markdown prompt/response pairs. */
export function formatEvidence(evidence: EvidenceItem[]): string {
  if (evidence.length === 0) return '_No evidence collected._\n';

  return evidence
    .map((ev) => {
      const promptText = truncate(ev.prompt, 200);
      const responseText = truncate(ev.response, 300);
      const timeLabel = ev.responseTimeMs ? ` (${ev.responseTimeMs}ms)` : '';
      return [
        `**Prompt** (step ${ev.stepIndex}):`,
        '```',
        promptText,
        '```',
        `**Response**${timeLabel}:`,
        '```',
        responseText,
        '```',
      ].join('\n');
    })
    .join('\n\n');
}

function generateSummaryText(result: ScanResult): string {
  const { total, vulnerable } = result.summary;
  if (total === 0) return 'No probes were executed.';

  const vulnPct = (vulnerable / total) * 100;
  if (vulnPct === 0) {
    return 'Target passed all security tests. No vulnerabilities detected.';
  } else if (vulnPct < 15) {
    return (
      `Target shows minor security concerns with ` +
      `${vulnerable} vulnerabilities found across ${total} tests (${vulnPct.toFixed(0)}%).`
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
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    const existing = groups.get(f.category) ?? [];
    existing.push(f);
    groups.set(f.category, existing);
  }
  return groups;
}

// ─── Public API ─────────────────────────────────────────

/** Generate a full markdown report from scan results. */
export function generateMarkdownReport(result: ScanResult): string {
  const { summary } = result;
  const lines: string[] = [];

  // Header
  lines.push('# Keelson Security Scan Report');
  lines.push('');
  lines.push(`**Target**: ${result.target}`);
  lines.push(`**Scan ID**: ${result.scanId}`);
  lines.push(`**Started**: ${result.startedAt}`);
  lines.push(`**Completed**: ${result.completedAt}`);
  lines.push('');

  // Summary table
  lines.push('## Summary');
  lines.push('');
  lines.push(generateSummaryText(result));
  lines.push('');
  lines.push('| Metric | Count |');
  lines.push('|--------|------:|');
  lines.push(`| Total Probes | ${summary.total} |`);
  lines.push(`| Vulnerable | ${summary.vulnerable} |`);
  lines.push(`| Safe | ${summary.safe} |`);
  lines.push(`| Inconclusive | ${summary.inconclusive} |`);
  lines.push('');

  // Severity breakdown
  lines.push('### Severity Breakdown');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|----------|------:|');
  for (const sev of [Severity.Critical, Severity.High, Severity.Medium, Severity.Low]) {
    lines.push(`| ${sev} | ${summary.bySeverity[sev] ?? 0} |`);
  }
  lines.push('');

  // Findings by severity
  const nonSafe = result.findings.filter((f) => f.verdict !== Verdict.Safe);
  const sorted = sortBySeverity(nonSafe);

  if (sorted.length === 0) {
    lines.push('## Findings');
    lines.push('');
    lines.push('No vulnerable or inconclusive findings.');
    lines.push('');
  } else {
    // Group by category
    const grouped = groupByCategory(sorted);

    lines.push('## Findings');
    lines.push('');

    for (const [category, findings] of grouped) {
      lines.push(`### ${category}`);
      lines.push('');

      for (const f of findings) {
        const icon = VERDICT_ICONS[f.verdict];
        lines.push(`#### ${icon} ${f.probeId}: ${f.probeName} -- ${f.verdict}`);
        lines.push('');
        lines.push(`**Severity**: ${f.severity}`);
        lines.push(`**OWASP**: ${f.owaspId}`);
        lines.push(`**Confidence**: ${(f.confidence * 100).toFixed(0)}%`);
        lines.push('');
        lines.push(`**Reasoning**: ${f.reasoning}`);
        lines.push('');

        if (f.evidence.length > 0) {
          lines.push('**Evidence**:');
          lines.push('');
          lines.push(formatEvidence(f.evidence));
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
      }
    }
  }

  // Footer
  lines.push('---');
  lines.push('');
  lines.push(`*Report generated by Keelson AI Agent Security Scanner on ${result.completedAt}.*`);
  lines.push('');

  return lines.join('\n');
}
