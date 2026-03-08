/**
 * JUnit XML output generation from scan results.
 *
 * Produces valid JUnit XML where each finding maps to a test case.
 * Vulnerable = failure, Safe = passing, Inconclusive = skipped.
 */

import type { Finding, ScanResult } from '../types/index.js';
import { Verdict } from '../types/index.js';

// ─── Helpers ────────────────────────────────────────────

function escapeXml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function escapeAttr(text: string): string {
  return escapeXml(text);
}

function findingTimeSeconds(finding: Finding): string {
  const totalMs = finding.evidence.reduce((sum, ev) => sum + ev.responseTimeMs, 0);
  return (totalMs / 1000).toFixed(3);
}

function buildTestCase(finding: Finding): string {
  const time = findingTimeSeconds(finding);
  const name = escapeAttr(finding.probeName);
  const classname = escapeAttr(finding.category);

  const lines: string[] = [];
  lines.push(`    <testcase name="${name}" classname="${classname}" time="${time}">`);

  if (finding.verdict === Verdict.Vulnerable) {
    const message = escapeAttr(
      `${finding.probeId}: ${finding.probeName} -- Severity: ${finding.severity}, OWASP: ${finding.owaspId}`,
    );
    const text = escapeXml(
      finding.reasoning ||
        `${finding.probeId}: ${finding.probeName} -- Severity: ${finding.severity}, OWASP: ${finding.owaspId}`,
    );
    lines.push(`      <failure message="${message}" type="vulnerability">${text}</failure>`);
  } else if (finding.verdict === Verdict.Inconclusive) {
    const message = escapeAttr(`${finding.probeId}: ${finding.probeName} -- result was inconclusive`);
    const text = escapeXml(finding.reasoning || `${finding.probeId}: ${finding.probeName} -- result was inconclusive`);
    lines.push(`      <skipped message="${message}">${text}</skipped>`);
  }
  // Safe findings have no child elements (passing test)

  lines.push('    </testcase>');
  return lines.join('\n');
}

// ─── Public API ─────────────────────────────────────────

/** Generate JUnit XML from scan results. */
export function generateJunit(result: ScanResult): string {
  const totalTimeMs = result.findings.reduce(
    (sum, f) => sum + f.evidence.reduce((s, ev) => s + ev.responseTimeMs, 0),
    0,
  );
  const totalTimeStr = (totalTimeMs / 1000).toFixed(3);
  const failures = result.findings.filter((f) => f.verdict === Verdict.Vulnerable).length;
  const skipped = result.findings.filter((f) => f.verdict === Verdict.Inconclusive).length;

  const lines: string[] = [];
  lines.push('<?xml version="1.0" encoding="UTF-8"?>');
  lines.push(
    `<testsuite name="keelson-scan-${escapeAttr(result.scanId)}" ` +
      `tests="${result.findings.length}" ` +
      `failures="${failures}" ` +
      `skipped="${skipped}" ` +
      `errors="0" ` +
      `time="${totalTimeStr}" ` +
      `timestamp="${escapeAttr(result.startedAt)}">`,
  );

  // Properties
  lines.push('  <properties>');
  lines.push(`    <property name="target" value="${escapeAttr(result.target)}" />`);
  lines.push(`    <property name="scan_id" value="${escapeAttr(result.scanId)}" />`);
  lines.push('  </properties>');

  // Test cases
  for (const finding of result.findings) {
    lines.push(buildTestCase(finding));
  }

  lines.push('</testsuite>');
  return lines.join('\n');
}
