/**
 * Scan diff and baseline comparison.
 *
 * Compares two scan results to produce a structured diff, formats diff reports,
 * classifies regression alert severity, and supports campaign-level comparison.
 */

import type {
  AlertSeverity,
  CampaignResult,
  ChangeType,
  Finding,
  RegressionAlert,
  ScanDiff,
  ScanDiffItem,
  ScanResult,
  StatisticalFinding,
} from '../types/index.js';
import { Severity, Verdict } from '../types/index.js';

// ─── Verdict severity ordering ──────────────────────────

const VERDICT_SEVERITY: Record<Verdict, number> = {
  [Verdict.Safe]: 0,
  [Verdict.Inconclusive]: 1,
  [Verdict.Vulnerable]: 2,
};

const ALERT_SEVERITY_ORDER: Record<AlertSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

// ─── Internal helpers ───────────────────────────────────

function classifyChange(oldVerdict: Verdict, newVerdict: Verdict): ChangeType {
  if (VERDICT_SEVERITY[newVerdict] > VERDICT_SEVERITY[oldVerdict]) {
    return 'regression';
  }
  return 'improvement';
}

function buildFindingMap(findings: Finding[]): Map<string, Finding> {
  return new Map(findings.map((f) => [f.probeId, f]));
}

function buildStatFindingMap(findings: StatisticalFinding[]): Map<string, StatisticalFinding> {
  return new Map(findings.map((f) => [f.probeId, f]));
}

function sortedUnion<T>(a: Map<string, T>, b: Map<string, T>): string[] {
  const ids = new Set([...a.keys(), ...b.keys()]);
  return [...ids].sort();
}

function sortAlertsBySeverity(alerts: RegressionAlert[]): RegressionAlert[] {
  return alerts.sort(
    (a, b) =>
      (ALERT_SEVERITY_ORDER[a.alertSeverity] ?? 4) -
      (ALERT_SEVERITY_ORDER[b.alertSeverity] ?? 4),
  );
}

function formatVerdict(verdict: Verdict | null): string {
  return verdict ?? 'N/A';
}

function formatRate(rate: number): string {
  return `${Math.round(rate * 100)}%`;
}

// ─── Core diff ──────────────────────────────────────────

/**
 * Compare two scan results and produce a diff.
 *
 * scanA is the "before" scan, scanB is the "after" scan.
 */
export function diffScans(scanA: ScanResult, scanB: ScanResult): ScanDiff {
  const aMap = buildFindingMap(scanA.findings);
  const bMap = buildFindingMap(scanB.findings);
  const allIds = sortedUnion(aMap, bMap);
  const items: ScanDiffItem[] = [];

  for (const id of allIds) {
    const fa = aMap.get(id);
    const fb = bMap.get(id);

    if (fa && fb) {
      if (fa.verdict === fb.verdict) {
        continue; // No change
      }
      const changeType = classifyChange(fa.verdict, fb.verdict);
      items.push({
        probeId: id,
        probeName: fb.probeName,
        oldVerdict: fa.verdict,
        newVerdict: fb.verdict,
        changeType,
      });
    } else if (fa && !fb) {
      items.push({
        probeId: id,
        probeName: fa.probeName,
        oldVerdict: fa.verdict,
        newVerdict: null,
        changeType: 'removed',
      });
    } else if (fb) {
      items.push({
        probeId: id,
        probeName: fb.probeName,
        oldVerdict: null,
        newVerdict: fb.verdict,
        changeType: 'new',
      });
    }
  }

  return { scanAId: scanA.scanId, scanBId: scanB.scanId, items };
}

/**
 * Compare current scan against a baseline scan.
 */
export function diffFromBaseline(baseline: ScanResult, current: ScanResult): ScanDiff {
  return diffScans(baseline, current);
}

// ─── Diff helpers ───────────────────────────────────────

/** Return only regression items from a diff. */
export function getRegressions(diff: ScanDiff): ScanDiffItem[] {
  return diff.items.filter((i) => i.changeType === 'regression');
}

/** Return only improvement items from a diff. */
export function getImprovements(diff: ScanDiff): ScanDiffItem[] {
  return diff.items.filter((i) => i.changeType === 'improvement');
}

// ─── Diff report formatting ─────────────────────────────

/**
 * Format a scan diff as a readable markdown section.
 */
export function formatDiffReport(diff: ScanDiff): string {
  const lines: string[] = [`## Scan Diff: ${diff.scanAId} \u2192 ${diff.scanBId}\n`];

  if (diff.items.length === 0) {
    lines.push('No changes detected.\n');
    return lines.join('\n');
  }

  const regressions = getRegressions(diff);
  const improvements = getImprovements(diff);
  const newItems = diff.items.filter((i) => i.changeType === 'new');
  const removedItems = diff.items.filter((i) => i.changeType === 'removed');

  if (regressions.length > 0) {
    lines.push('### Regressions\n');
    for (const item of regressions) {
      lines.push(
        `- **${item.probeId}**: ${item.probeName} \u2014 ` +
          `${formatVerdict(item.oldVerdict)} \u2192 ${formatVerdict(item.newVerdict)}`,
      );
    }
    lines.push('');
  }

  if (improvements.length > 0) {
    lines.push('### Improvements\n');
    for (const item of improvements) {
      lines.push(
        `- **${item.probeId}**: ${item.probeName} \u2014 ` +
          `${formatVerdict(item.oldVerdict)} \u2192 ${formatVerdict(item.newVerdict)}`,
      );
    }
    lines.push('');
  }

  if (newItems.length > 0) {
    lines.push('### New Probes\n');
    for (const item of newItems) {
      lines.push(
        `- **${item.probeId}**: ${item.probeName} \u2014 ${formatVerdict(item.newVerdict)}`,
      );
    }
    lines.push('');
  }

  if (removedItems.length > 0) {
    lines.push('### Removed Probes\n');
    for (const item of removedItems) {
      lines.push(
        `- **${item.probeId}**: ${item.probeName} \u2014 was ${formatVerdict(item.oldVerdict)}`,
      );
    }
    lines.push('');
  }

  const summary =
    `**Summary**: ${regressions.length} regressions, ` +
    `${improvements.length} improvements, ` +
    `${newItems.length} new, ${removedItems.length} removed`;
  lines.push(summary);

  return lines.join('\n');
}

// ─── Enhanced regression alerts ─────────────────────────

/**
 * Classify the severity of a regression alert.
 *
 * Rules:
 * - Critical: SAFE -> VULNERABLE on Critical/High severity probe
 * - High: new VULNERABLE probe or SAFE -> VULNERABLE on Medium/Low
 * - Medium: INCONCLUSIVE -> VULNERABLE
 * - Low: minor behavioral changes (e.g., SAFE -> INCONCLUSIVE)
 */
export function classifyAlertSeverity(
  item: ScanDiffItem,
  probeSeverity: Severity | null = null,
): AlertSeverity {
  if (item.changeType === 'new' && item.newVerdict === Verdict.Vulnerable) {
    return 'high';
  }

  if (item.oldVerdict === Verdict.Safe && item.newVerdict === Verdict.Vulnerable) {
    if (probeSeverity && (probeSeverity === Severity.Critical || probeSeverity === Severity.High)) {
      return 'critical';
    }
    return 'high';
  }

  if (item.oldVerdict === Verdict.Inconclusive && item.newVerdict === Verdict.Vulnerable) {
    return 'medium';
  }

  return 'low';
}

/**
 * Compare two scans with severity-classified regression alerts.
 *
 * Returns the standard ScanDiff plus a list of RegressionAlert objects.
 */
export function enhancedDiffScans(
  scanA: ScanResult,
  scanB: ScanResult,
): { diff: ScanDiff; alerts: RegressionAlert[] } {
  const diff = diffScans(scanA, scanB);
  const alerts: RegressionAlert[] = [];

  // Build severity lookup from both scans (scanA values override scanB)
  const severityMap = new Map<string, Severity>();
  for (const f of scanB.findings) {
    severityMap.set(f.probeId, f.severity);
  }
  for (const f of scanA.findings) {
    severityMap.set(f.probeId, f.severity);
  }

  for (const item of diff.items) {
    if (item.changeType !== 'regression' && item.changeType !== 'new') {
      continue;
    }
    // Only alert on items that became (more) vulnerable
    if (item.newVerdict !== Verdict.Vulnerable && item.newVerdict !== Verdict.Inconclusive) {
      continue;
    }
    if (item.changeType === 'new' && item.newVerdict !== Verdict.Vulnerable) {
      continue;
    }

    const probeSev = severityMap.get(item.probeId) ?? null;
    const alertSev = classifyAlertSeverity(item, probeSev);

    alerts.push({
      probeId: item.probeId,
      alertSeverity: alertSev,
      changeType: item.changeType,
      description:
        `${item.probeName}: ` +
        `${formatVerdict(item.oldVerdict)} \u2192 ${formatVerdict(item.newVerdict)}`,
      oldVerdict: item.oldVerdict,
      newVerdict: item.newVerdict,
      probeSeverity: probeSev,
    });
  }

  sortAlertsBySeverity(alerts);

  return { diff, alerts };
}

// ─── Campaign comparison ────────────────────────────────

/**
 * Compare two campaign results for statistical regressions.
 *
 * Detects rate increases between campaigns (e.g., probe that went from 10% to 60%).
 */
export function diffCampaigns(
  campaignA: CampaignResult,
  campaignB: CampaignResult,
): RegressionAlert[] {
  const alerts: RegressionAlert[] = [];

  const aMap = buildStatFindingMap(campaignA.findings);
  const bMap = buildStatFindingMap(campaignB.findings);

  for (const id of sortedUnion(aMap, bMap)) {
    const fa = aMap.get(id);
    const fb = bMap.get(id);

    if (fa && fb) {
      if (fa.verdict === Verdict.Safe && fb.verdict === Verdict.Vulnerable) {
        const alertSev: AlertSeverity =
          fb.severity === Severity.Critical || fb.severity === Severity.High ? 'critical' : 'high';
        alerts.push({
          probeId: id,
          alertSeverity: alertSev,
          changeType: 'regression',
          description:
            `${fb.probeName}: vulnerability rate increased from ` +
            `${formatRate(fa.successRate)} to ${formatRate(fb.successRate)}`,
          oldVerdict: fa.verdict,
          newVerdict: fb.verdict,
          probeSeverity: fb.severity,
        });
      } else if (fa.verdict !== Verdict.Vulnerable && fb.verdict === Verdict.Vulnerable) {
        alerts.push({
          probeId: id,
          alertSeverity: 'medium',
          changeType: 'regression',
          description:
            `${fb.probeName}: became statistically vulnerable ` +
            `(${formatRate(fb.successRate)} rate)`,
          oldVerdict: fa.verdict,
          newVerdict: fb.verdict,
          probeSeverity: fb.severity,
        });
      } else if (fb.successRate > fa.successRate + 0.2) {
        // Significant rate increase even without verdict change
        alerts.push({
          probeId: id,
          alertSeverity: 'low',
          changeType: 'rate_increase',
          description:
            `${fb.probeName}: vulnerability rate increased from ` +
            `${formatRate(fa.successRate)} to ${formatRate(fb.successRate)}`,
          oldVerdict: fa.verdict,
          newVerdict: fb.verdict,
          probeSeverity: fb.severity,
        });
      }
    } else if (fb && !fa) {
      if (fb.verdict === Verdict.Vulnerable) {
        alerts.push({
          probeId: id,
          alertSeverity: 'high',
          changeType: 'new_vulnerable',
          description:
            `${fb.probeName}: new vulnerable probe (${formatRate(fb.successRate)} rate)`,
          oldVerdict: null,
          newVerdict: fb.verdict,
          probeSeverity: fb.severity,
        });
      }
    }
  }

  sortAlertsBySeverity(alerts);
  return alerts;
}
