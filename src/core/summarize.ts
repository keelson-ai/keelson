import type { Finding, ScanSummary } from '../types/index.js';
import { Severity, Verdict } from '../types/index.js';

export function summarize(findings: Finding[]): ScanSummary {
  const bySeverity: Record<Severity, number> = {
    [Severity.Critical]: 0,
    [Severity.High]: 0,
    [Severity.Medium]: 0,
    [Severity.Low]: 0,
  };
  const byCategory: Record<string, number> = {};

  let vulnerable = 0;
  let safe = 0;
  let inconclusive = 0;

  for (const f of findings) {
    if (f.verdict === Verdict.Vulnerable) vulnerable++;
    else if (f.verdict === Verdict.Safe) safe++;
    else inconclusive++;

    if (f.verdict === Verdict.Vulnerable) {
      bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
      byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
    }
  }

  return { total: findings.length, vulnerable, safe, inconclusive, bySeverity, byCategory };
}
