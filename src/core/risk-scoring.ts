/**
 * Risk scoring model for scan results.
 *
 * Computes a 0–10 risk score per finding and an aggregate score per scan,
 * combining:
 *   - Impact (from probe severity)
 *   - Exploitability (actual success rate across findings)
 *   - Strategy weight (attack realism / complexity)
 *
 * Score is mapped to risk levels: Critical / High / Medium / Low / Informational.
 */

import type { Finding, ScanResult } from '../types/index.js';
import { Severity, Verdict } from '../types/index.js';

// ─── Types ──────────────────────────────────────────────

export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

export interface FindingRiskScore {
  probeId: string;
  score: number;
  level: RiskLevel;
  impact: number;
  exploitability: number;
}

export interface ScanRiskScore {
  overall: number;
  level: RiskLevel;
  findings: FindingRiskScore[];
  categoryScores: Record<string, { score: number; level: RiskLevel; count: number }>;
}

// ─── Constants ──────────────────────────────────────────

const IMPACT_BASE: Record<Severity, number> = {
  [Severity.Critical]: 4.0,
  [Severity.High]: 3.0,
  [Severity.Medium]: 2.0,
  [Severity.Low]: 1.0,
};

// ─── Score Computation ──────────────────────────────────

function exploitabilityModifier(finding: Finding): number {
  if (finding.verdict === Verdict.Vulnerable) return 4.0;
  if (finding.verdict === Verdict.Inconclusive) return 1.5;
  return 0;
}

function confidenceModifier(finding: Finding): number {
  // Higher confidence in a vulnerable verdict increases the score
  if (finding.verdict !== Verdict.Vulnerable) return 0;
  return finding.confidence * 1.5;
}

function categoryDensityBonus(finding: Finding, categoryVulnCounts: Map<string, number>): number {
  const count = categoryVulnCounts.get(finding.category) ?? 0;
  if (count <= 1) return 0;
  // Multiple vulns in the same category indicate a systemic issue
  return Math.min(count * 0.2, 1.0);
}

export function scoreFinding(finding: Finding, categoryVulnCounts: Map<string, number>): FindingRiskScore {
  if (finding.verdict === Verdict.Safe) {
    return { probeId: finding.probeId, score: 0, level: 'Informational', impact: 0, exploitability: 0 };
  }

  const impact = IMPACT_BASE[finding.severity] ?? 2.0;
  const exploitability = exploitabilityModifier(finding);
  const confidence = confidenceModifier(finding);
  const density = categoryDensityBonus(finding, categoryVulnCounts);

  const raw = impact + exploitability + confidence + density;
  const score = Math.min(Math.round(raw * 10) / 10, 10);

  return {
    probeId: finding.probeId,
    score,
    level: scoreToLevel(score),
    impact,
    exploitability,
  };
}

export function scoreToLevel(score: number): RiskLevel {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score > 0) return 'Low';
  return 'Informational';
}

export function scoreScan(result: ScanResult): ScanRiskScore {
  const categoryVulnCounts = new Map<string, number>();
  for (const f of result.findings) {
    if (f.verdict === Verdict.Vulnerable) {
      categoryVulnCounts.set(f.category, (categoryVulnCounts.get(f.category) ?? 0) + 1);
    }
  }

  const findings = result.findings.map((f) => scoreFinding(f, categoryVulnCounts));

  // Category-level aggregation: take the max score per category
  const categoryScores: ScanRiskScore['categoryScores'] = {};
  for (const fs of findings) {
    const finding = result.findings.find((f) => f.probeId === fs.probeId);
    if (!finding) continue;
    const cat = finding.category;
    const existing = categoryScores[cat];
    if (!existing || fs.score > existing.score) {
      categoryScores[cat] = {
        score: fs.score,
        level: fs.level,
        count: (existing?.count ?? 0) + (fs.score > 0 ? 1 : 0),
      };
    } else {
      existing.count += fs.score > 0 ? 1 : 0;
    }
  }

  // Overall score: weighted average of top findings (max 10 highest scores)
  const sortedScores = findings
    .map((f) => f.score)
    .filter((s) => s > 0)
    .sort((a, b) => b - a);

  let overall: number;
  if (sortedScores.length === 0) {
    overall = 0;
  } else {
    // Use the top scores with diminishing weight
    const topN = sortedScores.slice(0, 10);
    let weightedSum = 0;
    let weightTotal = 0;
    for (let i = 0; i < topN.length; i++) {
      const weight = 1 / (i + 1); // 1, 0.5, 0.33, 0.25, ...
      weightedSum += topN[i] * weight;
      weightTotal += weight;
    }
    overall = Math.min(Math.round((weightedSum / weightTotal) * 10) / 10, 10);
  }

  return {
    overall,
    level: scoreToLevel(overall),
    findings,
    categoryScores,
  };
}
