/**
 * Reporting module barrel export.
 *
 * Re-exports all formatters and provides a dispatcher function
 * to generate reports in any supported format.
 */


import { FRAMEWORK_CONTROLS, generateComplianceReport, mapFindingsToFramework } from './compliance.js';
import { generateExecutiveReport } from './executive.js';
import { generateJunit } from './junit.js';
import { formatEvidence, generateMarkdownReport } from './markdown.js';
import { generateOcsf } from './ocsf.js';
import { generateSarif } from './sarif.js';
import { ComplianceFramework } from '../types/index.js';
import type { ScanResult } from '../types/index.js';

// ─── Types ──────────────────────────────────────────────

export type ReportFormat = 'markdown' | 'executive' | 'compliance' | 'sarif' | 'junit' | 'ocsf';

export interface ReportOptions {
  /** Compliance framework to use (required when format is 'compliance'). */
  complianceFramework?: ComplianceFramework;
}

// ─── Dispatcher ─────────────────────────────────────────

/**
 * Generate a report in the specified format.
 *
 * Returns a string for text-based formats (markdown, executive, compliance, junit)
 * or an object for structured formats (sarif, ocsf).
 */
export function generateReport(
  result: ScanResult,
  format: ReportFormat,
  options?: ReportOptions,
): string | object {
  switch (format) {
    case 'markdown':
      return generateMarkdownReport(result);
    case 'executive':
      return generateExecutiveReport(result);
    case 'compliance':
      return generateComplianceReport(
        result,
        options?.complianceFramework ?? ComplianceFramework.OwaspLlmTop10,
      );
    case 'sarif':
      return generateSarif(result);
    case 'junit':
      return generateJunit(result);
    case 'ocsf':
      return generateOcsf(result);
  }
}

// ─── Re-exports ─────────────────────────────────────────

export {
  generateMarkdownReport,
  formatEvidence,
  generateExecutiveReport,
  generateComplianceReport,
  mapFindingsToFramework,
  FRAMEWORK_CONTROLS,
  generateSarif,
  generateJunit,
  generateOcsf,
};

export type { SeverityRow, CategoryRow, RecommendationItem } from './executive.js';
export type { FrameworkMapping } from './compliance.js';
export type { SarifLog, SarifRun, SarifResult, SarifRule } from './sarif.js';
export type { OcsfEvent } from './ocsf.js';
