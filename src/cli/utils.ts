import { mkdir, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

import chalk from 'chalk';

import { Store } from '../state/index.js';
import type { Finding, ScanResult, ScanSummary } from '../types/index.js';
import { Severity, Verdict } from '../types/index.js';
import { truncate } from '../utils.js';

/** Open the Store unless --no-store was passed. */
export function openStore(opts: { noStore?: boolean }): Store | null {
  if (opts.noStore) return null;
  return Store.open();
}

/** Default output directory. */
export const DEFAULT_OUTPUT_DIR = join(homedir(), '.keelson', 'output');

/** Write scan result to output directory. Returns the file path written. */
export async function writeScanOutput(
  result: ScanResult,
  format: string,
  outputDir: string,
): Promise<string> {
  await mkdir(outputDir, { recursive: true });
  const ext = format === 'markdown' ? 'md' : format;
  const filePath = join(outputDir, `${result.scanId}.${ext}`);
  await writeReport(result, format, filePath);
  return filePath;
}

export const VERDICT_ICONS: Record<Verdict, string> = {
  [Verdict.Vulnerable]: chalk.red('\u2717'),
  [Verdict.Safe]: chalk.green('\u2713'),
  [Verdict.Inconclusive]: chalk.yellow('?'),
};

export const VERDICT_LABELS: Record<Verdict, string> = {
  [Verdict.Vulnerable]: chalk.red('VULNERABLE'),
  [Verdict.Safe]: chalk.green('SAFE'),
  [Verdict.Inconclusive]: chalk.yellow('INCONCLUSIVE'),
};

export const SEVERITY_COLORS: Record<Severity, typeof chalk> = {
  [Severity.Critical]: chalk.redBright,
  [Severity.High]: chalk.red,
  [Severity.Medium]: chalk.yellow,
  [Severity.Low]: chalk.dim,
};

export function colorSeverity(severity: Severity): string {
  const colorFn = SEVERITY_COLORS[severity];
  return colorFn(severity);
}

export function formatFinding(finding: Finding, index: number): string {
  const icon = VERDICT_ICONS[finding.verdict];
  const sev = colorSeverity(finding.severity);
  const confidence = chalk.dim(`(${Math.round(finding.confidence * 100)}%)`);

  const lines: string[] = [
    `  ${icon} ${chalk.bold(`#${index + 1}`)} ${finding.probeName} [${sev}] ${confidence}`,
    `    ${chalk.dim('Probe:')} ${finding.probeId} | ${chalk.dim('Category:')} ${finding.category}`,
    `    ${chalk.dim('OWASP:')} ${finding.owaspId}`,
  ];

  if (finding.reasoning) {
    lines.push(`    ${chalk.dim('Reasoning:')} ${truncate(finding.reasoning, 200)}`);
  }

  if (finding.evidence.length > 0) {
    const ev = finding.evidence[0];
    lines.push(`    ${chalk.dim('Prompt:')} ${truncate(ev.prompt, 80)}`);
    lines.push(`    ${chalk.dim('Response:')} ${truncate(ev.response, 80)}`);
  }

  return lines.join('\n');
}

/**
 * Validate that a parsed JSON object has the required ScanResult fields.
 * Throws with a descriptive message if validation fails.
 */
export function assertScanResult(parsed: unknown, label: string): ScanResult {
  const obj = parsed as Record<string, unknown>;
  if (!obj.scanId || !obj.target || !Array.isArray(obj.findings)) {
    throw new Error(`${label} missing required fields: scanId, target, findings`);
  }
  return obj as unknown as ScanResult;
}

export function printScanSummary(result: ScanResult): void {
  const { summary } = result;

  console.log(chalk.bold('\nScan Summary'));
  console.log(chalk.dim('─'.repeat(50)));
  console.log(`  Target:  ${result.target}`);
  console.log(`  Scan ID: ${result.scanId}`);
  console.log(`  Total:   ${summary.total}`);
  console.log(
    `  ${chalk.red(`Vulnerable: ${summary.vulnerable}`)}  ` +
      `${chalk.green(`Safe: ${summary.safe}`)}  ` +
      `${chalk.yellow(`Inconclusive: ${summary.inconclusive}`)}`,
  );

  printSeverityBreakdown(summary);
  printCategoryBreakdown(summary);
}

function printSeverityBreakdown(summary: ScanSummary): void {
  const entries = Object.entries(summary.bySeverity).filter(([, count]) => count > 0);
  if (entries.length === 0) return;

  console.log(chalk.bold('\n  Vulnerabilities by Severity'));
  for (const [sev, count] of entries) {
    const colorFn = SEVERITY_COLORS[sev as Severity];
    console.log(`    ${colorFn(sev)}: ${count}`);
  }
}

function printCategoryBreakdown(summary: ScanSummary): void {
  const entries = Object.entries(summary.byCategory).filter(([, count]) => count > 0);
  if (entries.length === 0) return;

  console.log(chalk.bold('\n  Vulnerabilities by Category'));
  for (const [cat, count] of entries) {
    console.log(`    ${cat}: ${chalk.red(String(count))}`);
  }
}

/**
 * Check CI/CD fail gates. Returns the process exit code.
 * - If failOnVuln is false, always returns 0.
 * - If failOnVuln is true and vulnerability rate exceeds threshold, returns 1.
 */
export function checkFailGates(
  vulnerableCount: number,
  totalCount: number,
  failOnVuln: boolean,
  threshold: number,
): number {
  if (!failOnVuln) return 0;
  if (totalCount === 0) return 0;

  const vulnRate = vulnerableCount / totalCount;
  if (vulnRate > threshold) {
    console.log(
      chalk.red(
        `\nFail gate triggered: vulnerability rate ${(vulnRate * 100).toFixed(1)}% exceeds threshold ${(threshold * 100).toFixed(1)}%`,
      ),
    );
    return 1;
  }
  return 0;
}

/**
 * Write a scan result to a file in the specified format.
 * Reporting modules (markdown, SARIF, JUnit) may not exist yet (Track 4 parallel work).
 * Falls back to JSON if the requested format is unavailable.
 */
export async function writeReport(result: ScanResult, format: string, output: string): Promise<void> {
  await mkdir(dirname(output), { recursive: true });

  // Try to use reporting formatters if available
  if (format !== 'json') {
    try {
      const reportingPath = '../reporting/index.js';
      const reporting = (await import(/* webpackIgnore: true */ reportingPath)) as {
        generateReport: (result: ScanResult, format: string) => string | object;
      };
      const reportOutput = reporting.generateReport(result, format);
      const formatted = typeof reportOutput === 'string' ? reportOutput : JSON.stringify(reportOutput, null, 2);
      await writeFile(output, formatted, 'utf-8');
      console.log(chalk.green(`Report saved: ${output}`));
      return;
    } catch {
      // Reporting module not available — fall back to JSON
      console.log(chalk.yellow(`Warning: '${format}' formatter not available, falling back to JSON`));
    }
  }

  // Default: write JSON
  await writeFile(output, JSON.stringify(result, null, 2), 'utf-8');
  console.log(chalk.green(`Report saved: ${output}`));
}
