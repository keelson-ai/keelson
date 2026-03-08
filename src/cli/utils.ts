import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

import chalk from 'chalk';

import type { Finding, ScanResult, ScanSummary } from '../types/index.js';
import { Severity, Verdict } from '../types/index.js';

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

export function parseIntSafe(value: string, fallback: number): number {
  const parsed = parseInt(value, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
}

export function parseFloatSafe(value: string, fallback: number): number {
  const parsed = parseFloat(value);
  return Number.isNaN(parsed) ? fallback : parsed;
}

function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen) + '...';
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
 * Falls back to JSON if the requested format is unavailable.
 */
export async function writeReport(result: ScanResult, format: string, output: string): Promise<void> {
  await mkdir(dirname(output), { recursive: true });

  if (format !== 'json') {
    try {
      const reportingPath = '../reporting/index.js';
      const reporting = (await import(/* webpackIgnore: true */ reportingPath)) as {
        formatReport: (result: ScanResult, format: string) => Promise<string>;
      };
      const formatted = await reporting.formatReport(result, format);
      await writeFile(output, formatted, 'utf-8');
      console.log(chalk.green(`Report saved: ${output}`));
      return;
    } catch (err: unknown) {
      // Distinguish module-not-found from formatter errors
      const isModuleNotFound =
        err instanceof Error && 'code' in err && (err as NodeJS.ErrnoException).code === 'ERR_MODULE_NOT_FOUND';

      if (isModuleNotFound) {
        console.log(chalk.yellow(`Warning: '${format}' formatter not available, falling back to JSON`));
      } else {
        console.error(chalk.red(`Error in '${format}' formatter: ${err instanceof Error ? err.message : String(err)}`));
        console.log(chalk.yellow('Falling back to JSON'));
      }
    }
  }

  await writeFile(output, JSON.stringify(result, null, 2), 'utf-8');
  console.log(chalk.green(`Report saved: ${output}`));
}

/** Count occurrences grouped by a key extractor. */
export function countBy<T>(items: T[], keyFn: (item: T) => string): Map<string, number> {
  const counts = new Map<string, number>();
  for (const item of items) {
    const key = keyFn(item);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
}
