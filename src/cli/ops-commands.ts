import { readFile } from 'node:fs/promises';

import chalk from 'chalk';
import type { Command } from 'commander';

import { SEVERITY_COLORS, countBy, printScanSummary, writeReport } from './utils.js';
import { loadProbes } from '../core/templates.js';
import { scanResultSchema } from '../schemas/scan-result.js';
import type { ProbeTemplate, ScanResult } from '../types/index.js';
import { SEVERITY_ORDER } from '../types/index.js';

function formatProbeRow(probe: ProbeTemplate): string {
  const id = chalk.bold(probe.id.padEnd(8));
  const name = probe.name.padEnd(40).slice(0, 40);
  const colorFn = SEVERITY_COLORS[probe.severity];
  const sev = colorFn(probe.severity.padEnd(20));
  const cat = probe.category.padEnd(25).slice(0, 25);
  const steps = String(probe.turns.length).padStart(5);
  return `  ${id} ${name} ${sev} ${cat} ${steps}`;
}

function printCategorySummary(categories: Map<string, number>): void {
  if (categories.size <= 1) return;
  console.log(chalk.bold('\n  Categories:'));
  for (const [cat, count] of [...categories.entries()].sort()) {
    console.log(`    ${cat}: ${count}`);
  }
}

export function registerOpsCommands(program: Command): void {
  program
    .command('list')
    .description('List all available probes')
    .option('--category <category>', 'Filter by category')
    .action(async (opts: { category?: string }) => {
      const probes = await loadProbes();

      let filtered = probes;
      if (opts.category) {
        const cat = opts.category.toLowerCase();
        filtered = probes.filter((p) => p.category.toLowerCase() === cat);
      }

      filtered.sort((a, b) => {
        const sevDiff = (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
        if (sevDiff !== 0) return sevDiff;
        return a.id.localeCompare(b.id);
      });

      console.log(chalk.bold('\nAvailable Security Probes'));
      console.log(chalk.dim('─'.repeat(110)));

      const header =
        `  ${'ID'.padEnd(8)} ${'Name'.padEnd(40)} ` +
        `${'Severity'.padEnd(20)} ${'Category'.padEnd(25)} ${'Steps'.padStart(5)}`;
      console.log(chalk.dim(header));
      console.log(chalk.dim('─'.repeat(110)));

      for (const probe of filtered) {
        console.log(formatProbeRow(probe));
      }

      console.log(chalk.dim('─'.repeat(110)));
      console.log(`  Total: ${filtered.length} probes`);

      printCategorySummary(countBy(filtered, (p) => p.category));
    });

  program
    .command('report')
    .description('Generate report from saved scan JSON')
    .requiredOption('--input <path>', 'Path to scan result JSON file')
    .option('--format <format>', 'Output format: json, markdown, sarif, junit', 'json')
    .option('--output <path>', 'Output file path')
    .action(async (opts: { input: string; format: string; output?: string }) => {
      let resultData: string;
      try {
        resultData = await readFile(opts.input, 'utf-8');
      } catch {
        console.error(chalk.red(`Error: cannot read file ${opts.input}`));
        process.exit(1);
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(resultData);
      } catch {
        console.error(chalk.red('Error: invalid JSON in input file'));
        process.exit(1);
      }

      const validation = scanResultSchema.safeParse(parsed);
      if (!validation.success) {
        console.error(chalk.red('Error: invalid scan result structure'));
        for (const issue of validation.error.issues) {
          console.error(chalk.dim(`  ${issue.path.join('.')}: ${issue.message}`));
        }
        process.exit(1);
      }

      const result = validation.data as ScanResult;

      printScanSummary(result);

      if (opts.output) {
        await writeReport(result, opts.format, opts.output);
      } else {
        console.log(JSON.stringify(result, null, 2));
      }
    });

  program
    .command('validate')
    .description('Validate probe YAML files')
    .option('--dir <directory>', 'Probes directory to validate')
    .action(async (opts: { dir?: string }) => {
      console.log(chalk.bold('\nValidating probe playbooks...'));
      console.log();

      let probes: ProbeTemplate[];
      const errors: Array<{ file: string; error: string }> = [];

      try {
        probes = await loadProbes(opts.dir);
      } catch (err) {
        console.error(chalk.red(`Error loading probes: ${err instanceof Error ? err.message : String(err)}`));
        process.exit(1);
        return;
      }

      const ids = new Set<string>();
      for (const probe of probes) {
        if (ids.has(probe.id)) {
          errors.push({
            file: probe.sourcePath ?? probe.id,
            error: `Duplicate probe ID: ${probe.id}`,
          });
        }
        ids.add(probe.id);

        if (probe.evaluation.vulnerableIf.length === 0 || probe.evaluation.safeIf.length === 0) {
          errors.push({
            file: probe.sourcePath ?? probe.id,
            error: `Missing evaluation criteria: vulnerableIf or safeIf is empty`,
          });
        }

        const emptyTurns = probe.turns.filter((t) => t.content.trim().length === 0);
        if (emptyTurns.length > 0) {
          errors.push({
            file: probe.sourcePath ?? probe.id,
            error: `Contains ${emptyTurns.length} empty turn(s)`,
          });
        }
      }

      if (errors.length > 0) {
        console.log(chalk.red(`Found ${errors.length} validation error(s):\n`));
        for (const { file, error } of errors) {
          console.log(`  ${chalk.red('\u2717')} ${file}`);
          console.log(`    ${error}`);
        }
        process.exit(1);
      }

      console.log(chalk.green(`\u2713 All ${probes.length} probes are valid`));

      const categories = countBy(probes, (p) => p.category);
      console.log();
      for (const [cat, count] of [...categories.entries()].sort()) {
        console.log(`  ${cat}: ${count} probes`);
      }
    });
}
