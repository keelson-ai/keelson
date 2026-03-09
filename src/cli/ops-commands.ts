import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import chalk from 'chalk';
import type { Command } from 'commander';

import {
  DEFAULT_OUTPUT_DIR,
  assertScanResult,
  colorSeverity,
  printScanSummary,
  withStore,
  writeReport,
} from './utils.js';
import { loadProbes } from '../core/index.js';
import { diffScans, enhancedDiffScans, formatDiffReport } from '../diff/index.js';
import { Store } from '../state/index.js';
import type { ProbeTemplate, RegressionAlert, ScanResult } from '../types/index.js';
import { SEVERITY_ORDER } from '../types/index.js';
import { getErrorMessage } from '../utils.js';

function formatProbeRow(probe: ProbeTemplate): string {
  const id = chalk.bold(probe.id.padEnd(8));
  const name = probe.name.padEnd(40).slice(0, 40);
  const sev = colorSeverity(probe.severity).padEnd(20);
  const cat = probe.category.padEnd(25).slice(0, 25);
  const steps = String(probe.turns.length).padStart(5);
  return `  ${id} ${name} ${sev} ${cat} ${steps}`;
}

export function registerOpsCommands(program: Command): void {
  program
    .command('list')
    .description('List all available probes')
    .option('--category <category>', 'Filter by category')
    .action(async (opts) => {
      const probes = await loadProbes();

      let filtered = probes;
      if (opts.category) {
        const cat = opts.category.toLowerCase();
        filtered = probes.filter((p) => p.category.toLowerCase() === cat);
      }

      // Sort by severity (critical first) then by ID
      filtered.sort((a, b) => {
        const sevDiff = (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
        if (sevDiff !== 0) return sevDiff;
        return a.id.localeCompare(b.id);
      });

      console.log(chalk.bold('\nAvailable Security Probes'));
      console.log(chalk.dim('─'.repeat(110)));

      // Header
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

      // Category summary
      const categories = new Map<string, number>();
      for (const p of filtered) {
        categories.set(p.category, (categories.get(p.category) ?? 0) + 1);
      }
      if (categories.size > 1) {
        console.log(chalk.bold('\n  Categories:'));
        for (const [cat, count] of [...categories.entries()].sort()) {
          console.log(`    ${cat}: ${count}`);
        }
      }
    });

  program
    .command('report')
    .description('Generate a report from a stored scan or JSON file')
    .option('--scan-id <id>', 'Scan ID to load from store')
    .option('--input <path>', 'Path to scan result JSON file')
    .option('--format <format>', 'Output format: json, markdown, sarif, junit', 'json')
    .option('--output <path>', 'Output file path')
    .action(async (opts) => {
      let result: ScanResult;

      if (opts.scanId) {
        const store = Store.open();
        const scan = store.getScan(opts.scanId);
        store.close();
        if (!scan) {
          console.error(chalk.red(`Scan not found: ${opts.scanId}`));
          process.exit(1);
        }
        result = scan;
      } else if (opts.input) {
        let resultData: string;
        try {
          resultData = await readFile(opts.input, 'utf-8');
        } catch {
          console.error(chalk.red(`Error: cannot read file ${opts.input}`));
          process.exit(1);
        }
        try {
          result = assertScanResult(JSON.parse(resultData), 'scan result');
        } catch (err) {
          console.error(chalk.red(`Error: invalid scan result JSON — ${getErrorMessage(err)}`));
          process.exit(1);
        }
      } else {
        console.error(chalk.red('Error: provide --scan-id or --input'));
        process.exit(1);
      }

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
    .action(async (opts) => {
      console.log(chalk.bold('\nValidating probe playbooks...'));
      console.log();

      let probes: ProbeTemplate[];
      const errors: Array<{ file: string; error: string }> = [];

      try {
        probes = await loadProbes(opts.dir);
      } catch (err) {
        console.error(chalk.red(`Error loading probes: ${getErrorMessage(err)}`));
        process.exit(1);
      }

      // Additional validation checks
      const ids = new Set<string>();
      for (const probe of probes) {
        // Check for duplicate IDs
        if (ids.has(probe.id)) {
          errors.push({
            file: probe.sourcePath ?? probe.id,
            error: `Duplicate probe ID: ${probe.id}`,
          });
        }
        ids.add(probe.id);

        // Check evaluation criteria completeness
        if (probe.evaluation.vulnerableIf.length === 0 || probe.evaluation.safeIf.length === 0) {
          errors.push({
            file: probe.sourcePath ?? probe.id,
            error: `Missing evaluation criteria: vulnerableIf or safeIf is empty`,
          });
        }

        // Check for empty turns
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

      // Show summary by category
      const categories = new Map<string, number>();
      for (const p of probes) {
        categories.set(p.category, (categories.get(p.category) ?? 0) + 1);
      }
      console.log();
      for (const [cat, count] of [...categories.entries()].sort()) {
        console.log(`  ${cat}: ${count} probes`);
      }
    });

  program
    .command('diff')
    .description('Compare two scans to detect regressions and improvements')
    .option('--scan-a <id>', 'First scan ID (from store)')
    .option('--scan-b <id>', 'Second scan ID (from store)')
    .option('--file-a <name>', 'First scan filename (in output dir)')
    .option('--file-b <name>', 'Second scan filename (in output dir)')
    .option('--latest', 'Use the most recent scan')
    .option('--previous', 'Use the second most recent scan (with --latest)')
    .option('--baseline', 'Use the current baseline scan (with --latest)')
    .option('--enhanced', 'Include severity-classified regression alerts', false)
    .option('--output <path>', 'Write diff report to file')
    .action(async (opts) => {
      const store = Store.open();

      let scanA: ScanResult | undefined;
      let scanB: ScanResult | undefined;

      // Resolve scan A
      if (opts.scanA) {
        scanA = store.getScan(opts.scanA);
        if (!scanA) {
          console.error(chalk.red(`Scan not found: ${opts.scanA}`));
          store.close();
          process.exit(1);
        }
      } else if (opts.fileA) {
        const outputDir = DEFAULT_OUTPUT_DIR;
        try {
          const raw = await readFile(join(outputDir, opts.fileA), 'utf-8');
          scanA = assertScanResult(JSON.parse(raw), 'file-a');
        } catch {
          console.error(chalk.red(`Error: cannot read file ${opts.fileA} from ${outputDir}`));
          store.close();
          process.exit(1);
        }
      } else if (opts.baseline) {
        const baselines = store.getBaselines(1);
        if (baselines.length === 0) {
          console.error(chalk.red('No baseline set'));
          store.close();
          process.exit(1);
        }
        scanA = store.getScan(baselines[0].scanId);
        if (!scanA) {
          console.error(chalk.red(`Baseline scan not found: ${baselines[0].scanId}`));
          store.close();
          process.exit(1);
        }
      }

      // Resolve scan B
      if (opts.scanB) {
        scanB = store.getScan(opts.scanB);
        if (!scanB) {
          console.error(chalk.red(`Scan not found: ${opts.scanB}`));
          store.close();
          process.exit(1);
        }
      } else if (opts.fileB) {
        const outputDir = DEFAULT_OUTPUT_DIR;
        try {
          const raw = await readFile(join(outputDir, opts.fileB), 'utf-8');
          scanB = assertScanResult(JSON.parse(raw), 'file-b');
        } catch {
          console.error(chalk.red(`Error: cannot read file ${opts.fileB} from ${outputDir}`));
          store.close();
          process.exit(1);
        }
      } else if (opts.latest) {
        const recent = store.listScans(2);
        if (recent.length === 0) {
          console.error(chalk.red('No scans in store'));
          store.close();
          process.exit(1);
        }
        scanB = store.getScan(recent[0].scanId);
        if (opts.previous && recent.length >= 2) {
          scanA = store.getScan(recent[1].scanId);
        }
      }

      store.close();

      if (!scanA || !scanB) {
        console.error(
          chalk.red(
            'Error: could not resolve both scans. Use --scan-a/--scan-b, --file-a/--file-b, or --latest --previous/--baseline',
          ),
        );
        process.exit(1);
      }

      // Keep existing diff logic (enhanced vs basic)
      if (opts.enhanced) {
        const { diff, alerts } = enhancedDiffScans(scanA, scanB);
        const report = formatDiffReport(diff);
        console.log(report);

        if (alerts.length > 0) {
          console.log(chalk.bold('\nRegression Alerts'));
          for (const alert of alerts) {
            const color =
              alert.alertSeverity === 'critical' || alert.alertSeverity === 'high'
                ? chalk.red
                : alert.alertSeverity === 'medium'
                  ? chalk.yellow
                  : chalk.dim;
            console.log(`  ${color(`[${alert.alertSeverity.toUpperCase()}]`)} ${alert.description}`);
          }
        }

        if (opts.output) {
          const alertSection =
            alerts.length > 0
              ? '\n### Regression Alerts\n\n' +
                alerts
                  .map((a: RegressionAlert) => `- **[${a.alertSeverity.toUpperCase()}]** ${a.description}`)
                  .join('\n') +
                '\n'
              : '';
          await writeFile(opts.output, report + alertSection, 'utf-8');
          console.log(`\nReport saved: ${opts.output}`);
        }
      } else {
        const diff = diffScans(scanA, scanB);
        const report = formatDiffReport(diff);
        console.log(report);

        if (opts.output) {
          await writeFile(opts.output, report, 'utf-8');
          console.log(`\nReport saved: ${opts.output}`);
        }
      }
    });

  // ─── History command ─────────────────────────────────────

  program
    .command('history')
    .description('List recent scans with date, target, and vulnerability counts')
    .option('--limit <n>', 'Max results to show', '20')
    .action((opts) => {
      const scans = withStore((store) => store.listScans(parseInt(opts.limit, 10)));

      if (scans.length === 0) {
        console.log('\nNo scans found. Run `keelson scan` to get started.');
        return;
      }

      console.log(chalk.bold('\nScan History'));
      console.log(chalk.dim('─'.repeat(100)));
      const header =
        `  ${'ID'.padEnd(30)} ${'Target'.padEnd(30)} ` +
        `${'Date'.padEnd(20)} ${'Total'.padStart(5)} ${'Vuln'.padStart(5)} ${'Safe'.padStart(5)}`;
      console.log(chalk.dim(header));
      console.log(chalk.dim('─'.repeat(100)));

      for (const s of scans) {
        const date = new Date(s.startedAt).toISOString().slice(0, 16).replace('T', ' ');
        const target = s.target.slice(0, 30).padEnd(30);
        const vuln = s.vulnerable > 0 ? chalk.red(String(s.vulnerable).padStart(5)) : String(s.vulnerable).padStart(5);
        console.log(
          `  ${s.scanId.padEnd(30)} ${target} ${date.padEnd(20)} ${String(s.total).padStart(5)} ${vuln} ${String(s.safe).padStart(5)}`,
        );
      }

      console.log(chalk.dim('─'.repeat(100)));
      console.log(`  ${scans.length} scan(s)`);
    });

  // ─── Baseline commands ───────────────────────────────────

  const baselineCmd = program.command('baseline').description('Manage scan baselines for regression comparison');

  baselineCmd
    .command('set')
    .description('Mark a scan as the baseline for future comparisons')
    .argument('<scan-id>', 'Scan ID to set as baseline')
    .option('--label <label>', 'Optional label for this baseline', '')
    .action((scanId: string, opts) => {
      const scan = withStore((store) => {
        const s = store.getScan(scanId);
        if (!s) {
          console.error(chalk.red(`Scan not found: ${scanId}`));
          process.exit(1);
        }
        store.saveBaseline(scanId, opts.label);
        return s;
      });
      if (scan) {
        console.log(`Baseline set: ${scanId}${opts.label ? ` (${opts.label})` : ''}`);
      }
    });

  baselineCmd
    .command('list')
    .description('Show all saved baselines')
    .option('--limit <n>', 'Max results', '20')
    .action((opts) => {
      const baselines = withStore((store) => store.getBaselines(parseInt(opts.limit, 10)));

      if (baselines.length === 0) {
        console.log('\nNo baselines set. Use `keelson baseline set <scan-id>` after a scan.');
        return;
      }

      console.log(chalk.bold('\nBaselines'));
      console.log(chalk.dim('─'.repeat(70)));
      for (const b of baselines) {
        const date = new Date(b.createdAt).toISOString().slice(0, 16).replace('T', ' ');
        const label = b.label ? chalk.dim(` (${b.label})`) : '';
        console.log(`  ${b.scanId}  ${date}${label}`);
      }
    });

  // ─── Alerts commands ─────────────────────────────────────

  const alertsCmd = program
    .command('alerts')
    .description('List unacknowledged regression alerts')
    .option('--all', 'Show acknowledged alerts too', false)
    .option('--limit <n>', 'Max results', '50')
    .action((opts) => {
      const alerts = withStore((store) => store.listRegressionAlerts(parseInt(opts.limit, 10)));

      const filtered = opts.all ? alerts : alerts.filter((a) => !a.acknowledged);

      if (filtered.length === 0) {
        console.log('\nNo regression alerts.');
        return;
      }

      console.log(chalk.bold('\nRegression Alerts'));
      console.log(chalk.dim('─'.repeat(90)));
      for (const a of filtered) {
        const color =
          a.alertSeverity === 'critical' || a.alertSeverity === 'high'
            ? chalk.red
            : a.alertSeverity === 'medium'
              ? chalk.yellow
              : chalk.dim;
        const ack = a.acknowledged ? chalk.dim(' [ack]') : '';
        console.log(`  ${chalk.dim(`#${a.id}`)} ${color(`[${a.alertSeverity.toUpperCase()}]`)} ${a.description}${ack}`);
      }
    });

  alertsCmd
    .command('ack')
    .description('Acknowledge a regression alert')
    .argument('<alert-id>', 'Alert ID to acknowledge')
    .action((alertIdStr: string) => {
      const alertId = parseInt(alertIdStr, 10);
      if (isNaN(alertId)) {
        console.error(chalk.red('Invalid alert ID'));
        process.exit(1);
      }
      withStore((store) => store.acknowledgeAlert(alertId));
      console.log(`Alert #${alertId} acknowledged.`);
    });

  // ─── Store commands ──────────────────────────────────────

  const storeCmd = program.command('store').description('Manage the persistent store');

  storeCmd
    .command('path')
    .description('Print the store database path')
    .action(() => {
      const dbPath = withStore((store) => store.dbPath);
      console.log(dbPath);
    });

  storeCmd
    .command('info')
    .description('Show store location, size, and row counts per table')
    .action(() => {
      const { dbPath, stats } = withStore((store) => ({
        dbPath: store.dbPath,
        stats: store.getStats(),
      }));

      console.log(chalk.bold('\nKeelson Store'));
      console.log(chalk.dim('─'.repeat(40)));
      console.log(`  Path:       ${dbPath}`);
      console.log(`  Scans:      ${stats.scans}`);
      console.log(`  Campaigns:  ${stats.campaigns}`);
      console.log(`  Profiles:   ${stats.agent_profiles}`);
      console.log(`  Baselines:  ${stats.baselines}`);
      console.log(`  Cache:      ${stats.cache}`);
      console.log(`  Alerts:     ${stats.regression_alerts}`);
      console.log(`  Chains:     ${stats.probe_chains}`);
      console.log(`  Events:     ${stats.events}`);
    });
}
