import type { Command } from 'commander';

import {
  VERDICT_LABELS,
  checkFailGates,
  colorSeverity,
  formatFinding,
  parseFloatSafe,
  parseIntSafe,
  printScanSummary,
  writeReport,
} from './utils.js';
import { createAdapter } from '../adapters/index.js';
import { executeProbe } from '../core/engine.js';
import { scan } from '../core/scanner.js';
import { loadProbes } from '../core/templates.js';
import type { AdapterConfig, Finding, ScanResult } from '../types/index.js';
import { Severity, Verdict } from '../types/index.js';

function buildAdapterConfig(opts: {
  target: string;
  apiKey?: string;
  model?: string;
  adapterType?: string;
}): AdapterConfig {
  return {
    type: opts.adapterType ?? 'openai',
    baseUrl: opts.target,
    apiKey: opts.apiKey,
    model: opts.model,
  };
}

interface ScanCommandOpts {
  target: string;
  apiKey?: string;
  model: string;
  category?: string;
  delay: string;
  output?: string;
  format: string;
  adapterType: string;
  failOnVuln: boolean;
  failThreshold: string;
  concurrency?: string;
  maxPasses?: string;
}

function addCommonScanOptions<T extends Command>(cmd: T): T {
  return cmd
    .requiredOption('--target <url>', 'Target endpoint URL')
    .option('--api-key <key>', 'API key for authentication')
    .option('--model <model>', 'Model name for requests', 'default')
    .option('--delay <ms>', 'Milliseconds between requests', '1500')
    .option('--output <path>', 'Report output path')
    .option('--format <format>', 'Output format: json, markdown, sarif, junit', 'json')
    .option('--adapter-type <type>', 'Adapter type', 'openai')
    .option('--fail-on-vuln', 'Exit with code 1 if vulnerabilities found', false)
    .option('--fail-threshold <rate>', 'Vulnerability rate threshold (0.0-1.0)', '0.0') as T;
}

async function finalizeScan(result: ScanResult, opts: ScanCommandOpts): Promise<void> {
  printScanSummary(result);

  if (opts.output) {
    await writeReport(result, opts.format, opts.output);
  }

  const exitCode = checkFailGates(
    result.summary.vulnerable,
    result.summary.total,
    opts.failOnVuln,
    parseFloatSafe(opts.failThreshold, 0),
  );
  if (exitCode !== 0) {
    process.exit(exitCode);
  }
}

export function registerScanCommands(program: Command): void {
  addCommonScanOptions(program.command('scan').description('Run a full security scan against an AI agent endpoint'))
    .option('--category <category>', 'Filter by category')
    .option('--concurrency <n>', 'Max concurrent probes', '1')
    .action(async (opts: ScanCommandOpts) => {
      const adapter = createAdapter(buildAdapterConfig(opts));
      const categories = opts.category ? [opts.category] : undefined;
      const delayMs = parseIntSafe(opts.delay, 1500);
      const concurrency = parseIntSafe(opts.concurrency ?? '1', 1);

      console.log('\nKeelson Security Scan');
      console.log(`Target: ${opts.target}`);
      console.log(`Model: ${opts.model}`);
      if (opts.category) {
        console.log(`Category: ${opts.category}`);
      }
      console.log();

      let result: ScanResult;
      try {
        result = await scan(opts.target, adapter, {
          categories,
          delayMs,
          concurrency,
          reorder: concurrency <= 1,
          onFinding: (finding, current, total) => {
            const progress = `[${current}/${total}]`;
            const icon =
              finding.verdict === Verdict.Vulnerable ? '\u2717' : finding.verdict === Verdict.Safe ? '\u2713' : '?';
            console.log(`  ${progress} ${icon} ${finding.probeId}: ${finding.probeName} — ${finding.verdict}`);
          },
        });
      } finally {
        await adapter.close();
      }

      // Print detailed findings for vulnerabilities
      const vulnFindings = result.findings.filter((f) => f.verdict === Verdict.Vulnerable);
      if (vulnFindings.length > 0) {
        console.log('\nVulnerabilities Found:');
        for (const [i, f] of vulnFindings.entries()) {
          console.log(formatFinding(f, i));
        }
      }

      await finalizeScan(result, opts);
    });

  addCommonScanOptions(
    program.command('smart-scan').description('Adaptive scan: recon, classify, select relevant probes, execute'),
  ).action(async (opts: ScanCommandOpts) => {
    const adapter = createAdapter(buildAdapterConfig(opts));
    const delayMs = parseIntSafe(opts.delay, 2000);

    console.log('\nKeelson Smart Scan');
    console.log(`Target: ${opts.target}`);
    console.log(`Model: ${opts.model}`);
    console.log();

    let result: ScanResult;
    try {
      result = await scan(opts.target, adapter, {
        delayMs,
        reorder: true,
        onFinding: (finding, current, total) => {
          const progress = `[${current}/${total}]`;
          console.log(`  ${progress} ${finding.probeId}: ${finding.verdict}`);
        },
      });
    } finally {
      await adapter.close();
    }

    await finalizeScan(result, opts);
  });

  addCommonScanOptions(
    program.command('convergence-scan').description('Cross-category feedback loop with iterative passes'),
  )
    .option('--category <category>', 'Initial category filter')
    .option('--max-passes <n>', 'Maximum convergence passes', '4')
    .action(async (opts: ScanCommandOpts) => {
      const adapter = createAdapter(buildAdapterConfig(opts));
      const maxPasses = parseIntSafe(opts.maxPasses ?? '4', 4);
      const delayMs = parseIntSafe(opts.delay, 1500);

      console.log('\nKeelson Convergence Scan');
      console.log(`Target: ${opts.target}`);
      console.log(`Model: ${opts.model}`);
      console.log(`Max passes: ${maxPasses}`);
      if (opts.category) {
        console.log(`Initial category: ${opts.category}`);
      }
      console.log();

      const allFindings: ScanResult[] = [];
      const seenVulnerableProbeIds = new Set<string>();
      try {
        for (let pass = 1; pass <= maxPasses; pass++) {
          console.log(`  PASS ${pass}  Running probes...`);

          const categories = opts.category ? [opts.category] : undefined;
          const passResult = await scan(opts.target, adapter, {
            categories,
            delayMs,
            reorder: true,
            onFinding: (finding, current, total) => {
              console.log(`    [${current}/${total}] ${finding.probeId}: ${finding.verdict}`);
            },
          });

          allFindings.push(passResult);

          let newVulns = 0;
          for (const finding of passResult.findings) {
            if (finding.verdict === Verdict.Vulnerable && !seenVulnerableProbeIds.has(finding.probeId)) {
              newVulns++;
              seenVulnerableProbeIds.add(finding.probeId);
            }
          }

          console.log(`  PASS ${pass}  Complete: ${newVulns} new vulnerabilities found`);

          if (newVulns === 0 && pass > 1) {
            console.log('  Converged: no new vulnerabilities in this pass.');
            break;
          }
        }
      } finally {
        await adapter.close();
      }

      if (allFindings.length === 0) {
        console.log('No convergence passes were executed. Check --max-passes value.');
        return;
      }

      const verdictRank: Record<string, number> = {
        [Verdict.Vulnerable]: 2,
        [Verdict.Inconclusive]: 1,
        [Verdict.Safe]: 0,
      };

      const findingsByProbe = new Map<string, Finding>();
      for (const passResult of allFindings) {
        for (const finding of passResult.findings) {
          const existing = findingsByProbe.get(finding.probeId);
          if (!existing || (verdictRank[finding.verdict] ?? 0) > (verdictRank[existing.verdict] ?? 0)) {
            findingsByProbe.set(finding.probeId, finding);
          }
        }
      }

      const mergedFindings = [...findingsByProbe.values()];
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

      for (const f of mergedFindings) {
        if (f.verdict === Verdict.Vulnerable) {
          vulnerable++;
          bySeverity[f.severity as Severity] = (bySeverity[f.severity as Severity] ?? 0) + 1;
          byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
        } else if (f.verdict === Verdict.Safe) {
          safe++;
        } else {
          inconclusive++;
        }
      }

      const lastPass = allFindings[allFindings.length - 1];
      const result: ScanResult = {
        scanId: lastPass.scanId,
        target: lastPass.target,
        startedAt: allFindings[0].startedAt,
        completedAt: lastPass.completedAt,
        findings: mergedFindings,
        summary: {
          total: mergedFindings.length,
          vulnerable,
          safe,
          inconclusive,
          bySeverity,
          byCategory,
        },
      };

      await finalizeScan(result, opts);
    });

  program
    .command('test')
    .description('Run a single probe against a target')
    .requiredOption('--target <url>', 'Target endpoint URL')
    .requiredOption('--probe-id <id>', 'Probe ID (e.g., GA-001)')
    .option('--api-key <key>', 'API key for authentication')
    .option('--model <model>', 'Model name for requests', 'default')
    .option('--adapter-type <type>', 'Adapter type', 'openai')
    .action(async (opts: { target: string; probeId: string; apiKey?: string; model: string; adapterType: string }) => {
      const adapter = createAdapter(buildAdapterConfig(opts));

      const probes = await loadProbes();
      const template = probes.find((p) => p.id === opts.probeId);
      if (!template) {
        console.error(`Probe ${opts.probeId} not found`);
        process.exit(1);
      }

      console.log(`\n${template.id}: ${template.name}`);
      console.log(`Severity: ${colorSeverity(template.severity)} | Category: ${template.category}`);
      console.log();

      let finding;
      try {
        finding = await executeProbe(template, adapter, {
          onTurn: (stepIndex, prompt, response) => {
            console.log(`  Step ${stepIndex}:`);
            const promptPreview = prompt.length > 150 ? prompt.slice(0, 150) + '...' : prompt;
            const responsePreview = response.length > 200 ? response.slice(0, 200) + '...' : response;
            console.log(`  Prompt: ${promptPreview}`);
            console.log(`  Response: ${responsePreview}`);
            console.log();
          },
        });
      } finally {
        await adapter.close();
      }

      console.log(`Verdict: ${VERDICT_LABELS[finding.verdict]}`);
      console.log(`Confidence: ${Math.round(finding.confidence * 100)}%`);
      console.log(`Reasoning: ${finding.reasoning}`);
    });

  // 'probe' is an alias for 'test'
  const testCmd = program.commands.find((c) => c.name() === 'test');
  program
    .command('probe')
    .description('Run a single probe (alias for test)')
    .requiredOption('--target <url>', 'Target endpoint URL')
    .requiredOption('--probe-id <id>', 'Probe ID (e.g., GA-001)')
    .option('--api-key <key>', 'API key for authentication')
    .option('--model <model>', 'Model name for requests', 'default')
    .option('--adapter-type <type>', 'Adapter type', 'openai')
    .action(async (opts: { target: string; probeId: string; apiKey?: string; model: string; adapterType: string }) => {
      await testCmd?.parseAsync(
        [
          '--target',
          opts.target,
          '--probe-id',
          opts.probeId,
          ...(opts.apiKey ? ['--api-key', opts.apiKey] : []),
          '--model',
          opts.model,
          '--adapter-type',
          opts.adapterType,
        ],
        { from: 'user' },
      );
    });
}
