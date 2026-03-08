import type { Command } from 'commander';

import { createAdapter } from '../adapters/index.js';
import { executeProbe } from '../core/engine.js';
import { scan } from '../core/scanner.js';
import { loadProbes } from '../core/templates.js';
import type { AdapterConfig, Finding, ScanResult } from '../types/index.js';
import { Severity, Verdict } from '../types/index.js';
import {
  checkFailGates,
  colorSeverity,
  formatFinding,
  printScanSummary,
  VERDICT_LABELS,
  writeReport,
} from './utils.js';

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

export function registerScanCommands(program: Command): void {
  program
    .command('scan')
    .description('Run a full security scan against an AI agent endpoint')
    .requiredOption('--target <url>', 'Target endpoint URL')
    .option('--api-key <key>', 'API key for authentication')
    .option('--model <model>', 'Model name for requests', 'default')
    .option('--category <category>', 'Filter by category')
    .option('--delay <ms>', 'Milliseconds between requests', '1500')
    .option('--output <path>', 'Report output path')
    .option('--format <format>', 'Output format: json, markdown, sarif, junit', 'json')
    .option('--adapter-type <type>', 'Adapter type', 'openai')
    .option('--fail-on-vuln', 'Exit with code 1 if vulnerabilities found', false)
    .option(
      '--fail-threshold <rate>',
      'Vulnerability rate threshold (0.0-1.0)',
      '0.0',
    )
    .option('--concurrency <n>', 'Max concurrent probes', '1')
    .action(async (opts) => {
      const adapterConfig = buildAdapterConfig({
        target: opts.target,
        apiKey: opts.apiKey,
        model: opts.model,
        adapterType: opts.adapterType,
      });
      const adapter = createAdapter(adapterConfig);

      const categories = opts.category ? [opts.category] : undefined;
      const delayMs = parseInt(opts.delay, 10);
      const concurrency = parseInt(opts.concurrency, 10);

      console.log('\nKeelson Security Scan');
      console.log(`Target: ${opts.target}`);
      console.log(`Model: ${opts.model}`);
      if (opts.category) {
        console.log(`Category: ${opts.category}`);
      }
      console.log();

      let findingIndex = 0;

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
              finding.verdict === Verdict.Vulnerable
                ? '\u2717'
                : finding.verdict === Verdict.Safe
                  ? '\u2713'
                  : '?';
            console.log(
              `  ${progress} ${icon} ${finding.probeId}: ${finding.probeName} — ${finding.verdict}`,
            );
          },
        });
      } finally {
        await adapter.close();
      }

      // Print detailed findings for vulnerabilities
      const vulnFindings = result.findings.filter(
        (f) => f.verdict === Verdict.Vulnerable,
      );
      if (vulnFindings.length > 0) {
        console.log('\nVulnerabilities Found:');
        for (const f of vulnFindings) {
          console.log(formatFinding(f, findingIndex++));
        }
      }

      printScanSummary(result);

      if (opts.output) {
        await writeReport(result, opts.format, opts.output);
      }

      const exitCode = checkFailGates(
        result.summary.vulnerable,
        result.summary.total,
        opts.failOnVuln,
        parseFloat(opts.failThreshold),
      );
      if (exitCode !== 0) {
        process.exit(exitCode);
      }
    });

  program
    .command('smart-scan')
    .description(
      'Adaptive scan: recon, classify, select relevant probes, execute',
    )
    .requiredOption('--target <url>', 'Target endpoint URL')
    .option('--api-key <key>', 'API key for authentication')
    .option('--model <model>', 'Model name for requests', 'default')
    .option('--delay <ms>', 'Milliseconds between requests', '2000')
    .option('--output <path>', 'Report output path')
    .option('--format <format>', 'Output format: json, markdown, sarif, junit', 'json')
    .option('--adapter-type <type>', 'Adapter type', 'openai')
    .option('--fail-on-vuln', 'Exit with code 1 if vulnerabilities found', false)
    .option(
      '--fail-threshold <rate>',
      'Vulnerability rate threshold (0.0-1.0)',
      '0.0',
    )
    .action(async (opts) => {
      const adapterConfig = buildAdapterConfig({
        target: opts.target,
        apiKey: opts.apiKey,
        model: opts.model,
        adapterType: opts.adapterType,
      });
      const adapter = createAdapter(adapterConfig);

      console.log('\nKeelson Smart Scan');
      console.log(`Target: ${opts.target}`);
      console.log(`Model: ${opts.model}`);
      console.log();

      // Smart scan uses all probes ordered by effectiveness, reordering as it goes
      let result: ScanResult;
      try {
        result = await scan(opts.target, adapter, {
          delayMs: parseInt(opts.delay, 10),
          reorder: true,
          onFinding: (finding, current, total) => {
            const progress = `[${current}/${total}]`;
            console.log(
              `  ${progress} ${finding.probeId}: ${finding.verdict}`,
            );
          },
        });
      } finally {
        await adapter.close();
      }

      printScanSummary(result);

      if (opts.output) {
        await writeReport(result, opts.format, opts.output);
      }

      const exitCode = checkFailGates(
        result.summary.vulnerable,
        result.summary.total,
        opts.failOnVuln,
        parseFloat(opts.failThreshold),
      );
      if (exitCode !== 0) {
        process.exit(exitCode);
      }
    });

  program
    .command('convergence-scan')
    .description('Cross-category feedback loop with iterative passes')
    .requiredOption('--target <url>', 'Target endpoint URL')
    .option('--api-key <key>', 'API key for authentication')
    .option('--model <model>', 'Model name for requests', 'default')
    .option('--category <category>', 'Initial category filter')
    .option('--delay <ms>', 'Milliseconds between requests', '1500')
    .option('--output <path>', 'Report output path')
    .option('--format <format>', 'Output format: json, markdown, sarif, junit', 'json')
    .option('--adapter-type <type>', 'Adapter type', 'openai')
    .option('--fail-on-vuln', 'Exit with code 1 if vulnerabilities found', false)
    .option(
      '--fail-threshold <rate>',
      'Vulnerability rate threshold (0.0-1.0)',
      '0.0',
    )
    .option('--max-passes <n>', 'Maximum convergence passes', '4')
    .action(async (opts) => {
      const adapterConfig = buildAdapterConfig({
        target: opts.target,
        apiKey: opts.apiKey,
        model: opts.model,
        adapterType: opts.adapterType,
      });
      const adapter = createAdapter(adapterConfig);
      const maxPasses = parseInt(opts.maxPasses, 10);

      console.log('\nKeelson Convergence Scan');
      console.log(`Target: ${opts.target}`);
      console.log(`Model: ${opts.model}`);
      console.log(`Max passes: ${maxPasses}`);
      if (opts.category) {
        console.log(`Initial category: ${opts.category}`);
      }
      console.log();

      // Run multiple convergence passes
      const allFindings: ScanResult[] = [];
      const seenVulnerableProbeIds = new Set<string>();
      try {
        for (let pass = 1; pass <= maxPasses; pass++) {
          console.log(`  PASS ${pass}  Running probes...`);

          const categories = opts.category ? [opts.category] : undefined;
          const passResult = await scan(opts.target, adapter, {
            categories,
            delayMs: parseInt(opts.delay, 10),
            reorder: true,
            onFinding: (finding, current, total) => {
              console.log(
                `    [${current}/${total}] ${finding.probeId}: ${finding.verdict}`,
              );
            },
          });

          allFindings.push(passResult);

          // Count only truly new vulnerabilities (probe IDs not seen in previous passes)
          let newVulns = 0;
          for (const finding of passResult.findings) {
            if (
              finding.verdict === Verdict.Vulnerable &&
              !seenVulnerableProbeIds.has(finding.probeId)
            ) {
              newVulns++;
              seenVulnerableProbeIds.add(finding.probeId);
            }
          }

          console.log(
            `  PASS ${pass}  Complete: ${newVulns} new vulnerabilities found`,
          );

          // Converge: stop if no new unique vulnerabilities were found
          if (newVulns === 0 && pass > 1) {
            console.log('  Converged: no new vulnerabilities in this pass.');
            break;
          }
        }
      } finally {
        await adapter.close();
      }

      // Merge findings from all passes, deduplicating by probeId
      // When a probe appears in multiple passes, keep the worst verdict
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
          if (
            !existing ||
            (verdictRank[finding.verdict] ?? 0) >
              (verdictRank[existing.verdict] ?? 0)
          ) {
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
          bySeverity[f.severity as Severity] =
            (bySeverity[f.severity as Severity] ?? 0) + 1;
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
      printScanSummary(result);

      if (opts.output) {
        await writeReport(result, opts.format, opts.output);
      }

      const exitCode = checkFailGates(
        result.summary.vulnerable,
        result.summary.total,
        opts.failOnVuln,
        parseFloat(opts.failThreshold),
      );
      if (exitCode !== 0) {
        process.exit(exitCode);
      }
    });

  const testCmd = program
    .command('test')
    .description('Run a single probe against a target')
    .requiredOption('--target <url>', 'Target endpoint URL')
    .requiredOption('--probe-id <id>', 'Probe ID (e.g., GA-001)')
    .option('--api-key <key>', 'API key for authentication')
    .option('--model <model>', 'Model name for requests', 'default')
    .option('--adapter-type <type>', 'Adapter type', 'openai')
    .action(async (opts) => {
      const adapterConfig = buildAdapterConfig({
        target: opts.target,
        apiKey: opts.apiKey,
        model: opts.model,
        adapterType: opts.adapterType,
      });
      const adapter = createAdapter(adapterConfig);

      const probes = await loadProbes();
      const template = probes.find((p) => p.id === opts.probeId);
      if (!template) {
        console.error(`Probe ${opts.probeId} not found`);
        process.exit(1);
      }

      console.log(`\n${template.id}: ${template.name}`);
      console.log(
        `Severity: ${colorSeverity(template.severity)} | Category: ${template.category}`,
      );
      console.log();

      let finding;
      try {
        finding = await executeProbe(template, adapter, {
          onTurn: (stepIndex, prompt, response) => {
            console.log(`  Step ${stepIndex}:`);
            const promptPreview =
              prompt.length > 150 ? prompt.slice(0, 150) + '...' : prompt;
            const responsePreview =
              response.length > 200 ? response.slice(0, 200) + '...' : response;
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
  program
    .command('probe')
    .description('Run a single probe (alias for test)')
    .requiredOption('--target <url>', 'Target endpoint URL')
    .requiredOption('--probe-id <id>', 'Probe ID (e.g., GA-001)')
    .option('--api-key <key>', 'API key for authentication')
    .option('--model <model>', 'Model name for requests', 'default')
    .option('--adapter-type <type>', 'Adapter type', 'openai')
    .action(async (opts) => {
      // Delegate to the test command action
      await testCmd.parseAsync(
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
