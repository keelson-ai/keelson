import type { Command } from 'commander';

import {
  DEFAULT_OUTPUT_DIR,
  buildAdapterConfig,
  checkFailGates,
  colorSeverity,
  formatFinding,
  openStore,
  printScanSummary,
  writeScanOutput,
} from './utils.js';
import { Logger, Verbosity, parseVerbosity } from './verbosity.js';
import { createAdapter } from '../adapters/index.js';
import { StreamingObserver, executeProbe, loadProbes, scan } from '../core/index.js';
import { errorFinding, sanitizeErrorMessage } from '../core/scan-helpers.js';
import type { Store } from '../state/index.js';
import type { Adapter, ScanResult } from '../types/index.js';
import { Verdict } from '../types/index.js';

// ─── Shared helpers ─────────────────────────────────────

interface ScanCommandOpts {
  target: string;
  apiKey?: string;
  model?: string;
  adapterType?: string;
  delay?: string;
  outputDir?: string;
  format?: string;
  failOnVuln?: boolean;
  failThreshold?: string;
  category?: string;
  concurrency?: string;
  maxPasses?: string;
  noStore?: boolean;
  // SiteGPT-specific
  chatbotId?: string;
  // Browser-specific
  chatInputSelector?: string;
  chatSubmitSelector?: string;
  chatResponseSelector?: string;
  browserHeadless?: boolean;
  // HubSpot-specific
  hubspotPreInteraction?: string;
  // LLM Judge
  judgeProvider?: string;
  judgeModel?: string;
  judgeApiKey?: string;
  // Payload size limit
  maxPayloadLength?: string;
}

function buildJudge(opts: ScanCommandOpts): Adapter | undefined {
  if (!opts.judgeProvider) return undefined;
  if (!opts.judgeApiKey) {
    process.stderr.write('Warning: --judge-provider set but --judge-api-key missing; judge disabled\n');
    return undefined;
  }
  return createAdapter({
    type: opts.judgeProvider,
    baseUrl: '', // adapters resolve their own base URL from type
    apiKey: opts.judgeApiKey,
    model: opts.judgeModel ?? 'default',
  });
}

function printHeader(logger: Logger, title: string, opts: ScanCommandOpts, extra?: Record<string, string>): void {
  logger.info(`\n${title}`);
  logger.info(`Target: ${opts.target}`);
  logger.info(`Model: ${opts.model}`);
  for (const [key, value] of Object.entries(extra ?? {})) {
    logger.info(`${key}: ${value}`);
  }
  logger.info('');
}

async function finalizeScan(
  result: ScanResult,
  store: Store | null,
  opts: ScanCommandOpts,
  logger: Logger,
  showVulnDetails = true,
): Promise<void> {
  try {
    if (store) {
      store.saveScan(result);
    }

    if (showVulnDetails) {
      const vulnFindings = result.findings.filter((f) => f.verdict === Verdict.Vulnerable);
      if (vulnFindings.length > 0) {
        logger.info('\nVulnerabilities Found:');
        vulnFindings.forEach((f, i) => logger.info(formatFinding(f, i)));
      }
    }

    printScanSummary(result, logger);

    const outputDir = opts.outputDir ?? DEFAULT_OUTPUT_DIR;
    const filePath = await writeScanOutput(result, opts.format ?? 'json', outputDir);
    logger.info(`Scan ID: ${result.scanId}`);
    logger.info(`Output:  ${filePath}`);

    const exitCode = checkFailGates(
      result.summary.vulnerable,
      result.summary.total,
      opts.failOnVuln ?? false,
      parseFloat(opts.failThreshold ?? '0.0'),
      logger,
    );
    if (exitCode !== 0) {
      process.exit(exitCode);
    }
  } finally {
    store?.close();
  }
}

// ─── Shared CLI options ─────────────────────────────────

function addCommonScanOptions(cmd: ReturnType<Command['command']>, delayDefault = '1500'): typeof cmd {
  return cmd
    .requiredOption('--target <url>', 'Target endpoint URL')
    .option('--api-key <key>', 'API key for authentication')
    .option('--model <model>', 'Model name for requests', 'default')
    .option('--delay <ms>', 'Milliseconds between requests', delayDefault)
    .option('--output-dir <dir>', 'Output directory (default: ~/.keelson/output/)')
    .option('--no-store', 'Skip saving to persistent store')
    .option('--format <format>', 'Output format: json, markdown, sarif, junit', 'json')
    .option('--adapter-type <type>', 'Adapter type', 'openai')
    .option('--fail-on-vuln', 'Exit with code 1 if vulnerabilities found', false)
    .option('--fail-threshold <rate>', 'Vulnerability rate threshold (0.0-1.0)', '0.0')
    .option('--chatbot-id <id>', 'Chatbot ID (SiteGPT adapter)')
    .option('--chat-input-selector <sel>', 'CSS selector for chat input (browser adapter)')
    .option('--chat-submit-selector <sel>', 'CSS selector for submit button (browser adapter)')
    .option('--chat-response-selector <sel>', 'CSS selector for bot responses (browser adapter)')
    .option('--browser-headless', 'Run browser in headless mode (default: true)', true)
    .option('--no-browser-headless', 'Run browser in headed mode (visible)')
    .option('--hubspot-pre-interaction <js>', 'JS snippet to run before HubSpot chat interaction')
    .option('--judge-provider <type>', 'LLM judge adapter type (e.g., openai, anthropic)')
    .option('--judge-model <model>', 'LLM judge model name')
    .option('--judge-api-key <key>', 'API key for LLM judge')
    .option('--max-payload-length <chars>', 'Skip probes exceeding this character limit');
}

// ─── Commands ───────────────────────────────────────────

export function registerScanCommands(program: Command): void {
  addCommonScanOptions(program.command('scan').description('Run a full security scan against an AI agent endpoint'))
    .option('--category <category>', 'Filter by category')
    .option('--concurrency <n>', 'Max concurrent probes', '1')
    .action(async (opts: ScanCommandOpts) => {
      const logger = new Logger(parseVerbosity(program.opts().verbose));
      const observer = new StreamingObserver();
      let adapter;
      let store: Store | null = null;
      try {
        adapter = createAdapter(buildAdapterConfig(opts));
        store = openStore(opts);
      } catch (err: unknown) {
        console.error(`Setup failed: ${sanitizeErrorMessage(err)}`);
        process.exit(1);
      }
      const categories = opts.category ? [opts.category] : undefined;
      const delayMs = parseInt(opts.delay ?? '1500', 10);
      const concurrency = parseInt(opts.concurrency ?? '1', 10);
      const judge = buildJudge(opts);
      const maxPayloadLength = opts.maxPayloadLength ? parseInt(opts.maxPayloadLength, 10) : undefined;

      printHeader(logger, 'Keelson Security Scan', opts, opts.category ? { Category: opts.category } : undefined);

      let result: ScanResult;
      try {
        result = await scan(opts.target, adapter, {
          categories,
          delayMs,
          concurrency,
          reorder: concurrency <= 1,
          observer,
          judge,
          maxPayloadLength,
          onFinding: (finding, current, total) => logger.finding(finding, current, total),
        });
      } finally {
        await adapter.close?.();
      }

      await finalizeScan(result, store, opts, logger);
    });

  addCommonScanOptions(
    program.command('smart-scan').description('Adaptive scan: recon, classify, select relevant probes, execute'),
    '2000',
  ).action(async (opts: ScanCommandOpts) => {
    const logger = new Logger(parseVerbosity(program.opts().verbose));
    let adapter;
    let store: Store | null = null;
    try {
      adapter = createAdapter(buildAdapterConfig(opts));
      store = openStore(opts);
    } catch (err: unknown) {
      console.error(`Setup failed: ${sanitizeErrorMessage(err)}`);
      process.exit(1);
    }

    printHeader(logger, 'Keelson Smart Scan', opts);

    let result: ScanResult;
    try {
      result = await scan(opts.target, adapter, {
        delayMs: parseInt(opts.delay ?? '2000', 10),
        reorder: true,
        onFinding: (finding, current, total) => logger.finding(finding, current, total),
      });
    } finally {
      await adapter.close?.();
    }

    await finalizeScan(result, store, opts, logger, false);
  });

  addCommonScanOptions(
    program.command('convergence-scan').description('Cross-category feedback loop with iterative passes'),
  )
    .option('--category <category>', 'Initial category filter')
    .option('--max-passes <n>', 'Maximum convergence passes', '4')
    .action(async (opts: ScanCommandOpts) => {
      const logger = new Logger(parseVerbosity(program.opts().verbose));
      let adapter;
      let store: Store | null = null;
      try {
        adapter = createAdapter(buildAdapterConfig(opts));
        store = openStore(opts);
      } catch (err: unknown) {
        console.error(`Setup failed: ${sanitizeErrorMessage(err)}`);
        process.exit(1);
      }
      const maxPasses = parseInt(opts.maxPasses ?? '4', 10);

      const extra: Record<string, string> = { 'Max passes': String(maxPasses) };
      if (opts.category) extra['Initial category'] = opts.category;
      printHeader(logger, 'Keelson Convergence Scan', opts, extra);

      const allResults: ScanResult[] = [];
      try {
        for (let pass = 1; pass <= maxPasses; pass++) {
          logger.info(`  PASS ${pass}  Running probes...`);

          const categories = opts.category ? [opts.category] : undefined;
          const passResult = await scan(opts.target, adapter, {
            categories,
            delayMs: parseInt(opts.delay ?? '1500', 10),
            reorder: true,
            onFinding: (finding, current, total) => logger.finding(finding, current, total),
          });

          allResults.push(passResult);
          logger.info(`  PASS ${pass}  Complete: ${passResult.summary.vulnerable} vulnerabilities found`);

          if (passResult.summary.vulnerable === 0 && pass > 1) {
            logger.info('  Converged: no new vulnerabilities in this pass.');
            break;
          }
        }
      } finally {
        await adapter.close?.();
      }

      const result = allResults[allResults.length - 1];
      await finalizeScan(result, store, opts, logger, false);
    });

  program
    .command('probe')
    .description('Run a single probe against a target')
    .requiredOption('--target <url>', 'Target endpoint URL')
    .requiredOption('--probe-id <id>', 'Probe ID (e.g., GA-001)')
    .option('--api-key <key>', 'API key for authentication')
    .option('--model <model>', 'Model name for requests', 'default')
    .option('--adapter-type <type>', 'Adapter type', 'openai')
    .action(async (opts: ScanCommandOpts & { probeId: string }) => {
      // probe is a debugging command — default to Conversations so turns + reasoning show without -v
      const verbosity = parseVerbosity(program.opts().verbose);
      const logger = new Logger(Math.max(verbosity, Verbosity.Conversations) as Verbosity);
      const observer = new StreamingObserver();
      const adapter = createAdapter(buildAdapterConfig(opts));

      const probes = await loadProbes();
      const template = probes.find((p) => p.id === opts.probeId);
      if (!template) {
        console.error(`Probe ${opts.probeId} not found`);
        process.exit(1);
      }

      logger.info(`\n${template.id}: ${template.name}`);
      logger.info(`Severity: ${colorSeverity(template.severity)} | Category: ${template.category}`);
      logger.info('');

      const totalTurns = template.turns.filter((t) => t.role === 'user').length;
      logger.probeStart(template.id, template.name, totalTurns);

      let finding;
      try {
        finding = await executeProbe(template, adapter, {
          observer,
          ...logger.buildProbeCallbacks(),
        });
      } catch (err: unknown) {
        finding = errorFinding(template, sanitizeErrorMessage(err));
      } finally {
        await adapter.close?.();
      }

      logger.leakageSignals(finding.leakageSignals);
      logger.finding(finding, 1, 1);
    });
}
