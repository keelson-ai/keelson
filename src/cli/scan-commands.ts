import { readFile } from 'node:fs/promises';

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
import { detectLeakage } from '../core/convergence.js';
import { StreamingObserver, executeProbe, loadProbes, scan } from '../core/index.js';
import { errorFinding, sanitizeErrorMessage } from '../core/scan-helpers.js';
import type { Store } from '../state/index.js';
import { classifyResponse } from '../strategies/branching.js';
import type { Adapter, ScanResult, Turn } from '../types/index.js';
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
  smart?: boolean;
  // SiteGPT-specific
  chatbotId?: string;
  // Browser-specific
  chatInputSelector?: string;
  chatSubmitSelector?: string;
  chatResponseSelector?: string;
  browserHeadless?: boolean;
  // Browser pre-interaction
  browserPreInteraction?: string;
  browserLauncherSelector?: string;
  // LLM Judge
  judgeProvider?: string;
  judgeModel?: string;
  judgeApiKey?: string;
  // Payload size limit
  maxPayloadLength?: string;
  // Engagement profile
  engagement?: string;
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

function setupScan(opts: ScanCommandOpts): { adapter: Adapter; store: Store | null } {
  try {
    return { adapter: createAdapter(buildAdapterConfig(opts)), store: openStore(opts) };
  } catch (err: unknown) {
    console.error(`Setup failed: ${sanitizeErrorMessage(err)}`);
    process.exit(1);
  }
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
    .option(
      '--browser-pre-interaction <js>',
      'JS snippet to run in page before chat interaction (e.g. dismiss cookie banner)',
    )
    .option(
      '--browser-launcher-selector <sel>',
      'CSS selector for chat launcher button (clicked with real mouse events before detection)',
    )
    .option('--judge-provider <type>', 'LLM judge adapter type (e.g., openai, anthropic)')
    .option('--judge-model <model>', 'LLM judge model name')
    .option('--judge-api-key <key>', 'API key for LLM judge')
    .option('--max-payload-length <chars>', 'Skip probes exceeding this character limit')
    .option('--engagement <profile>', 'Engagement profile ID or path (e.g., stealth-cs-bot, aggressive)');
}

// ─── Commands ───────────────────────────────────────────

export function registerScanCommands(program: Command): void {
  addCommonScanOptions(program.command('scan').description('Run a full security scan against an AI agent endpoint'))
    .option('--category <category>', 'Filter by category')
    .option('--concurrency <n>', 'Max concurrent probes', '1')
    .option('--max-passes <n>', 'Max convergence passes (cross-category follow-up on vulns)', '1')
    .option('--smart', 'Adaptive scan: recon, classify, select relevant probes, execute', false)
    .action(async (opts: ScanCommandOpts) => {
      const logger = new Logger(parseVerbosity(program.opts().verbose));
      const observer = new StreamingObserver();
      const { adapter, store } = setupScan(opts);
      const categories = opts.category ? [opts.category] : undefined;
      const delayMs = parseInt(opts.delay ?? '1500', 10);
      const concurrency = parseInt(opts.concurrency ?? '1', 10);
      const judge = buildJudge(opts);
      const maxPayloadLength = opts.maxPayloadLength ? parseInt(opts.maxPayloadLength, 10) : undefined;
      const maxPasses = parseInt(opts.maxPasses ?? '1', 10);

      printHeader(logger, 'Keelson Security Scan', opts, opts.category ? { Category: opts.category } : undefined);

      let result: ScanResult;
      try {
        if (opts.smart) {
          // Smart scan autonomously selects probes — warn about ignored flags
          const ignored: string[] = [];
          if (opts.category) ignored.push('--category');
          if (maxPasses > 1) ignored.push('--max-passes');
          if (concurrency > 1) ignored.push('--concurrency');
          if (ignored.length > 0) {
            logger.info(`Warning: --smart ignores ${ignored.join(', ')} (smart scan selects probes autonomously)`);
          }

          const { runSmartScan } = await import('../core/index.js');
          result = await runSmartScan(opts.target, adapter, {
            delayMs,
            judge,
            observer,
            maxPayloadLength,
            engagement: opts.engagement,
            onFinding: (finding, current, total) => logger.finding(finding, current, total),
            onPhase: (phase, detail) => logger.info(`  [${phase}] ${detail}`),
          });
        } else {
          result = await scan(opts.target, adapter, {
            categories,
            delayMs,
            concurrency,
            reorder: concurrency <= 1,
            observer,
            judge,
            maxPayloadLength,
            engagement: opts.engagement,
            maxPasses,
            onFinding: (finding, current, total) => logger.finding(finding, current, total),
            onPass: maxPasses > 1 ? (passNum, desc) => logger.info(`  [Pass ${passNum}] ${desc}`) : undefined,
          });
        }
      } finally {
        await adapter.close?.();
      }

      await finalizeScan(result, store, opts, logger);
    });

  program
    .command('recon')
    .description('Discover target capabilities and build a profile (no attack probes)')
    .requiredOption('--target <url>', 'Target endpoint URL')
    .option('--api-key <key>', 'API key for authentication')
    .option('--model <model>', 'Model name for requests', 'default')
    .option('--adapter-type <type>', 'Adapter type', 'openai')
    .option('--delay <ms>', 'Milliseconds between discovery probes', '2000')
    .option('--output-dir <dir>', 'Output directory', DEFAULT_OUTPUT_DIR)
    .option('--format <format>', 'Output format: json, markdown', 'json')
    .action(async (opts: ScanCommandOpts) => {
      const logger = new Logger(parseVerbosity(program.opts().verbose));
      const adapter = createAdapter(buildAdapterConfig(opts));

      printHeader(logger, 'Keelson Recon', opts);

      const { runRecon } = await import('../core/index.js');

      let result;
      try {
        result = await runRecon(opts.target, adapter, {
          delayMs: parseInt(opts.delay ?? '2000', 10),
          onPhase: (phase, detail) => logger.info(`  [${phase}] ${detail}`),
        });
      } finally {
        await adapter.close?.();
      }

      // Display results
      const tp = result.targetProfile;
      logger.info('\n--- Target Profile ---');
      logger.info(`Agent types:  ${tp.agentTypes.join(', ') || 'unknown'}`);
      logger.info(`Tools:        ${tp.detectedTools.join(', ') || 'none detected'}`);
      logger.info(`Memory:       ${tp.hasMemory}`);
      logger.info(`Write access: ${tp.hasWriteAccess}`);
      logger.info(`Refusal:      ${tp.refusalStyle}`);

      const detected = result.agentProfile.capabilities.filter((c) => c.detected);
      if (detected.length > 0) {
        logger.info('\n--- Detected Capabilities ---');
        for (const cap of detected) {
          logger.info(`  ${cap.name} (confidence: ${(cap.confidence * 100).toFixed(0)}%)`);
        }
      }

      if (result.infraFindings.length > 0) {
        logger.info('\n--- Infrastructure Findings ---');
        for (const inf of result.infraFindings) {
          logger.info(`  ${colorSeverity(inf.severity)} ${inf.title}`);
        }
      }

      logger.info('\n--- Probe Plan ---');
      logger.info(`Total probes recommended: ${result.probePlan.totalProbes}`);
      for (const cp of result.probePlan.categories) {
        if (cp.probeIds.length > 0) {
          logger.info(`  ${cp.category}: ${cp.probeIds.length} probes (${cp.priority}) — ${cp.rationale}`);
        }
      }

      // Write output
      const { mkdir, writeFile } = await import('node:fs/promises');
      const { join } = await import('node:path');
      const outputDir = opts.outputDir ?? DEFAULT_OUTPUT_DIR;
      await mkdir(outputDir, { recursive: true });

      const format = opts.format ?? 'json';
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);

      if (format === 'json') {
        const filePath = join(outputDir, `recon-${timestamp}.json`);
        await writeFile(filePath, JSON.stringify(result, null, 2));
        logger.info(`\nOutput: ${filePath}`);
      } else {
        const lines: string[] = [
          `# Recon Report — ${result.targetUrl}`,
          '',
          `**Completed**: ${result.completedAt}`,
          '',
          '## Target Profile',
          '',
          `- **Agent types**: ${tp.agentTypes.join(', ') || 'unknown'}`,
          `- **Detected tools**: ${tp.detectedTools.join(', ') || 'none'}`,
          `- **Memory**: ${tp.hasMemory}`,
          `- **Write access**: ${tp.hasWriteAccess}`,
          `- **Refusal style**: ${tp.refusalStyle}`,
          '',
          '## Capabilities',
          '',
        ];
        for (const cap of result.agentProfile.capabilities) {
          const status = cap.detected ? 'detected' : 'not detected';
          lines.push(`- **${cap.name}**: ${status} (${(cap.confidence * 100).toFixed(0)}%)`);
        }
        if (result.infraFindings.length > 0) {
          lines.push('', '## Infrastructure Findings', '');
          for (const inf of result.infraFindings) {
            lines.push(`- **${inf.severity}**: ${inf.title} — ${inf.description}`);
          }
        }
        lines.push('', '## Probe Plan', '', `**Total probes**: ${result.probePlan.totalProbes}`, '');
        lines.push('| Category | Priority | Probes | Rationale |');
        lines.push('|----------|----------|--------|-----------|');
        for (const cp of result.probePlan.categories) {
          if (cp.probeIds.length > 0) {
            lines.push(`| ${cp.category} | ${cp.priority} | ${cp.probeIds.length} | ${cp.rationale} |`);
          }
        }
        lines.push('');
        const filePath = join(outputDir, `recon-${timestamp}.md`);
        await writeFile(filePath, lines.join('\n'));
        logger.info(`\nOutput: ${filePath}`);
      }
    });

  program
    .command('probe')
    .description('Run a single probe against a target')
    .requiredOption('--target <url>', 'Target endpoint URL')
    .requiredOption('--probe-id <id>', 'Probe ID (e.g., GA-001)')
    .option('--api-key <key>', 'API key for authentication')
    .option('--model <model>', 'Model name for requests', 'default')
    .option('--adapter-type <type>', 'Adapter type', 'openai')
    .option('--chatbot-id <id>', 'Chatbot ID (SiteGPT adapter)')
    .option('--chat-input-selector <sel>', 'CSS selector for chat input (browser adapter)')
    .option('--chat-submit-selector <sel>', 'CSS selector for submit button (browser adapter)')
    .option('--chat-response-selector <sel>', 'CSS selector for bot responses (browser adapter)')
    .option('--browser-headless', 'Run browser in headless mode (default: true)', true)
    .option('--no-browser-headless', 'Run browser in headed mode (visible)')
    .option('--browser-pre-interaction <js>', 'JS snippet to run in page before chat interaction')
    .option(
      '--browser-launcher-selector <sel>',
      'CSS selector for chat launcher button (clicked with real mouse events)',
    )
    .action(async (opts: ScanCommandOpts & { probeId: string }) => {
      // probe is a debugging command — default to Conversations so turns + reasoning show without -v
      const verbosity = parseVerbosity(program.opts().verbose);
      const logger = new Logger(Math.max(verbosity, Verbosity.Conversations) as Verbosity);
      const observer = new StreamingObserver();
      const adapter = createAdapter(buildAdapterConfig(opts));

      const probes = await loadProbes();
      const template = probes.find((p) => p.id === opts.probeId);
      if (!template) {
        logger.error(`Probe ${opts.probeId} not found`);
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

  program
    .command('send')
    .description('Send a message through any adapter and return the enriched response')
    .requiredOption('--target <url>', 'Target endpoint URL')
    .requiredOption('--message <text>', 'Message to send')
    .option('--api-key <key>', 'API key for authentication')
    .option('--model <model>', 'Model name for requests', 'default')
    .option('--adapter-type <type>', 'Adapter type', 'openai')
    .option('--history <path>', 'Path to JSON file with conversation history (Turn[])')
    .option('--raw', 'Output plain text response only', false)
    .option('--chatbot-id <id>', 'Chatbot ID (SiteGPT adapter)')
    .option('--chat-input-selector <sel>', 'CSS selector for chat input (browser adapter)')
    .option('--chat-submit-selector <sel>', 'CSS selector for submit button (browser adapter)')
    .option('--chat-response-selector <sel>', 'CSS selector for bot responses (browser adapter)')
    .option('--browser-headless', 'Run browser in headless mode', true)
    .option('--no-browser-headless', 'Run browser in headed mode')
    .option('--browser-pre-interaction <js>', 'JS snippet to run before interaction')
    .option(
      '--browser-launcher-selector <sel>',
      'CSS selector for chat launcher button (clicked with real mouse events before detection)',
    )
    .action(async (opts: ScanCommandOpts & { message: string; history?: string; raw?: boolean }) => {
      const adapter = createAdapter(buildAdapterConfig(opts));

      try {
        const messages: Turn[] = [];

        if (opts.history) {
          let historyJson: string;
          try {
            historyJson = await readFile(opts.history, 'utf-8');
          } catch {
            console.error(`Error: cannot read history file ${opts.history}`);
            process.exit(1);
          }
          let history: Turn[];
          try {
            history = JSON.parse(historyJson) as Turn[];
          } catch (err) {
            console.error(`Error: invalid JSON in history file — ${err instanceof Error ? err.message : err}`);
            process.exit(1);
          }
          messages.push(...history);
        }

        messages.push({ role: 'user', content: opts.message });

        const response = await adapter.send(messages);
        const leakage = detectLeakage(response.content);
        const classification = classifyResponse(response.content);
        const refusalDetected = classification === 'refusal';

        if (opts.raw) {
          console.log(response.content);
        } else {
          console.log(
            JSON.stringify(
              {
                content: response.content,
                latencyMs: response.latencyMs,
                leakage,
                refusalDetected,
                metadata: response.raw ?? {},
              },
              null,
              2,
            ),
          );
        }
      } finally {
        await adapter.close?.();
      }
    });
}
