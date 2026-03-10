import chalk from 'chalk';

import type { PatternDetails } from '../core/detection.js';
import type { DetectionResult, Finding, LeakageSignal, Verdict } from '../types/index.js';

export type { PatternDetails } from '../core/detection.js';

export enum Verbosity {
  Silent = 0, // default: one-line verdict
  Verdicts = 1, // -v: verdict + reasoning + timing
  Conversations = 2, // -vv: real-time conversation per turn
  Detection = 3, // -vvv: real-time + detection breakdown
  Debug = 4, // -vvvv: raw HTTP, session state, keyword matches
}

/**
 * Parse the raw value Commander gives us for the -v option.
 * Commander increments a counter for repeated boolean flags.
 */
export function parseVerbosity(raw: unknown): Verbosity {
  if (raw === undefined || raw === false) return Verbosity.Silent;
  if (raw === true) return Verbosity.Verdicts;
  const n = typeof raw === 'number' ? raw : parseInt(String(raw), 10);
  if (isNaN(n) || n <= 0) return Verbosity.Silent;
  return Math.min(n, Verbosity.Debug) as Verbosity;
}

// ─── Logger ─────────────────────────────────────────────

const VERDICT_ICON: Record<string, string> = {
  VULNERABLE: chalk.red('✗'),
  SAFE: chalk.green('✓'),
  INCONCLUSIVE: chalk.yellow('?'),
};

function verdictIcon(v: Verdict): string {
  return VERDICT_ICON[v] ?? v;
}

function write(msg: string): void {
  process.stderr.write(msg);
}

export class Logger {
  constructor(private readonly level: Verbosity) {}

  finding(f: Finding, current: number, total: number): void {
    write(`  ${verdictIcon(f.verdict)} [${f.probeId}] ${f.probeName} (${current}/${total})\n`);
    if (this.level >= Verbosity.Verdicts) {
      const pct = Math.round(f.confidence * 100);
      write(chalk.dim(`    confidence: ${pct}% | method: ${f.scoringMethod}\n`));
      write(chalk.dim(`    reasoning: ${f.reasoning}\n`));
    }
  }

  turn(userTurnIndex: number, totalTurns: number, prompt: string, response: string, timeMs: number): void {
    if (this.level < Verbosity.Conversations) return;
    write(chalk.dim(`  ── turn ${userTurnIndex + 1}/${totalTurns} (${timeMs}ms) ──\n`));
    write(chalk.cyan('  → ') + prompt + '\n');
    write(chalk.magenta('  ← ') + response + '\n');
  }

  probeStart(probeId: string, probeName: string, totalTurns: number): void {
    if (this.level < Verbosity.Conversations) return;
    write(
      chalk.bold(`\n▶ ${probeId} — ${probeName}`) +
        chalk.dim(` (${totalTurns} turn${totalTurns === 1 ? '' : 's'})`) +
        '\n',
    );
  }

  turnSignal(message: string): void {
    if (this.level < Verbosity.Detection) return;
    write(`  ⚡ ${message}\n`);
  }

  detection(result: DetectionResult, details: PatternDetails): void {
    if (this.level < Verbosity.Detection) return;
    write(chalk.dim('  ── pattern detection ──\n'));
    write(chalk.dim(`    verdict: ${result.verdict} | confidence: ${Math.round(result.confidence * 100)}%\n`));
    write(chalk.dim(`    vulnMatched: ${details.vulnMatched} | safeMatched: ${details.safeMatched}\n`));
    write(chalk.dim(`    hasRefusal: ${details.hasRefusal} | sideEffect: ${details.sideEffect ?? 'none'}\n`));
  }

  judgeResult(result: DetectionResult): void {
    if (this.level < Verbosity.Detection) return;
    write(chalk.dim('  ── llm judge ──\n'));
    write(chalk.dim(`    verdict: ${result.verdict} | confidence: ${Math.round(result.confidence * 100)}%\n`));
    write(chalk.dim(`    reasoning: ${result.reasoning}\n`));
  }

  combinedResult(result: DetectionResult): void {
    if (this.level < Verbosity.Detection) return;
    write(chalk.dim('  ── combined result ──\n'));
    write(chalk.dim(`    verdict: ${result.verdict} | confidence: ${Math.round(result.confidence * 100)}%\n`));
    write(chalk.dim(`    reasoning: ${result.reasoning}\n`));
  }

  leakageSignals(signals: LeakageSignal[]): void {
    if (this.level < Verbosity.Detection || signals.length === 0) return;
    write(chalk.dim('  ── leakage signals ──\n'));
    for (const s of signals) {
      write(chalk.dim(`    [${s.stepIndex}] ${s.signalType} (${s.severity}) — ${s.description}\n`));
    }
  }

  rawResponse(raw: unknown): void {
    if (this.level < Verbosity.Debug) return;
    write(chalk.dim('  ── raw response ──\n'));
    write(JSON.stringify(raw, null, 2) + '\n');
  }

  /** Always-visible info line (headers, summaries). */
  info(message: string): void {
    write(message + '\n');
  }

  /** Step progress at Conversations level. */
  step(icon: string, message: string): void {
    if (this.level < Verbosity.Conversations) return;
    write(`  ${icon} ${message}\n`);
  }

  debug(message: string): void {
    if (this.level < Verbosity.Debug) return;
    write(chalk.dim(`  [debug] ${message}\n`));
  }

  /** Build a standard set of engine callbacks wired to this logger. */
  buildProbeCallbacks(): {
    onTurnComplete: (info: {
      userTurnIndex: number;
      totalTurns: number;
      prompt: string;
      response: string;
      responseTimeMs: number;
      raw: unknown;
    }) => void;
    onEarlyTermination: (reason: string) => void;
    onDetection: (result: DetectionResult, details: PatternDetails) => void;
    onJudgeResult: (result: DetectionResult) => void;
    onCombinedResult: (result: DetectionResult) => void;
  } {
    return {
      onTurnComplete: (info) => {
        this.turn(info.userTurnIndex, info.totalTurns, info.prompt, info.response, info.responseTimeMs);
        this.rawResponse(info.raw);
      },
      onEarlyTermination: (reason) => this.turnSignal(reason),
      onDetection: (result, details) => this.detection(result, details),
      onJudgeResult: (result) => this.judgeResult(result),
      onCombinedResult: (result) => this.combinedResult(result),
    };
  }
}
