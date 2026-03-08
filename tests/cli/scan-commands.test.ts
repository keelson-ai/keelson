import { describe, expect, it, vi } from 'vitest';
import { Command } from 'commander';

import { registerScanCommands } from '../../src/cli/scan-commands.js';

describe('registerScanCommands', () => {
  it('registers scan, smart-scan, convergence-scan, test, and probe commands', () => {
    const program = new Command();
    registerScanCommands(program);

    const commandNames = program.commands.map((c) => c.name());
    expect(commandNames).toContain('scan');
    expect(commandNames).toContain('smart-scan');
    expect(commandNames).toContain('convergence-scan');
    expect(commandNames).toContain('test');
    expect(commandNames).toContain('probe');
  });

  it('scan command has required --target option', () => {
    const program = new Command();
    registerScanCommands(program);

    const scanCmd = program.commands.find((c) => c.name() === 'scan');
    expect(scanCmd).toBeDefined();

    const targetOpt = scanCmd!.options.find((o) => o.long === '--target');
    expect(targetOpt).toBeDefined();
    expect(targetOpt!.required).toBe(true);
  });

  it('scan command has expected options', () => {
    const program = new Command();
    registerScanCommands(program);

    const scanCmd = program.commands.find((c) => c.name() === 'scan');
    expect(scanCmd).toBeDefined();

    const optionLongs = scanCmd!.options.map((o) => o.long);
    expect(optionLongs).toContain('--api-key');
    expect(optionLongs).toContain('--model');
    expect(optionLongs).toContain('--category');
    expect(optionLongs).toContain('--delay');
    expect(optionLongs).toContain('--output');
    expect(optionLongs).toContain('--format');
    expect(optionLongs).toContain('--adapter-type');
    expect(optionLongs).toContain('--fail-on-vuln');
    expect(optionLongs).toContain('--fail-threshold');
    expect(optionLongs).toContain('--concurrency');
  });

  it('test command has required --target and --probe-id options', () => {
    const program = new Command();
    registerScanCommands(program);

    const testCmd = program.commands.find((c) => c.name() === 'test');
    expect(testCmd).toBeDefined();

    const targetOpt = testCmd!.options.find((o) => o.long === '--target');
    const probeIdOpt = testCmd!.options.find((o) => o.long === '--probe-id');
    expect(targetOpt).toBeDefined();
    expect(targetOpt!.required).toBe(true);
    expect(probeIdOpt).toBeDefined();
    expect(probeIdOpt!.required).toBe(true);
  });

  it('smart-scan command has required --target option', () => {
    const program = new Command();
    registerScanCommands(program);

    const smartCmd = program.commands.find((c) => c.name() === 'smart-scan');
    expect(smartCmd).toBeDefined();

    const targetOpt = smartCmd!.options.find((o) => o.long === '--target');
    expect(targetOpt).toBeDefined();
    expect(targetOpt!.required).toBe(true);
  });

  it('convergence-scan command has max-passes option', () => {
    const program = new Command();
    registerScanCommands(program);

    const convCmd = program.commands.find(
      (c) => c.name() === 'convergence-scan',
    );
    expect(convCmd).toBeDefined();

    const maxPassesOpt = convCmd!.options.find(
      (o) => o.long === '--max-passes',
    );
    expect(maxPassesOpt).toBeDefined();
  });
});
