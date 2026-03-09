import { Command } from 'commander';
import { describe, expect, it } from 'vitest';

import { registerScanCommands } from '../../src/cli/scan-commands.js';

describe('registerScanCommands', () => {
  it('registers scan, smart-scan, convergence-scan, and probe commands', () => {
    const program = new Command();
    registerScanCommands(program);

    const commandNames = program.commands.map((c) => c.name());
    expect(commandNames).toContain('scan');
    expect(commandNames).toContain('smart-scan');
    expect(commandNames).toContain('convergence-scan');
    expect(commandNames).toContain('probe');
    expect(commandNames).not.toContain('test');
  });

  it('scan command has required --target option', () => {
    const program = new Command();
    registerScanCommands(program);

    const scanCmd = program.commands.find((c) => c.name() === 'scan') as Command;
    expect(scanCmd).toBeDefined();

    const targetOpt = scanCmd.options.find((o) => o.long === '--target');
    expect(targetOpt).toBeDefined();
    expect((targetOpt as typeof targetOpt & { required: boolean }).required).toBe(true);
  });

  it('scan command has expected options', () => {
    const program = new Command();
    registerScanCommands(program);

    const scanCmd = program.commands.find((c) => c.name() === 'scan') as Command;
    expect(scanCmd).toBeDefined();

    const optionLongs = scanCmd.options.map((o) => o.long);
    expect(optionLongs).toContain('--api-key');
    expect(optionLongs).toContain('--model');
    expect(optionLongs).toContain('--category');
    expect(optionLongs).toContain('--delay');
    expect(optionLongs).toContain('--output-dir');
    expect(optionLongs).toContain('--no-store');
    expect(optionLongs).toContain('--format');
    expect(optionLongs).toContain('--adapter-type');
    expect(optionLongs).toContain('--fail-on-vuln');
    expect(optionLongs).toContain('--fail-threshold');
    expect(optionLongs).toContain('--concurrency');
  });

  it('probe command has required --target and --probe-id options', () => {
    const program = new Command();
    registerScanCommands(program);

    const probeCmd = program.commands.find((c) => c.name() === 'probe') as Command;
    expect(probeCmd).toBeDefined();

    const targetOpt = probeCmd.options.find((o) => o.long === '--target');
    const probeIdOpt = probeCmd.options.find((o) => o.long === '--probe-id');
    expect(targetOpt).toBeDefined();
    expect((targetOpt as typeof targetOpt & { required: boolean }).required).toBe(true);
    expect(probeIdOpt).toBeDefined();
    expect((probeIdOpt as typeof probeIdOpt & { required: boolean }).required).toBe(true);
  });

  it('smart-scan command has required --target option', () => {
    const program = new Command();
    registerScanCommands(program);

    const smartCmd = program.commands.find((c) => c.name() === 'smart-scan') as Command;
    expect(smartCmd).toBeDefined();

    const targetOpt = smartCmd.options.find((o) => o.long === '--target');
    expect(targetOpt).toBeDefined();
    expect((targetOpt as typeof targetOpt & { required: boolean }).required).toBe(true);
  });

  it('convergence-scan command has max-passes option', () => {
    const program = new Command();
    registerScanCommands(program);

    const convCmd = program.commands.find((c) => c.name() === 'convergence-scan') as Command;
    expect(convCmd).toBeDefined();

    const maxPassesOpt = convCmd.options.find((o) => o.long === '--max-passes');
    expect(maxPassesOpt).toBeDefined();
  });
});
