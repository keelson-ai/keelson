import { Command } from 'commander';
import { describe, expect, it } from 'vitest';

import { registerScanCommands } from '../../src/cli/scan-commands.js';

describe('registerScanCommands', () => {
  it('registers scan, recon, and probe commands', () => {
    const program = new Command();
    registerScanCommands(program);

    const commandNames = program.commands.map((c) => c.name());
    expect(commandNames).toContain('scan');
    expect(commandNames).toContain('recon');
    expect(commandNames).toContain('probe');
    expect(commandNames).not.toContain('smart-scan');
    expect(commandNames).not.toContain('convergence-scan');
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

  it('scan command has --max-passes option with default 1', () => {
    const program = new Command();
    registerScanCommands(program);

    const scanCmd = program.commands.find((c) => c.name() === 'scan') as Command;
    const passesOpt = scanCmd.options.find((o) => o.long === '--max-passes');
    expect(passesOpt).toBeDefined();
    expect(passesOpt!.defaultValue).toBe('1');
  });

  it('scan command has --smart flag', () => {
    const program = new Command();
    registerScanCommands(program);

    const scanCmd = program.commands.find((c) => c.name() === 'scan') as Command;
    const smartOpt = scanCmd.options.find((o) => o.long === '--smart');
    expect(smartOpt).toBeDefined();
  });
});
