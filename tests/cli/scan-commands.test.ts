import { Command } from 'commander';
import { describe, expect, it } from 'vitest';

import { registerScanCommands } from '../../src/cli/scan-commands.js';

describe('registerScanCommands', () => {
  function setup(): Command {
    const program = new Command();
    registerScanCommands(program);
    return program;
  }

  it('registers scan, smart-scan, convergence-scan, test, and probe commands', () => {
    const program = setup();
    const commandNames = program.commands.map((c) => c.name());
    expect(commandNames).toContain('scan');
    expect(commandNames).toContain('smart-scan');
    expect(commandNames).toContain('convergence-scan');
    expect(commandNames).toContain('test');
    expect(commandNames).toContain('probe');
  });

  it('scan command has required --target option', () => {
    const program = setup();
    const scanCmd = program.commands.find((c) => c.name() === 'scan');
    expect(scanCmd).toBeDefined();

    const targetOpt = scanCmd!.options.find((o) => o.long === '--target');
    expect(targetOpt).toBeDefined();
    expect(targetOpt!.required).toBe(true);
  });

  it('scan command has expected options', () => {
    const program = setup();
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

  it('smart-scan command shares common scan options', () => {
    const program = setup();
    const smartCmd = program.commands.find((c) => c.name() === 'smart-scan');
    expect(smartCmd).toBeDefined();

    const optionLongs = smartCmd!.options.map((o) => o.long);
    expect(optionLongs).toContain('--target');
    expect(optionLongs).toContain('--api-key');
    expect(optionLongs).toContain('--delay');
    expect(optionLongs).toContain('--output');
    expect(optionLongs).toContain('--format');
    expect(optionLongs).toContain('--fail-on-vuln');
    expect(optionLongs).toContain('--fail-threshold');
  });

  it('convergence-scan command has max-passes option', () => {
    const program = setup();
    const convCmd = program.commands.find((c) => c.name() === 'convergence-scan');
    expect(convCmd).toBeDefined();

    const maxPassesOpt = convCmd!.options.find((o) => o.long === '--max-passes');
    expect(maxPassesOpt).toBeDefined();
  });

  it('test command has required --target and --probe-id options', () => {
    const program = setup();
    const testCmd = program.commands.find((c) => c.name() === 'test');
    expect(testCmd).toBeDefined();

    const targetOpt = testCmd!.options.find((o) => o.long === '--target');
    const probeIdOpt = testCmd!.options.find((o) => o.long === '--probe-id');
    expect(targetOpt).toBeDefined();
    expect(targetOpt!.required).toBe(true);
    expect(probeIdOpt).toBeDefined();
    expect(probeIdOpt!.required).toBe(true);
  });

  it('probe command mirrors test command options', () => {
    const program = setup();
    const testCmd = program.commands.find((c) => c.name() === 'test');
    const probeCmd = program.commands.find((c) => c.name() === 'probe');
    expect(testCmd).toBeDefined();
    expect(probeCmd).toBeDefined();

    const testOptLongs = testCmd!.options.map((o) => o.long).sort();
    const probeOptLongs = probeCmd!.options.map((o) => o.long).sort();
    expect(probeOptLongs).toEqual(testOptLongs);
  });
});
