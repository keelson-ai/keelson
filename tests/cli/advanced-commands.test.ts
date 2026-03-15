import { Command } from 'commander';
import { describe, expect, it } from 'vitest';

import { registerAdvancedCommands } from '../../src/cli/advanced-commands.js';

describe('registerAdvancedCommands', () => {
  it('registers campaign, evolve, chain, generate, and erode commands', () => {
    const program = new Command();
    registerAdvancedCommands(program);

    const commandNames = program.commands.map((c) => c.name());
    expect(commandNames).toContain('campaign');
    expect(commandNames).toContain('evolve');
    expect(commandNames).toContain('chain');
    expect(commandNames).toContain('generate');
    expect(commandNames).toContain('erode');
  });

  it('registers exactly 5 commands', () => {
    const program = new Command();
    registerAdvancedCommands(program);

    expect(program.commands).toHaveLength(5);
  });

  it('campaign command accepts a config-path argument', () => {
    const program = new Command();
    registerAdvancedCommands(program);

    const campaignCmd = program.commands.find((c) => c.name() === 'campaign') as Command;
    expect(campaignCmd).toBeDefined();

    // Commander stores arguments in _args
    const args = (campaignCmd as unknown as { _args: Array<{ _name: string }> })._args;
    expect(args).toHaveLength(1);
    expect(args[0]._name).toBe('config-path');
  });

  it('evolve command has required --target and --probe-id options', () => {
    const program = new Command();
    registerAdvancedCommands(program);

    const evolveCmd = program.commands.find((c) => c.name() === 'evolve') as Command;
    expect(evolveCmd).toBeDefined();

    const targetOpt = evolveCmd.options.find((o) => o.long === '--target');
    const probeIdOpt = evolveCmd.options.find((o) => o.long === '--probe-id');
    expect(targetOpt).toBeDefined();
    expect((targetOpt as typeof targetOpt & { required: boolean }).required).toBe(true);
    expect(probeIdOpt).toBeDefined();
    expect((probeIdOpt as typeof probeIdOpt & { required: boolean }).required).toBe(true);
  });

  it('evolve command has mutation-related options', () => {
    const program = new Command();
    registerAdvancedCommands(program);

    const evolveCmd = program.commands.find((c) => c.name() === 'evolve') as Command;
    expect(evolveCmd).toBeDefined();

    const optionLongs = evolveCmd.options.map((o) => o.long);
    expect(optionLongs).toContain('--mutations');
    expect(optionLongs).toContain('--prober-url');
    expect(optionLongs).toContain('--prober-key');
    expect(optionLongs).toContain('--adapter-type');
  });

  it('chain command has required --target and --probe-id options', () => {
    const program = new Command();
    registerAdvancedCommands(program);

    const chainCmd = program.commands.find((c) => c.name() === 'chain') as Command;
    expect(chainCmd).toBeDefined();

    const targetOpt = chainCmd.options.find((o) => o.long === '--target');
    const probeIdOpt = chainCmd.options.find((o) => o.long === '--probe-id');
    expect(targetOpt).toBeDefined();
    expect((targetOpt as typeof targetOpt & { required: boolean }).required).toBe(true);
    expect(probeIdOpt).toBeDefined();
    expect((probeIdOpt as typeof probeIdOpt & { required: boolean }).required).toBe(true);
  });

  it('chain command has strategy option with pair default', () => {
    const program = new Command();
    registerAdvancedCommands(program);

    const chainCmd = program.commands.find((c) => c.name() === 'chain') as Command;
    expect(chainCmd).toBeDefined();

    const strategyOpt = chainCmd.options.find((o) => o.long === '--strategy');
    expect(strategyOpt).toBeDefined();
    expect(strategyOpt!.defaultValue).toBe('pair');
  });

  it('generate command has required --prober-url option', () => {
    const program = new Command();
    registerAdvancedCommands(program);

    const genCmd = program.commands.find((c) => c.name() === 'generate') as Command;
    expect(genCmd).toBeDefined();

    const proberUrlOpt = genCmd.options.find((o) => o.long === '--prober-url');
    expect(proberUrlOpt).toBeDefined();
    expect((proberUrlOpt as typeof proberUrlOpt & { required: boolean }).required).toBe(true);
  });

  it('generate command has count option with default 3', () => {
    const program = new Command();
    registerAdvancedCommands(program);

    const genCmd = program.commands.find((c) => c.name() === 'generate') as Command;
    expect(genCmd).toBeDefined();

    const countOpt = genCmd.options.find((o) => o.long === '--count');
    expect(countOpt).toBeDefined();
    expect(countOpt!.defaultValue).toBe('3');
  });

  it('campaign command has expected options', () => {
    const program = new Command();
    registerAdvancedCommands(program);

    const campaignCmd = program.commands.find((c) => c.name() === 'campaign') as Command;
    expect(campaignCmd).toBeDefined();

    const optionLongs = campaignCmd.options.map((o) => o.long);
    expect(optionLongs).toContain('--output');
    expect(optionLongs).toContain('--format');
    expect(optionLongs).toContain('--adapter-type');
    expect(optionLongs).toContain('--api-key');
    expect(optionLongs).toContain('--model');
    expect(optionLongs).toContain('--fail-on-vuln');
    expect(optionLongs).toContain('--fail-threshold');
  });
});
