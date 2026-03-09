import { Command } from 'commander';
import { describe, expect, it } from 'vitest';

import { registerAdvancedCommands } from '../../src/cli/advanced-commands.js';

describe('registerAdvancedCommands', () => {
  it('registers campaign, evolve, chain, test-crew, test-chain, and generate commands', () => {
    const program = new Command();
    registerAdvancedCommands(program);

    const commandNames = program.commands.map((c) => c.name());
    expect(commandNames).toContain('campaign');
    expect(commandNames).toContain('evolve');
    expect(commandNames).toContain('chain');
    expect(commandNames).toContain('test-crew');
    expect(commandNames).toContain('test-chain');
    expect(commandNames).toContain('generate');
  });

  it('registers exactly 6 commands', () => {
    const program = new Command();
    registerAdvancedCommands(program);

    expect(program.commands).toHaveLength(6);
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

  it('test-crew command has required --target option', () => {
    const program = new Command();
    registerAdvancedCommands(program);

    const crewCmd = program.commands.find((c) => c.name() === 'test-crew') as Command;
    expect(crewCmd).toBeDefined();

    const targetOpt = crewCmd.options.find((o) => o.long === '--target');
    expect(targetOpt).toBeDefined();
    expect((targetOpt as typeof targetOpt & { required: boolean }).required).toBe(true);
  });

  it('test-crew command defaults adapter-type to crewai', () => {
    const program = new Command();
    registerAdvancedCommands(program);

    const crewCmd = program.commands.find((c) => c.name() === 'test-crew') as Command;
    expect(crewCmd).toBeDefined();

    const adapterOpt = crewCmd.options.find((o) => o.long === '--adapter-type');
    expect(adapterOpt).toBeDefined();
    expect(adapterOpt!.defaultValue).toBe('crewai');
  });

  it('test-chain command has required --target option', () => {
    const program = new Command();
    registerAdvancedCommands(program);

    const chainCmd = program.commands.find((c) => c.name() === 'test-chain') as Command;
    expect(chainCmd).toBeDefined();

    const targetOpt = chainCmd.options.find((o) => o.long === '--target');
    expect(targetOpt).toBeDefined();
    expect((targetOpt as typeof targetOpt & { required: boolean }).required).toBe(true);
  });

  it('test-chain command has input-key and output-key options', () => {
    const program = new Command();
    registerAdvancedCommands(program);

    const chainCmd = program.commands.find((c) => c.name() === 'test-chain') as Command;
    expect(chainCmd).toBeDefined();

    const inputKeyOpt = chainCmd.options.find((o) => o.long === '--input-key');
    const outputKeyOpt = chainCmd.options.find((o) => o.long === '--output-key');
    expect(inputKeyOpt).toBeDefined();
    expect(inputKeyOpt!.defaultValue).toBe('input');
    expect(outputKeyOpt).toBeDefined();
    expect(outputKeyOpt!.defaultValue).toBe('output');
  });

  it('test-chain command defaults adapter-type to langchain', () => {
    const program = new Command();
    registerAdvancedCommands(program);

    const chainCmd = program.commands.find((c) => c.name() === 'test-chain') as Command;
    expect(chainCmd).toBeDefined();

    const adapterOpt = chainCmd.options.find((o) => o.long === '--adapter-type');
    expect(adapterOpt).toBeDefined();
    expect(adapterOpt!.defaultValue).toBe('langchain');
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
