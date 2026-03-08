#!/usr/bin/env node
import { Command } from 'commander';

const program = new Command().name('keelson').description('AI agent security scanner').version('0.5.0');

program
  .command('scan')
  .description('Run security scan against a target')
  .action(() => {
    console.log('scan: not yet implemented');
  });

program
  .command('probe')
  .description('Run a single probe against a target')
  .action(() => {
    console.log('probe: not yet implemented');
  });

program
  .command('report')
  .description('Generate report from scan results')
  .action(() => {
    console.log('report: not yet implemented');
  });

program
  .command('list')
  .description('List available probes')
  .action(() => {
    console.log('list: not yet implemented');
  });

program
  .command('validate')
  .description('Validate probe YAML files')
  .action(() => {
    console.log('validate: not yet implemented');
  });

program.parse();
