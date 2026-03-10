#!/usr/bin/env node
import { Command } from 'commander';

import { registerAdvancedCommands } from './advanced-commands.js';
import { registerOpsCommands } from './ops-commands.js';
import { registerScanCommands } from './scan-commands.js';

function increaseVerbosity(_dummyValue: string, previous: number): number {
  return previous + 1;
}

const program = new Command()
  .name('keelson')
  .description('AI Agent Security Scanner')
  .version('1.0.0')
  .option('-v, --verbose', 'Increase verbosity (-v, -vv, -vvv, -vvvv)', increaseVerbosity, 0);

registerScanCommands(program);
registerOpsCommands(program);
registerAdvancedCommands(program);

program.parse();
