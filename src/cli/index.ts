#!/usr/bin/env node
import { Command } from 'commander';

import { registerOpsCommands } from './ops-commands.js';
import { registerScanCommands } from './scan-commands.js';

const program = new Command().name('keelson').description('AI Agent Security Scanner').version('0.5.0');

registerScanCommands(program);
registerOpsCommands(program);

program.parse();
