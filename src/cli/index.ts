#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Command } from 'commander';

import { registerOpsCommands } from './ops-commands.js';
import { registerScanCommands } from './scan-commands.js';

const cliDir = dirname(fileURLToPath(import.meta.url));

async function getVersion(): Promise<string> {
  try {
    const pkgPath = join(cliDir, '..', '..', 'package.json');
    const pkg = JSON.parse(await readFile(pkgPath, 'utf-8')) as { version: string };
    return pkg.version;
  } catch {
    return '0.0.0';
  }
}

const version = await getVersion();

const program = new Command().name('keelson').description('AI Agent Security Scanner').version(version);

registerScanCommands(program);
registerOpsCommands(program);

program.parse();
