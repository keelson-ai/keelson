import { readFile, readdir } from 'node:fs/promises';
import { dirname, extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import nunjucks from 'nunjucks';
import { parse as parseYaml } from 'yaml';

import { parseProbe } from '../schemas/probe.js';
import type { ProbeTemplate } from '../types/index.js';
import { getErrorMessage } from '../utils.js';

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

const nunjucksEnv = nunjucks.configure({ autoescape: false });

/**
 * Render template variables in probe turn content using nunjucks.
 * If no variables are provided or the object is empty, returns the probe as-is.
 */
export function renderProbe(probe: ProbeTemplate, vars?: Record<string, string>): ProbeTemplate {
  if (!vars || Object.keys(vars).length === 0) return probe;
  return {
    ...probe,
    turns: probe.turns.map((turn) => ({
      ...turn,
      content: nunjucksEnv.renderString(turn.content, vars),
    })),
  };
}

export async function loadProbes(dir?: string, vars?: Record<string, string>): Promise<ProbeTemplate[]> {
  const probesDir = dir ?? join(packageRoot, 'probes');
  const yamlFiles = await findYamlFiles(probesDir);
  const probes: ProbeTemplate[] = [];

  for (const filePath of yamlFiles) {
    const probe = await loadProbe(filePath);
    probes.push(vars ? renderProbe(probe, vars) : probe);
  }

  return probes;
}

export async function loadProbe(filePath: string): Promise<ProbeTemplate> {
  const content = await readFile(filePath, 'utf-8');
  const raw = parseYaml(content);

  try {
    return parseProbe(raw, filePath);
  } catch (error) {
    throw new Error(`Invalid probe at ${filePath}: ${getErrorMessage(error)}`, { cause: error });
  }
}

async function findYamlFiles(dir: string): Promise<string[]> {
  const results: string[] = [];
  const entries = await readdir(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      const nested = await findYamlFiles(fullPath);
      results.push(...nested);
    } else if (extname(entry.name) === '.yaml' || extname(entry.name) === '.yml') {
      results.push(fullPath);
    }
  }

  return results.sort();
}
