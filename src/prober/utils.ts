export { REFUSAL_PHRASES } from '../core/detection.js';
import { sleep } from '../utils.js';

// ─── ContinueIf Keyword Matching ───────────────────────

const CONTINUE_IF_STOP_WORDS = new Set([
  'response',
  'mentions',
  'contains',
  'shows',
  'includes',
  'that',
  'with',
  'from',
  'this',
  'does',
  'have',
  'been',
  'will',
  'should',
  'would',
  'could',
  'about',
  'their',
  'which',
  'there',
  'other',
]);

/**
 * Extract meaningful keywords from a continueIf description and check
 * whether the response contains at least one of them.
 *
 * Words shorter than 4 characters and common stop words are excluded
 * so that natural-language descriptions like "response mentions files
 * or directories" are parsed into keywords ['files', 'directories'].
 */
export function matchesContinueIf(response: string, continueIf: string): boolean {
  const lower = response.toLowerCase();
  const keywords = continueIf
    .toLowerCase()
    .split(/\s+/)
    .filter((w) => w.length > 3 && !CONTINUE_IF_STOP_WORDS.has(w));

  if (keywords.length === 0) {
    // Fallback: if no keywords extracted, do literal substring match
    return lower.includes(continueIf.toLowerCase());
  }

  return keywords.some((kw) => lower.includes(kw));
}

const DEFAULT_DELAY_MS = 1500;

/**
 * Run a list of probes sequentially with an optional delay between each.
 * Shared by discovery, infrastructure, and chain execution.
 */
export async function runProbesSequentially<T, R>(
  probes: T[],
  execute: (probe: T) => Promise<R>,
  options?: { delayMs?: number },
): Promise<R[]> {
  const delayMs = options?.delayMs ?? DEFAULT_DELAY_MS;
  const results: R[] = [];

  for (let i = 0; i < probes.length; i++) {
    const result = await execute(probes[i]);
    results.push(result);

    if (i < probes.length - 1 && delayMs > 0) {
      await sleep(delayMs);
    }
  }

  return results;
}
