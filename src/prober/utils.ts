const DEFAULT_DELAY_MS = 1500;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

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
