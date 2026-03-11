import { SEVERITY_ORDER } from './types/index.js';

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function compareBySeverity(a: { severity: string }, b: { severity: string }): number {
  return (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
}

export function groupBy<T>(items: T[], keyFn: (item: T) => string): Map<string, T[]> {
  const map = new Map<string, T[]>();
  for (const item of items) {
    const key = keyFn(item);
    const list = map.get(key) ?? [];
    list.push(item);
    map.set(key, list);
  }
  return map;
}

/** Extract a human-readable error message from an unknown catch value. */
export function getErrorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Extract the constructor name (error type) from an unknown catch value. */
export function getErrorName(err: unknown): string {
  return err instanceof Error ? err.constructor.name : 'UnknownError';
}

/** Extract the YYYY-MM-DD date portion from an ISO 8601 timestamp. */
export function extractDate(isoString: string): string {
  return isoString.slice(0, 10);
}

/** Truncate a string to maxLen characters, appending '...' if truncated. */
export function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen) + '...';
}
