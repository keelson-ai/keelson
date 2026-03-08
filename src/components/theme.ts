import { Severity, Verdict } from '../types/index.js';

export const VERDICT_ICON: Record<Verdict, { symbol: string; color: string }> = {
  [Verdict.Vulnerable]: { symbol: '\u2717', color: 'red' },
  [Verdict.Safe]: { symbol: '\u2713', color: 'green' },
  [Verdict.Inconclusive]: { symbol: '?', color: 'yellow' },
};

export const SEVERITY_COLOR: Record<Severity, string> = {
  [Severity.Critical]: 'redBright',
  [Severity.High]: 'red',
  [Severity.Medium]: 'yellow',
  [Severity.Low]: 'gray',
};

export const SEVERITY_ORDER: Record<Severity, number> = {
  [Severity.Critical]: 0,
  [Severity.High]: 1,
  [Severity.Medium]: 2,
  [Severity.Low]: 3,
};

export function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen) + '...';
}
