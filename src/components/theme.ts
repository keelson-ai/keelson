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
