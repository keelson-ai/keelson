import { SEVERITY_ORDER } from './types/index.js';

export function compareBySeverity(a: { severity: string }, b: { severity: string }): number {
  return (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
}
