import { Severity } from '../types/index.js';

/** Severity sort order: Critical first, Low last. */
export const SEVERITY_ORDER: Record<string, number> = {
  [Severity.Critical]: 0,
  [Severity.High]: 1,
  [Severity.Medium]: 2,
  [Severity.Low]: 3,
};
