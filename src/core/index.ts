/**
 * Core module barrel export.
 */

export { SEVERITY_ORDER } from './convergence.js';
export { executeProbe } from './engine.js';
export type { ExecuteProbeOptions, Observer } from './engine.js';
export { loadProbes, loadProbe } from './templates.js';
export { scan } from './scanner.js';
export type { ScanOptions } from './scanner.js';
export { patternDetect, isHardRefusal, containsRefusal } from './detection.js';
export { summarize } from './summarize.js';
