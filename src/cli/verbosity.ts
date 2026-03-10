export enum Verbosity {
  Silent = 0,        // default: one-line verdict
  Verdicts = 1,      // -v: verdict + reasoning + timing
  Conversations = 2, // -vv: real-time conversation per turn
  Detection = 3,     // -vvv: real-time + detection breakdown
  Debug = 4,         // -vvvv: raw HTTP, session state, keyword matches
}

/**
 * Parse the raw value Commander gives us for the -v option.
 * Commander increments a counter for repeated boolean flags.
 */
export function parseVerbosity(raw: unknown): Verbosity {
  if (raw === undefined || raw === false) return Verbosity.Silent;
  if (raw === true) return Verbosity.Verdicts;
  const n = typeof raw === 'number' ? raw : parseInt(String(raw), 10);
  if (isNaN(n) || n <= 0) return Verbosity.Silent;
  return Math.min(n, Verbosity.Debug) as Verbosity;
}
