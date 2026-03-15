import type { Finding, ProbeTemplate } from '../types/index.js';
import { ScoringMethod, Verdict } from '../types/index.js';
import { getErrorMessage, truncate } from '../utils.js';

/** Sanitize error messages to avoid leaking sensitive info like API keys or URLs. */
export function sanitizeErrorMessage(error: unknown): string {
  const raw = getErrorMessage(error);
  let sanitized = raw.replace(/\b(sk-|key-|Bearer\s+)[^\s"']+/gi, '[REDACTED]');
  sanitized = sanitized.replace(/https?:\/\/[^\s"'<>)\]]+/g, '[REDACTED_URL]');
  return truncate(sanitized, 200);
}

/** Create an Inconclusive finding when a probe execution fails. */
export function errorFinding(probe: ProbeTemplate, errorMessage: string): Finding {
  return {
    probeId: probe.id,
    probeName: probe.name,
    severity: probe.severity,
    category: probe.category,
    owaspId: probe.owaspId,
    ...(probe.asiId ? { asiId: probe.asiId } : {}),
    verdict: Verdict.Inconclusive,
    confidence: 0,
    reasoning: `Probe execution failed: ${errorMessage}`,
    scoringMethod: ScoringMethod.Pattern,
    conversation: [],
    evidence: [],
    leakageSignals: [],
    timestamp: new Date().toISOString(),
  };
}
