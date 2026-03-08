/**
 * SARIF v2.1.0 output generation from scan results.
 *
 * Produces a SARIF log conforming to the OASIS SARIF v2.1.0 schema,
 * compatible with GitHub Code Scanning, VS Code SARIF Viewer, and other tools.
 */

import type { Finding, ScanResult } from '../types/index.js';
import { Severity, Verdict } from '../types/index.js';

// ─── Interfaces ─────────────────────────────────────────

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: string };
  properties: {
    category: string;
    owasp: string;
    severity: string;
  };
}

export interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  kind: string;
  level: string;
  message: { text: string };
  locations?: Array<{
    physicalLocation: {
      artifactLocation: { uri: string; uriBaseId: string };
    };
  }>;
  properties: {
    verdict: string;
    category: string;
    owasp: string;
    evidence?: Array<{
      stepIndex: number;
      prompt: string;
      response: string;
      responseTimeMs: number;
    }>;
  };
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      semanticVersion: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
  invocations: Array<{
    executionSuccessful: boolean;
    startTimeUtc: string;
    endTimeUtc?: string;
  }>;
  properties?: {
    target: string;
    scanId: string;
  };
}

export interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

// ─── Constants ──────────────────────────────────────────

const SARIF_VERSION = '2.1.0';
const SARIF_SCHEMA =
  'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json';
const TOOL_NAME = 'keelson';
const TOOL_VERSION = '0.5.0';
const TOOL_INFO_URI = 'https://github.com/keelson-ai/keelson';

// ─── Mapping helpers ────────────────────────────────────

function severityToLevel(severity: Severity): string {
  switch (severity) {
    case Severity.Critical:
    case Severity.High:
      return 'error';
    case Severity.Medium:
      return 'warning';
    case Severity.Low:
      return 'note';
  }
}

function verdictToKind(verdict: Verdict): string {
  switch (verdict) {
    case Verdict.Vulnerable:
      return 'fail';
    case Verdict.Safe:
      return 'pass';
    case Verdict.Inconclusive:
      return 'review';
  }
}

function findingToRule(finding: Finding): SarifRule {
  return {
    id: finding.probeId,
    name: finding.probeName.replace(/\s+/g, ''),
    shortDescription: { text: finding.probeName },
    fullDescription: { text: `${finding.probeName} (${finding.owaspId})` },
    defaultConfiguration: { level: severityToLevel(finding.severity) },
    properties: {
      category: finding.category,
      owasp: finding.owaspId,
      severity: finding.severity,
    },
  };
}

function findingToResult(finding: Finding, ruleIndex: number): SarifResult {
  const result: SarifResult = {
    ruleId: finding.probeId,
    ruleIndex,
    kind: verdictToKind(finding.verdict),
    level: finding.verdict === Verdict.Vulnerable ? severityToLevel(finding.severity) : 'none',
    message: {
      text: finding.reasoning || `${finding.probeName}: ${finding.verdict}`,
    },
    properties: {
      verdict: finding.verdict,
      category: finding.category,
      owasp: finding.owaspId,
    },
  };

  if (finding.evidence.length > 0) {
    result.locations = [
      {
        physicalLocation: {
          artifactLocation: {
            uri: finding.probeId,
            uriBaseId: 'PROBES',
          },
        },
      },
    ];
    result.properties.evidence = finding.evidence.map((ev) => ({
      stepIndex: ev.stepIndex,
      prompt: ev.prompt,
      response: ev.response,
      responseTimeMs: ev.responseTimeMs,
    }));
  }

  return result;
}

// ─── Public API ─────────────────────────────────────────

/** Generate a SARIF v2.1.0 log from scan results. */
export function generateSarif(result: ScanResult): SarifLog {
  const seenRules = new Map<string, number>();
  const rules: SarifRule[] = [];
  const results: SarifResult[] = [];

  for (const finding of result.findings) {
    if (!seenRules.has(finding.probeId)) {
      seenRules.set(finding.probeId, rules.length);
      rules.push(findingToRule(finding));
    }
    const ruleIndex = seenRules.get(finding.probeId)!;
    results.push(findingToResult(finding, ruleIndex));
  }

  const run: SarifRun = {
    tool: {
      driver: {
        name: TOOL_NAME,
        semanticVersion: TOOL_VERSION,
        informationUri: TOOL_INFO_URI,
        rules,
      },
    },
    results,
    invocations: [
      {
        executionSuccessful: true,
        startTimeUtc: result.startedAt,
        endTimeUtc: result.completedAt,
      },
    ],
    properties: {
      target: result.target,
      scanId: result.scanId,
    },
  };

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [run],
  };
}
