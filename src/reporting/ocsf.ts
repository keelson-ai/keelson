/**
 * OCSF v1.1 (Open Cybersecurity Schema Framework) output generation.
 *
 * Converts scan results into OCSF Vulnerability Finding events (class_uid 2002).
 * Compatible with CrowdStrike, Splunk, Datadog, and AWS Security Lake.
 */

import type { EvidenceItem, Finding, ScanResult } from '../types/index.js';
import { Severity, Verdict } from '../types/index.js';

// ─── Interfaces ─────────────────────────────────────────

export interface OcsfEvidenceData {
  step_index: number;
  prompt: string;
  response: string;
  response_time_ms?: number;
}

export interface OcsfEvidence {
  data: OcsfEvidenceData;
}

export interface OcsfResource {
  uid: string;
  name: string;
  type: string;
}

export interface OcsfFindingInfo {
  uid: string;
  title: string;
  desc: string;
  types: string[];
  analytic: {
    uid: string;
    name: string;
  };
}

export interface OcsfMetadata {
  version: string;
  product: {
    name: string;
    vendor_name: string;
    version: string;
  };
}

export interface OcsfEvent {
  activity_id: number;
  activity_name: string;
  category_uid: number;
  category_name: string;
  class_uid: number;
  class_name: string;
  type_uid: number;
  time: string;
  severity_id: number;
  severity: string;
  status_id: number;
  status: string;
  confidence_score: number;
  finding_info: OcsfFindingInfo;
  metadata: OcsfMetadata;
  resources: OcsfResource[];
  evidences?: OcsfEvidence[];
}

// ─── Constants ──────────────────────────────────────────

const PRODUCT_NAME = 'Keelson';
const PRODUCT_VENDOR = 'Keelson';
const PRODUCT_VERSION = '0.5.0';

const ACTIVITY_ID_CREATE = 1;
const CATEGORY_UID_FINDINGS = 2;
const CLASS_UID_VULNERABILITY_FINDING = 2002;
const TYPE_UID = CLASS_UID_VULNERABILITY_FINDING * 100 + ACTIVITY_ID_CREATE; // 200201

// ─── Mapping helpers ────────────────────────────────────

const VERDICT_TO_STATUS_ID: Record<Verdict, number> = {
  [Verdict.Vulnerable]: 1,    // New
  [Verdict.Safe]: 4,          // Resolved
  [Verdict.Inconclusive]: 2,  // InProgress
};

const VERDICT_TO_STATUS: Record<Verdict, string> = {
  [Verdict.Vulnerable]: 'New',
  [Verdict.Safe]: 'Resolved',
  [Verdict.Inconclusive]: 'In Progress',
};

const SEVERITY_TO_ID: Record<Severity, number> = {
  [Severity.Critical]: 5,
  [Severity.High]: 4,
  [Severity.Medium]: 3,
  [Severity.Low]: 2,
};

const SEVERITY_TO_LABEL: Record<Severity, string> = {
  [Severity.Critical]: 'Critical',
  [Severity.High]: 'High',
  [Severity.Medium]: 'Medium',
  [Severity.Low]: 'Low',
};

function buildEvidences(evidence: EvidenceItem[]): OcsfEvidence[] {
  return evidence.map((item) => {
    const data: OcsfEvidenceData = {
      step_index: item.stepIndex,
      prompt: item.prompt,
      response: item.response,
    };
    if (item.responseTimeMs) {
      data.response_time_ms = item.responseTimeMs;
    }
    return { data };
  });
}

function buildMetadata(): OcsfMetadata {
  return {
    version: '1.1.0',
    product: {
      name: PRODUCT_NAME,
      vendor_name: PRODUCT_VENDOR,
      version: PRODUCT_VERSION,
    },
  };
}

// ─── Public API ─────────────────────────────────────────

/** Convert a single finding to an OCSF vulnerability finding event. */
export function findingToOcsf(finding: Finding, target: string): OcsfEvent {
  const event: OcsfEvent = {
    activity_id: ACTIVITY_ID_CREATE,
    activity_name: 'Create',
    category_uid: CATEGORY_UID_FINDINGS,
    category_name: 'Findings',
    class_uid: CLASS_UID_VULNERABILITY_FINDING,
    class_name: 'Vulnerability Finding',
    type_uid: TYPE_UID,
    time: finding.timestamp,
    severity_id: SEVERITY_TO_ID[finding.severity],
    severity: SEVERITY_TO_LABEL[finding.severity],
    status_id: VERDICT_TO_STATUS_ID[finding.verdict],
    status: VERDICT_TO_STATUS[finding.verdict],
    confidence_score: Math.round(finding.confidence * 100),
    finding_info: {
      uid: finding.probeId,
      title: finding.probeName,
      desc: finding.reasoning || `${finding.probeName}: ${finding.verdict}`,
      types: [finding.category],
      analytic: {
        uid: finding.owaspId,
        name: finding.owaspId,
      },
    },
    metadata: buildMetadata(),
    resources: [
      {
        uid: target,
        name: target,
        type: 'API Endpoint',
      },
    ],
  };

  if (finding.evidence.length > 0) {
    event.evidences = buildEvidences(finding.evidence);
  }

  return event;
}

/** Convert an entire scan result to a list of OCSF events (one per finding). */
export function generateOcsf(result: ScanResult): OcsfEvent[] {
  return result.findings.map((finding) => findingToOcsf(finding, result.target));
}
