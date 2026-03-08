/**
 * Compliance report generation mapping findings to security frameworks.
 *
 * Supports OWASP LLM Top 10, NIST AI RMF, EU AI Act, ISO 42001, SOC2, PCI DSS v4.
 */

import type { Finding, ScanResult } from '../types/index.js';
import { ComplianceFramework, Verdict } from '../types/index.js';

// ─── Interfaces ─────────────────────────────────────────

export interface FrameworkMapping {
  controlId: string;
  controlName: string;
  findings: Finding[];
  status: 'pass' | 'fail' | 'partial';
}

interface ControlDefinition {
  name: string;
  description: string;
  remediation: string;
  categories: string[];
  probePrefixes: string[];
}

// ─── Framework Controls ─────────────────────────────────

const OWASP_LLM_CONTROLS: Record<string, ControlDefinition> = {
  LLM01: {
    name: 'Prompt Injection',
    description:
      'Direct and indirect prompt injection probes that manipulate LLM behavior.',
    remediation:
      'Implement input validation, privilege control, and human-in-the-loop for critical actions.',
    categories: ['Goal Adherence'],
    probePrefixes: ['GA-'],
  },
  LLM02: {
    name: 'Insecure Output Handling',
    description:
      'Failure to validate/sanitize LLM outputs before passing to downstream systems.',
    remediation:
      'Apply output encoding, input validation on downstream systems, and least privilege.',
    categories: ['Tool Safety', 'Permission Boundaries'],
    probePrefixes: ['TS-', 'PB-'],
  },
  LLM03: {
    name: 'Training Data Poisoning',
    description: 'Manipulation of training data to introduce vulnerabilities or biases.',
    remediation:
      'Vet training data sources, use data sanitization, and implement anomaly detection.',
    categories: [],
    probePrefixes: [],
  },
  LLM04: {
    name: 'Model Denial of Service',
    description: 'Resource-intensive inputs causing degraded service or high costs.',
    remediation: 'Implement input length limits, rate limiting, and resource monitoring.',
    categories: [],
    probePrefixes: [],
  },
  LLM05: {
    name: 'Supply Chain Vulnerabilities',
    description:
      'Vulnerabilities in third-party components, plugins, or pre-trained models.',
    remediation: 'Vet third-party components, maintain SBOM, and monitor for CVEs.',
    categories: ['Memory Integrity', 'Session Isolation'],
    probePrefixes: ['MI-', 'SI-'],
  },
  LLM06: {
    name: 'Sensitive Information Disclosure',
    description: 'LLM revealing sensitive data through responses.',
    remediation:
      'Apply data sanitization, PII filtering, and access controls on training data.',
    categories: ['Content Safety', 'Execution Safety'],
    probePrefixes: ['CS-', 'ES-'],
  },
  LLM07: {
    name: 'Insecure Plugin Design',
    description: 'Plugins with inadequate access controls or input validation.',
    remediation:
      'Apply least privilege to plugins, validate inputs, and require user confirmation.',
    categories: ['Tool Safety'],
    probePrefixes: ['TS-'],
  },
  LLM08: {
    name: 'Excessive Agency',
    description: 'LLM granted excessive capabilities, permissions, or autonomy.',
    remediation:
      'Limit LLM permissions, implement function-level authorization, require human approval.',
    categories: ['Agentic Security', 'Delegation Integrity'],
    probePrefixes: ['AS-', 'DI-'],
  },
  LLM09: {
    name: 'Overreliance',
    description: 'Excessive dependence on LLM output without verification.',
    remediation:
      'Implement human oversight, output verification, and confidence scoring.',
    categories: ['Agentic Security', 'Delegation Integrity'],
    probePrefixes: ['AS-', 'DI-'],
  },
  LLM10: {
    name: 'Model Theft',
    description: 'Unauthorized access to or replication of the LLM.',
    remediation: 'Implement access controls, rate limiting, and watermarking.',
    categories: [],
    probePrefixes: [],
  },
};

const NIST_AI_RMF_CONTROLS: Record<string, ControlDefinition> = {
  GOVERN: {
    name: 'Govern',
    description: 'Establish and maintain organizational AI risk management policies.',
    remediation: 'Address identified vulnerabilities and re-test.',
    categories: ['Delegation Integrity', 'Permission Boundaries'],
    probePrefixes: ['DI-', 'PB-'],
  },
  MAP: {
    name: 'Map',
    description: 'Identify and document AI system risks in context.',
    remediation: 'Address identified vulnerabilities and re-test.',
    categories: ['Goal Adherence', 'Agentic Security'],
    probePrefixes: ['GA-', 'AS-'],
  },
  MEASURE: {
    name: 'Measure',
    description: 'Analyze and assess AI system risks quantitatively.',
    remediation: 'Address identified vulnerabilities and re-test.',
    categories: [
      'Goal Adherence', 'Tool Safety', 'Memory Integrity', 'Permission Boundaries',
      'Delegation Integrity', 'Execution Safety', 'Session Isolation',
      'Content Safety', 'Agentic Security',
    ],
    probePrefixes: [],
  },
  MANAGE: {
    name: 'Manage',
    description: 'Prioritize and respond to identified AI risks.',
    remediation: 'Address identified vulnerabilities and re-test.',
    categories: ['Execution Safety', 'Session Isolation'],
    probePrefixes: ['ES-', 'SI-'],
  },
};

const EU_AI_ACT_CONTROLS: Record<string, ControlDefinition> = {
  'Article 9': {
    name: 'Risk Management System',
    description: 'High-risk AI systems shall have a risk management system.',
    remediation: 'Address vulnerabilities to meet Article 9 requirements.',
    categories: ['Goal Adherence', 'Agentic Security', 'Delegation Integrity', 'Permission Boundaries'],
    probePrefixes: ['GA-', 'AS-', 'DI-', 'PB-'],
  },
  'Article 13': {
    name: 'Transparency and Information',
    description: 'High-risk AI systems shall be designed to ensure transparency of operation.',
    remediation: 'Address vulnerabilities to meet Article 13 requirements.',
    categories: ['Session Isolation', 'Content Safety'],
    probePrefixes: ['SI-', 'CS-'],
  },
  'Article 14': {
    name: 'Human Oversight',
    description: 'High-risk AI systems shall allow effective human oversight.',
    remediation: 'Address vulnerabilities to meet Article 14 requirements.',
    categories: ['Delegation Integrity', 'Execution Safety', 'Agentic Security'],
    probePrefixes: ['DI-', 'ES-', 'AS-'],
  },
  'Article 15': {
    name: 'Accuracy, Robustness and Cybersecurity',
    description:
      'High-risk AI systems shall be designed for accuracy, robustness and cybersecurity.',
    remediation: 'Address vulnerabilities to meet Article 15 requirements.',
    categories: ['Goal Adherence', 'Tool Safety', 'Memory Integrity', 'Permission Boundaries', 'Execution Safety'],
    probePrefixes: ['GA-', 'TS-', 'MI-', 'PB-', 'ES-'],
  },
};

const ISO_42001_CONTROLS: Record<string, ControlDefinition> = {
  'A.6': {
    name: 'AI System Security',
    description: 'Controls for securing AI systems against adversarial probes.',
    remediation: 'Implement security controls for identified AI vulnerabilities.',
    categories: [],
    probePrefixes: [],
  },
};

const SOC2_CONTROLS: Record<string, ControlDefinition> = {
  'CC6.1': {
    name: 'Logical and Physical Access Controls',
    description: 'The entity implements logical access security measures.',
    remediation: 'Strengthen AI agent access controls.',
    categories: ['Tool Safety', 'Agentic Security', 'Permission Boundaries', 'Execution Safety'],
    probePrefixes: ['TS-', 'AS-', 'PB-', 'ES-'],
  },
  'CC7.2': {
    name: 'System Monitoring',
    description: 'The entity monitors system components for anomalies.',
    remediation: 'Implement monitoring for AI-specific probe patterns.',
    categories: [],
    probePrefixes: [],
  },
};

const PCI_DSS_V4_CONTROLS: Record<string, ControlDefinition> = {
  '6.2': {
    name: 'Secure Development',
    description:
      'Bespoke and custom software is developed securely, including AI/ML components.',
    remediation:
      'Apply secure development practices to AI agent integrations and prompt handling.',
    categories: ['Goal Adherence', 'Delegation Integrity', 'Execution Safety'],
    probePrefixes: ['GA-', 'DI-', 'ES-'],
  },
  '6.3': {
    name: 'Security Testing',
    description:
      'Security vulnerabilities are identified and addressed, including AI-specific probe vectors.',
    remediation:
      'Perform regular security testing of AI agent capabilities including prompt injection and tool misuse.',
    categories: [
      'Goal Adherence', 'Tool Safety', 'Memory Integrity', 'Permission Boundaries',
      'Delegation Integrity', 'Execution Safety', 'Session Isolation',
      'Content Safety', 'Agentic Security',
    ],
    probePrefixes: ['GA-', 'TS-', 'MI-', 'PB-', 'DI-', 'ES-', 'SI-', 'CS-', 'AS-'],
  },
  '6.4': {
    name: 'Public-Facing Application Protection',
    description: 'Public-facing AI applications are protected against known probes.',
    remediation:
      'Implement input validation, output filtering, and rate limiting on public-facing AI endpoints.',
    categories: ['Goal Adherence', 'Content Safety', 'Permission Boundaries'],
    probePrefixes: ['GA-', 'CS-', 'PB-'],
  },
  '11.3': {
    name: 'Penetration Testing',
    description:
      'Regular penetration testing of AI systems to identify exploitable vulnerabilities.',
    remediation:
      'Conduct AI-specific penetration testing covering prompt injection, tool abuse, and privilege escalation.',
    categories: ['Tool Safety', 'Permission Boundaries', 'Agentic Security', 'Execution Safety'],
    probePrefixes: ['TS-', 'PB-', 'AS-', 'ES-'],
  },
};

export const FRAMEWORK_CONTROLS: Record<ComplianceFramework, Record<string, ControlDefinition>> = {
  [ComplianceFramework.OwaspLlmTop10]: OWASP_LLM_CONTROLS,
  [ComplianceFramework.NistAiRmf]: NIST_AI_RMF_CONTROLS,
  [ComplianceFramework.EuAiAct]: EU_AI_ACT_CONTROLS,
  [ComplianceFramework.Iso42001]: ISO_42001_CONTROLS,
  [ComplianceFramework.Soc2]: SOC2_CONTROLS,
  [ComplianceFramework.PciDssV4]: PCI_DSS_V4_CONTROLS,
};

// Build reverse mapping: control name → OWASP ID prefix (e.g. "Prompt Injection" → "LLM01")
const OWASP_NAME_TO_ID: Record<string, string> = Object.fromEntries(
  Object.entries(OWASP_LLM_CONTROLS).map(([id, ctrl]) => [ctrl.name, id]),
);

// ─── Helpers ────────────────────────────────────────────

function controlStatus(findings: Finding[]): 'pass' | 'fail' | 'partial' {
  if (findings.length === 0) return 'pass';
  if (findings.some((f) => f.verdict === Verdict.Vulnerable)) return 'fail';
  if (findings.every((f) => f.verdict === Verdict.Safe)) return 'pass';
  return 'partial';
}

function matchFindingsToControl(
  findings: Finding[],
  control: ControlDefinition,
): Finding[] {
  // Deduplicate by probeId
  const seen = new Set<string>();
  const matched: Finding[] = [];

  for (const f of findings) {
    if (seen.has(f.probeId)) continue;

    const matchesByCategory = control.categories.length > 0 &&
      control.categories.includes(f.category);
    const matchesByPrefix = control.probePrefixes.some((prefix) =>
      f.probeId.startsWith(prefix),
    );
    // Also match by OWASP ID for OWASP framework
    const owaspPrefix = OWASP_NAME_TO_ID[control.name];
    const matchesByOwasp = owaspPrefix != null && f.owaspId.startsWith(owaspPrefix);

    if (matchesByCategory || matchesByPrefix || matchesByOwasp) {
      seen.add(f.probeId);
      matched.push(f);
    }
  }

  return matched;
}

function complianceRecommendations(
  controls: Record<string, ControlDefinition>,
  mappings: FrameworkMapping[],
): string[] {
  const recs: string[] = [];
  const failed = mappings.filter((m) => m.status === 'fail');
  const notTested = mappings.filter((m) => m.findings.length === 0);

  if (failed.length > 0) {
    recs.push(`Address failing controls: ${failed.map((m) => m.controlId).join(', ')}`);
  }
  if (notTested.length > 0) {
    recs.push(
      `Expand testing to cover untested controls: ${notTested.map((m) => m.controlId).join(', ')}`,
    );
  }
  if (failed.length === 0) {
    recs.push('Maintain current security posture with regular testing.');
  }
  recs.push('Schedule periodic re-assessment to track compliance drift.');
  return recs;
}

// ─── Public API ─────────────────────────────────────────

/** Map findings to the controls of a compliance framework. */
export function mapFindingsToFramework(
  findings: Finding[],
  framework: ComplianceFramework,
): FrameworkMapping[] {
  const controls = FRAMEWORK_CONTROLS[framework];
  const mappings: FrameworkMapping[] = [];

  for (const [controlId, control] of Object.entries(controls)) {
    let matched: Finding[];

    // Special cases: ISO 42001 A.6 and SOC2 CC7.2 get all findings
    if (
      (framework === ComplianceFramework.Iso42001 && controlId === 'A.6') ||
      (framework === ComplianceFramework.Soc2 && controlId === 'CC7.2')
    ) {
      matched = findings;
    } else if (framework === ComplianceFramework.NistAiRmf && controlId === 'MEASURE') {
      // MEASURE gets all findings (security testing covers everything)
      matched = findings;
    } else {
      matched = matchFindingsToControl(findings, control);
    }

    mappings.push({
      controlId,
      controlName: control.name,
      findings: matched,
      status: matched.length === 0 ? 'pass' : controlStatus(matched),
    });
  }

  return mappings;
}

/** Generate a compliance report for the given framework. */
export function generateComplianceReport(
  result: ScanResult,
  framework: ComplianceFramework,
): string {
  const controls = FRAMEWORK_CONTROLS[framework];
  const mappings = mapFindingsToFramework(result.findings, framework);
  const recs = complianceRecommendations(controls, mappings);

  const totalControls = mappings.length;
  const tested = mappings.filter((m) => m.findings.length > 0).length;
  const passed = mappings.filter((m) => m.findings.length > 0 && m.status === 'pass').length;
  const coveragePct = totalControls > 0 ? Math.round((tested / totalControls) * 100) : 0;
  const passPct = tested > 0 ? Math.round((passed / tested) * 100) : 0;

  const frameworkNames: Record<ComplianceFramework, string> = {
    [ComplianceFramework.OwaspLlmTop10]: 'OWASP LLM Top 10',
    [ComplianceFramework.NistAiRmf]: 'NIST AI RMF',
    [ComplianceFramework.EuAiAct]: 'EU AI Act',
    [ComplianceFramework.Iso42001]: 'ISO 42001',
    [ComplianceFramework.Soc2]: 'SOC2',
    [ComplianceFramework.PciDssV4]: 'PCI DSS 4.0',
  };

  const lines: string[] = [];

  // Header
  lines.push('# Keelson Compliance Report');
  lines.push('');
  lines.push(`**Framework**: ${frameworkNames[framework]}`);
  lines.push(`**Target**: ${result.target}`);
  lines.push(`**Scan ID**: ${result.scanId}`);
  lines.push(`**Date**: ${result.startedAt}`);
  lines.push('');

  // Executive Summary
  lines.push('## Executive Summary');
  lines.push('');
  if (result.summary.vulnerable === 0) {
    lines.push(
      `All tested ${frameworkNames[framework]} controls passed security validation.`,
    );
  } else {
    lines.push(
      `Security testing identified ${result.summary.vulnerable} vulnerabilities across ` +
        `${frameworkNames[framework]} controls. Remediation is recommended.`,
    );
  }
  lines.push('');
  lines.push(`**Overall Coverage**: ${coveragePct}% of controls tested`);
  lines.push(`**Pass Rate**: ${passPct}% of tested controls passed`);
  lines.push('');

  // Control Assessment
  lines.push('## Control Assessment');
  lines.push('');

  for (const mapping of mappings) {
    const control = controls[mapping.controlId];
    lines.push(`### ${mapping.controlId}: ${mapping.controlName}`);
    lines.push('');
    lines.push(control.description);
    lines.push('');
    lines.push(`**Status**: ${mapping.status.toUpperCase()}`);
    lines.push(`**Findings**: ${mapping.findings.length} probes tested`);
    lines.push('');

    if (mapping.findings.length > 0) {
      lines.push('| Probe | Verdict | Severity |');
      lines.push('|-------|---------|----------|');
      for (const f of mapping.findings) {
        const name = f.probeName.length > 40 ? f.probeName.slice(0, 40) + '...' : f.probeName;
        lines.push(`| ${f.probeId}: ${name} | ${f.verdict} | ${f.severity} |`);
      }
      lines.push('');
    }

    if (mapping.status === 'fail' && control.remediation) {
      lines.push(`**Remediation**: ${control.remediation}`);
      lines.push('');
    }
  }

  // Recommendations
  lines.push('## Recommendations');
  lines.push('');
  for (let i = 0; i < recs.length; i++) {
    lines.push(`${i + 1}. ${recs[i]}`);
  }
  lines.push('');

  return lines.join('\n');
}
