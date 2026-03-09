import type { Severity } from '../types/index.js';

// ─── Agent Capability Discovery ─────────────────────────

export interface AgentCapability {
  name: string;
  detected: boolean;
  probePrompt: string;
  responseExcerpt: string;
  confidence: number;
}

export interface AgentProfile {
  profileId: string;
  targetUrl: string;
  capabilities: AgentCapability[];
  createdAt: string;
}

export function getDetectedCapabilities(profile: AgentProfile): AgentCapability[] {
  return profile.capabilities.filter((c) => c.detected);
}

// ─── Infrastructure Recon ───────────────────────────────

export interface InfraFinding {
  findingId: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  evidence: string;
  remediation: string;
  timestamp: string;
}

// ─── Probe Chains ───────────────────────────────────────

export interface ChainStep {
  prompt: string;
  expectedBehavior: string;
  continueIf: string;
}

export interface ProbeChain {
  chainId: string;
  name: string;
  capabilities: string[];
  steps: ChainStep[];
  severity: Severity;
  category: string;
  owaspId: string;
  description: string;
}
