/**
 * Policy models for Keelson Defend runtime security hooks.
 */

import { z } from 'zod';

// ─── Constants ──────────────────────────────────────────

export const BLOCKED_MESSAGE = '[BLOCKED by Keelson Defend]';
export const REDACTED_MESSAGE = '[REDACTED by Keelson Defend]';

// ─── Enums ──────────────────────────────────────────────

export enum PolicyAction {
  Allow = 'allow',
  Deny = 'deny',
  Log = 'log',
}

// ─── Interfaces ─────────────────────────────────────────

/** Rule for a specific tool or tool pattern. */
export interface ToolRule {
  /** Tool name or glob pattern (e.g. "delete_*", "send_email"). */
  pattern: string;
  action: PolicyAction;
  reason: string;
}

/** Rule for content pattern matching in LLM inputs/outputs. */
export interface ContentRule {
  /** Regex pattern to match. */
  pattern: string;
  action: PolicyAction;
  reason: string;
  checkInput: boolean;
  checkOutput: boolean;
}

/** Complete defend policy configuration. */
export interface DefendPolicy {
  toolRules: ToolRule[];
  contentRules: ContentRule[];
  defaultToolAction: PolicyAction;
  logAll: boolean;
}

/** Record of a policy violation. */
export interface Violation {
  timestamp: string;
  toolName: string | null;
  contentSnippet: string | null;
  rule: string;
  action: PolicyAction;
}

/** Result of a policy check. */
export interface PolicyDecision {
  allowed: boolean;
  rule: string | null;
  reason: string;
}

// ─── Zod Schemas ────────────────────────────────────────

export const toolRuleSchema = z.object({
  pattern: z.string(),
  action: z.enum([PolicyAction.Allow, PolicyAction.Deny, PolicyAction.Log]).default(PolicyAction.Deny),
  reason: z.string().default(''),
});

export const contentRuleSchema = z.object({
  pattern: z.string(),
  action: z.enum([PolicyAction.Allow, PolicyAction.Deny, PolicyAction.Log]).default(PolicyAction.Deny),
  reason: z.string().default(''),
  check_input: z.boolean().default(true),
  check_output: z.boolean().default(true),
});

export const policyFileSchema = z.object({
  tools: z.array(toolRuleSchema).default([]),
  content: z.array(contentRuleSchema).default([]),
  defaults: z
    .object({
      tool_action: z.enum([PolicyAction.Allow, PolicyAction.Deny, PolicyAction.Log]).default(PolicyAction.Allow),
      log_all: z.boolean().default(false),
    })
    .default({ tool_action: PolicyAction.Allow, log_all: false }),
});

export type PolicyFileInput = z.infer<typeof policyFileSchema>;
