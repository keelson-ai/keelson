/**
 * YAML policy loader for Keelson Defend.
 */

import { readFile } from 'node:fs/promises';

import yaml from 'yaml';

import type { ContentRule, DefendPolicy, ToolRule } from './types.js';
import { PolicyAction, policyFileSchema } from './types.js';

/**
 * Load a DefendPolicy from a YAML file.
 *
 * Expected YAML structure:
 * ```yaml
 * tools:
 *   - pattern: "delete_*"
 *     action: deny
 *     reason: "Destructive operations blocked"
 *   - pattern: "send_email"
 *     action: log
 * content:
 *   - pattern: "API_KEY|SECRET|PASSWORD"
 *     action: deny
 *     reason: "Sensitive data detected"
 * defaults:
 *   tool_action: allow
 *   log_all: false
 * ```
 */
export async function loadPolicy(path: string): Promise<DefendPolicy> {
  const raw = await readFile(path, 'utf-8');
  const parsed: unknown = yaml.parse(raw) ?? {};
  const validated = policyFileSchema.parse(parsed);

  const toolRules: ToolRule[] = validated.tools.map((item) => ({
    pattern: item.pattern,
    action: item.action,
    reason: item.reason,
  }));

  const contentRules: ContentRule[] = validated.content.map((item) => ({
    pattern: item.pattern,
    action: item.action,
    reason: item.reason,
    checkInput: item.check_input,
    checkOutput: item.check_output,
  }));

  return {
    toolRules,
    contentRules,
    defaultToolAction: validated.defaults.tool_action,
    logAll: validated.defaults.log_all,
  };
}

/** Return a sensible default policy with common dangerous tools blocked. */
export function defaultPolicy(): DefendPolicy {
  const toolRules: ToolRule[] = [
    // Block destructive operations
    { pattern: 'delete_*', action: PolicyAction.Deny, reason: 'Destructive operation' },
    { pattern: 'drop_*', action: PolicyAction.Deny, reason: 'Destructive operation' },
    { pattern: 'rm_*', action: PolicyAction.Deny, reason: 'Destructive operation' },
    { pattern: 'remove_*', action: PolicyAction.Deny, reason: 'Destructive operation' },
    // Block code execution
    { pattern: 'system_*', action: PolicyAction.Deny, reason: 'System command execution' },
    { pattern: 'exec_*', action: PolicyAction.Deny, reason: 'Code execution' },
    { pattern: 'eval_*', action: PolicyAction.Deny, reason: 'Code evaluation' },
    { pattern: 'execute_*', action: PolicyAction.Deny, reason: 'Code execution' },
    // Log sensitive operations
    { pattern: 'send_email', action: PolicyAction.Log, reason: 'Email sending' },
    { pattern: 'send_message', action: PolicyAction.Log, reason: 'Message sending' },
    { pattern: 'http_request', action: PolicyAction.Log, reason: 'HTTP request' },
    { pattern: 'charge_payment', action: PolicyAction.Log, reason: 'Payment operation' },
  ];

  const contentRules: ContentRule[] = [
    {
      pattern: String.raw`(?:API_KEY|SECRET_KEY|PASSWORD|PRIVATE_KEY|ACCESS_TOKEN)\s*[=:]\s*\S+`,
      action: PolicyAction.Deny,
      reason: 'Sensitive credential detected',
      checkInput: true,
      checkOutput: true,
    },
    {
      pattern: String.raw`(?:Bearer\s+[A-Za-z0-9\-._~+/]+=*)`,
      action: PolicyAction.Deny,
      reason: 'Bearer token detected',
      checkInput: true,
      checkOutput: true,
    },
  ];

  return {
    toolRules,
    contentRules,
    defaultToolAction: PolicyAction.Allow,
    logAll: false,
  };
}
