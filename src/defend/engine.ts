/**
 * Core policy evaluation engine for Keelson Defend.
 */

import type { ContentRule, DefendPolicy, PolicyDecision, Violation } from './types.js';
import { PolicyAction } from './types.js';

// ─── Side-Effect Detection Patterns ─────────────────────
// Mirrors the patterns from core/detection.ts for runtime policy enforcement.
// These detect tool call wrappers and dangerous tool names in LLM output.

const DANGEROUS_TOOL_PREFIXES: readonly string[] = [
  'execute', 'run', 'shell', 'bash', 'exec', 'system', 'eval',
  'read_file', 'write_file', 'delete_file',
  'sql', 'database', 'send_email', 'send_message',
  'http_request', 'fetch', 'curl', 'wget', 'rm',
];

const TOOL_CALL_WRAPPER_RE: RegExp[] = [
  /function_call\s*[":]/i,
  /tool_calls\s*[":[\]]/i,
];

const DANGEROUS_TOOL_NAME_RE: RegExp[] = (() => {
  const escaped = DANGEROUS_TOOL_PREFIXES.map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const alt = escaped.join('|');
  return [
    new RegExp(`["']name["']\\s*:\\s*["'](${alt})(?:[_.\\s\\-"']|$)`, 'i'),
    new RegExp(`["']function["']\\s*:\\s*["'](${alt})(?:[_.\\s\\-"']|$)`, 'i'),
  ];
})();

/** Pre-compiled content rule with its regex. */
interface CompiledContentRule {
  rule: ContentRule;
  regex: RegExp;
}

/**
 * Evaluate tool calls and content against a DefendPolicy.
 *
 * Records violations for auditing and returns allow/deny decisions.
 */
export class PolicyEngine {
  private readonly policy: DefendPolicy;
  private readonly violationLog: Violation[] = [];
  private readonly compiledContent: CompiledContentRule[];

  constructor(policy: DefendPolicy) {
    this.policy = policy;
    this.compiledContent = policy.contentRules.map((rule) => ({
      rule,
      regex: new RegExp(rule.pattern, 'i'),
    }));
  }

  /** Check if a tool call is allowed by policy. */
  checkTool(toolName: string, _arguments?: Record<string, unknown> | null): PolicyDecision {
    for (const rule of this.policy.toolRules) {
      if (matchGlob(toolName, rule.pattern)) {
        const allowed = rule.action === PolicyAction.Allow;
        const isLog = rule.action === PolicyAction.Log;

        if (!allowed && !isLog) {
          this.recordViolation({
            toolName,
            contentSnippet: null,
            rule: `tool:${rule.pattern}`,
            action: rule.action,
          });
          return {
            allowed: false,
            rule: rule.pattern,
            reason: rule.reason || `Tool '${toolName}' blocked by rule '${rule.pattern}'`,
          };
        }

        if (isLog) {
          this.recordViolation({
            toolName,
            contentSnippet: null,
            rule: `tool:${rule.pattern}`,
            action: PolicyAction.Log,
          });
          return {
            allowed: true,
            rule: rule.pattern,
            reason: rule.reason || `Tool '${toolName}' logged by rule '${rule.pattern}'`,
          };
        }

        // Explicit ALLOW
        return { allowed: true, rule: rule.pattern, reason: rule.reason };
      }
    }

    // No rule matched — use default action
    const defaultAllowed = this.policy.defaultToolAction !== PolicyAction.Deny;
    if (this.policy.logAll) {
      this.recordViolation({
        toolName,
        contentSnippet: null,
        rule: 'default:log_all',
        action: PolicyAction.Log,
      });
    }
    return { allowed: defaultAllowed, rule: null, reason: '' };
  }

  /** Check content against content rules and built-in detection patterns. */
  checkContent(content: string, isInput = true): PolicyDecision {
    const snippet = content.slice(0, 100);

    // Check content rules
    for (const { rule, regex } of this.compiledContent) {
      if (isInput && !rule.checkInput) continue;
      if (!isInput && !rule.checkOutput) continue;

      if (regex.test(content)) {
        const allowed = rule.action === PolicyAction.Allow;
        const isLog = rule.action === PolicyAction.Log;

        if (!allowed && !isLog) {
          this.recordViolation({
            toolName: null,
            contentSnippet: snippet,
            rule: `content:${rule.pattern}`,
            action: rule.action,
          });
          return {
            allowed: false,
            rule: rule.pattern,
            reason: rule.reason || `Content matched blocked pattern '${rule.pattern}'`,
          };
        }

        if (isLog) {
          this.recordViolation({
            toolName: null,
            contentSnippet: snippet,
            rule: `content:${rule.pattern}`,
            action: PolicyAction.Log,
          });
          return { allowed: true, rule: rule.pattern, reason: rule.reason };
        }

        // Explicit ALLOW — short-circuit, skip further rules
        return { allowed: true, rule: rule.pattern, reason: rule.reason };
      }
    }

    // For outputs, check side-effect patterns.
    // Only match dangerous tool names when a tool call wrapper is present.
    if (!isInput) {
      const hasWrapper = TOOL_CALL_WRAPPER_RE.some((re) => re.test(content));
      if (hasWrapper) {
        for (const pattern of DANGEROUS_TOOL_NAME_RE) {
          if (pattern.test(content)) {
            this.recordViolation({
              toolName: null,
              contentSnippet: snippet,
              rule: `side_effect:${pattern.source}`,
              action: PolicyAction.Deny,
            });
            return {
              allowed: false,
              rule: pattern.source,
              reason: `Output matched side-effect pattern: ${pattern.source}`,
            };
          }
        }

        // Wrapper alone is still suspicious
        const wrapperPat = TOOL_CALL_WRAPPER_RE.find((re) => re.test(content))!;
        this.recordViolation({
          toolName: null,
          contentSnippet: snippet,
          rule: `side_effect:${wrapperPat.source}`,
          action: PolicyAction.Deny,
        });
        return {
          allowed: false,
          rule: wrapperPat.source,
          reason: `Output matched tool call wrapper: ${wrapperPat.source}`,
        };
      }
    }

    return { allowed: true, rule: null, reason: '' };
  }

  /** Return a copy of all recorded violations. */
  get violations(): Violation[] {
    return [...this.violationLog];
  }

  private recordViolation(fields: Omit<Violation, 'timestamp'>): void {
    this.violationLog.push({
      timestamp: new Date().toISOString(),
      ...fields,
    });
  }
}

/**
 * Simple glob matching supporting `*` and `?` wildcards.
 *
 * Converts a glob pattern to a regex. The `*` wildcard matches any number of
 * characters (including none); `?` matches exactly one character.
 */
function matchGlob(value: string, pattern: string): boolean {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  const regexStr = escaped.replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${regexStr}$`).test(value);
}
