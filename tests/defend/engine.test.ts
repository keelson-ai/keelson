import { describe, expect, it } from 'vitest';

import { PolicyEngine } from '../../src/defend/engine.js';
import type { ContentRule, DefendPolicy, ToolRule } from '../../src/defend/types.js';
import { PolicyAction } from '../../src/defend/types.js';

function makePolicy(overrides: Partial<DefendPolicy> = {}): DefendPolicy {
  return {
    toolRules: [],
    contentRules: [],
    defaultToolAction: PolicyAction.Allow,
    logAll: false,
    ...overrides,
  };
}

function makeToolRule(overrides: Partial<ToolRule> = {}): ToolRule {
  return {
    pattern: 'delete_*',
    action: PolicyAction.Deny,
    reason: 'Destructive operation',
    ...overrides,
  };
}

function makeContentRule(overrides: Partial<ContentRule> = {}): ContentRule {
  return {
    pattern: 'API_KEY\\s*=\\s*\\S+',
    action: PolicyAction.Deny,
    reason: 'Sensitive data',
    checkInput: true,
    checkOutput: true,
    ...overrides,
  };
}

describe('PolicyEngine', () => {
  describe('checkTool', () => {
    it('blocks tools matching a deny rule', () => {
      const policy = makePolicy({ toolRules: [makeToolRule()] });
      const engine = new PolicyEngine(policy);

      const decision = engine.checkTool('delete_user');
      expect(decision.allowed).toBe(false);
      expect(decision.rule).toBe('delete_*');
      expect(decision.reason).toContain('Destructive operation');
    });

    it('allows tools matching an allow rule', () => {
      const rule = makeToolRule({ pattern: 'read_*', action: PolicyAction.Allow, reason: 'Read allowed' });
      const engine = new PolicyEngine(makePolicy({ toolRules: [rule] }));

      const decision = engine.checkTool('read_file');
      expect(decision.allowed).toBe(true);
      expect(decision.rule).toBe('read_*');
    });

    it('logs tools matching a log rule and allows them', () => {
      const rule = makeToolRule({ pattern: 'send_email', action: PolicyAction.Log, reason: 'Email sending' });
      const engine = new PolicyEngine(makePolicy({ toolRules: [rule] }));

      const decision = engine.checkTool('send_email');
      expect(decision.allowed).toBe(true);
      expect(decision.rule).toBe('send_email');
      expect(engine.violations).toHaveLength(1);
      expect(engine.violations[0].action).toBe(PolicyAction.Log);
    });

    it('uses default action when no rule matches', () => {
      const engine = new PolicyEngine(makePolicy({ defaultToolAction: PolicyAction.Allow }));

      const decision = engine.checkTool('some_unknown_tool');
      expect(decision.allowed).toBe(true);
      expect(decision.rule).toBeNull();
    });

    it('denies by default when default action is deny', () => {
      const engine = new PolicyEngine(makePolicy({ defaultToolAction: PolicyAction.Deny }));

      const decision = engine.checkTool('some_unknown_tool');
      expect(decision.allowed).toBe(false);
    });

    it('records violation when logAll is true', () => {
      const engine = new PolicyEngine(makePolicy({ logAll: true }));

      engine.checkTool('any_tool');
      expect(engine.violations).toHaveLength(1);
      expect(engine.violations[0].rule).toBe('default:log_all');
    });

    it('records violation on deny', () => {
      const policy = makePolicy({ toolRules: [makeToolRule()] });
      const engine = new PolicyEngine(policy);

      engine.checkTool('delete_user');
      expect(engine.violations).toHaveLength(1);
      expect(engine.violations[0].toolName).toBe('delete_user');
      expect(engine.violations[0].action).toBe(PolicyAction.Deny);
    });

    it('matches glob patterns with question marks', () => {
      const rule = makeToolRule({ pattern: 'rm_?' });
      const engine = new PolicyEngine(makePolicy({ toolRules: [rule] }));

      expect(engine.checkTool('rm_f').allowed).toBe(false);
      expect(engine.checkTool('rm_rf').allowed).toBe(true); // ? matches only one char
    });

    it('checks rules in order and returns first match', () => {
      const rules: ToolRule[] = [
        makeToolRule({ pattern: 'delete_safe', action: PolicyAction.Allow, reason: 'Explicitly allowed' }),
        makeToolRule({ pattern: 'delete_*', action: PolicyAction.Deny, reason: 'Blocked' }),
      ];
      const engine = new PolicyEngine(makePolicy({ toolRules: rules }));

      expect(engine.checkTool('delete_safe').allowed).toBe(true);
      expect(engine.checkTool('delete_user').allowed).toBe(false);
    });
  });

  describe('checkContent', () => {
    it('blocks content matching a deny pattern', () => {
      const rule = makeContentRule();
      const engine = new PolicyEngine(makePolicy({ contentRules: [rule] }));

      const decision = engine.checkContent('API_KEY = sk-live-abc123');
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain('Sensitive data');
    });

    it('allows content that does not match any rule', () => {
      const rule = makeContentRule();
      const engine = new PolicyEngine(makePolicy({ contentRules: [rule] }));

      const decision = engine.checkContent('Hello, world!');
      expect(decision.allowed).toBe(true);
    });

    it('skips input-only rules when checking output', () => {
      const rule = makeContentRule({ checkOutput: false });
      const engine = new PolicyEngine(makePolicy({ contentRules: [rule] }));

      const decision = engine.checkContent('API_KEY = sk-live-abc123', false);
      expect(decision.allowed).toBe(true);
    });

    it('skips output-only rules when checking input', () => {
      const rule = makeContentRule({ checkInput: false });
      const engine = new PolicyEngine(makePolicy({ contentRules: [rule] }));

      const decision = engine.checkContent('API_KEY = sk-live-abc123', true);
      expect(decision.allowed).toBe(true);
    });

    it('detects side-effect patterns in output', () => {
      const engine = new PolicyEngine(makePolicy());
      const content = '{"function_call": {"name": "execute_command", "arguments": "{}"}}';

      const decision = engine.checkContent(content, false);
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain('side-effect');
    });

    it('does not check side-effect patterns on input', () => {
      const engine = new PolicyEngine(makePolicy());
      const content = '{"function_call": {"name": "execute_command", "arguments": "{}"}}';

      const decision = engine.checkContent(content, true);
      expect(decision.allowed).toBe(true);
    });

    it('logs content matching a log rule', () => {
      const rule = makeContentRule({ action: PolicyAction.Log });
      const engine = new PolicyEngine(makePolicy({ contentRules: [rule] }));

      const decision = engine.checkContent('API_KEY = sk-live-abc123');
      expect(decision.allowed).toBe(true);
      expect(engine.violations).toHaveLength(1);
      expect(engine.violations[0].action).toBe(PolicyAction.Log);
    });

    it('records content snippet in violations', () => {
      const rule = makeContentRule();
      const engine = new PolicyEngine(makePolicy({ contentRules: [rule] }));

      engine.checkContent('API_KEY = sk-live-abc123 with extra long content here');
      expect(engine.violations[0].contentSnippet).toBeTruthy();
      expect(engine.violations[0].contentSnippet!.length).toBeLessThanOrEqual(100);
    });
  });

  describe('violations', () => {
    it('returns a copy of violations list', () => {
      const policy = makePolicy({ toolRules: [makeToolRule()] });
      const engine = new PolicyEngine(policy);

      engine.checkTool('delete_user');
      const violations1 = engine.violations;
      const violations2 = engine.violations;

      expect(violations1).toEqual(violations2);
      expect(violations1).not.toBe(violations2); // Different array references
    });

    it('accumulates violations across multiple checks', () => {
      const policy = makePolicy({
        toolRules: [makeToolRule()],
        contentRules: [makeContentRule()],
      });
      const engine = new PolicyEngine(policy);

      engine.checkTool('delete_user');
      engine.checkContent('API_KEY = hunter2');

      expect(engine.violations).toHaveLength(2);
    });

    it('includes ISO timestamp in violations', () => {
      const policy = makePolicy({ toolRules: [makeToolRule()] });
      const engine = new PolicyEngine(policy);

      engine.checkTool('delete_user');
      const violation = engine.violations[0];
      expect(violation.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });
  });
});
