import { mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { defaultPolicy, loadPolicy } from '../../src/defend/loader.js';
import { PolicyAction } from '../../src/defend/types.js';

const TEST_DIR = join(tmpdir(), `keelson-defend-loader-test-${Date.now()}`);

beforeAll(async () => {
  await mkdir(TEST_DIR, { recursive: true });
});

afterAll(async () => {
  await rm(TEST_DIR, { recursive: true, force: true });
});

describe('loadPolicy', () => {
  it('loads a valid policy from YAML', async () => {
    const yamlContent = `
tools:
  - pattern: "delete_*"
    action: deny
    reason: "Destructive operations blocked"
  - pattern: "send_email"
    action: log
    reason: "Email sending logged"
content:
  - pattern: "API_KEY"
    action: deny
    reason: "Sensitive data detected"
    check_input: true
    check_output: false
defaults:
  tool_action: allow
  log_all: false
`;
    const filePath = join(TEST_DIR, 'valid-policy.yaml');
    await writeFile(filePath, yamlContent, 'utf-8');

    const policy = await loadPolicy(filePath);

    expect(policy.toolRules).toHaveLength(2);
    expect(policy.toolRules[0].pattern).toBe('delete_*');
    expect(policy.toolRules[0].action).toBe(PolicyAction.Deny);
    expect(policy.toolRules[0].reason).toBe('Destructive operations blocked');

    expect(policy.toolRules[1].pattern).toBe('send_email');
    expect(policy.toolRules[1].action).toBe(PolicyAction.Log);

    expect(policy.contentRules).toHaveLength(1);
    expect(policy.contentRules[0].pattern).toBe('API_KEY');
    expect(policy.contentRules[0].checkInput).toBe(true);
    expect(policy.contentRules[0].checkOutput).toBe(false);

    expect(policy.defaultToolAction).toBe(PolicyAction.Allow);
    expect(policy.logAll).toBe(false);
  });

  it('uses default values for missing fields', async () => {
    const yamlContent = `
tools:
  - pattern: "exec_*"
`;
    const filePath = join(TEST_DIR, 'minimal-policy.yaml');
    await writeFile(filePath, yamlContent, 'utf-8');

    const policy = await loadPolicy(filePath);

    expect(policy.toolRules).toHaveLength(1);
    expect(policy.toolRules[0].action).toBe(PolicyAction.Deny); // default
    expect(policy.toolRules[0].reason).toBe('');

    expect(policy.contentRules).toHaveLength(0);
    expect(policy.defaultToolAction).toBe(PolicyAction.Allow);
    expect(policy.logAll).toBe(false);
  });

  it('handles empty YAML file', async () => {
    const filePath = join(TEST_DIR, 'empty-policy.yaml');
    await writeFile(filePath, '', 'utf-8');

    const policy = await loadPolicy(filePath);

    expect(policy.toolRules).toHaveLength(0);
    expect(policy.contentRules).toHaveLength(0);
    expect(policy.defaultToolAction).toBe(PolicyAction.Allow);
  });

  it('handles YAML with only defaults', async () => {
    const yamlContent = `
defaults:
  tool_action: deny
  log_all: true
`;
    const filePath = join(TEST_DIR, 'defaults-only.yaml');
    await writeFile(filePath, yamlContent, 'utf-8');

    const policy = await loadPolicy(filePath);

    expect(policy.toolRules).toHaveLength(0);
    expect(policy.contentRules).toHaveLength(0);
    expect(policy.defaultToolAction).toBe(PolicyAction.Deny);
    expect(policy.logAll).toBe(true);
  });

  it('throws on nonexistent file', async () => {
    await expect(loadPolicy(join(TEST_DIR, 'nonexistent.yaml'))).rejects.toThrow();
  });

  it('throws on invalid YAML structure', async () => {
    const yamlContent = `
tools:
  - pattern: 123
    action: invalid_action
`;
    const filePath = join(TEST_DIR, 'invalid-policy.yaml');
    await writeFile(filePath, yamlContent, 'utf-8');

    await expect(loadPolicy(filePath)).rejects.toThrow();
  });
});

describe('defaultPolicy', () => {
  it('returns a policy with tool rules', () => {
    const policy = defaultPolicy();
    expect(policy.toolRules.length).toBeGreaterThan(0);
  });

  it('returns a policy with content rules', () => {
    const policy = defaultPolicy();
    expect(policy.contentRules.length).toBeGreaterThan(0);
  });

  it('blocks destructive tool patterns', () => {
    const policy = defaultPolicy();
    const destructivePatterns = policy.toolRules
      .filter((r) => r.action === PolicyAction.Deny)
      .map((r) => r.pattern);

    expect(destructivePatterns).toContain('delete_*');
    expect(destructivePatterns).toContain('drop_*');
    expect(destructivePatterns).toContain('rm_*');
    expect(destructivePatterns).toContain('exec_*');
  });

  it('logs sensitive operations', () => {
    const policy = defaultPolicy();
    const logPatterns = policy.toolRules
      .filter((r) => r.action === PolicyAction.Log)
      .map((r) => r.pattern);

    expect(logPatterns).toContain('send_email');
    expect(logPatterns).toContain('http_request');
  });

  it('has allow as default tool action', () => {
    const policy = defaultPolicy();
    expect(policy.defaultToolAction).toBe(PolicyAction.Allow);
  });

  it('has logAll disabled', () => {
    const policy = defaultPolicy();
    expect(policy.logAll).toBe(false);
  });

  it('includes credential detection in content rules', () => {
    const policy = defaultPolicy();
    const hasCredentialRule = policy.contentRules.some((r) => r.pattern.includes('API_KEY'));
    expect(hasCredentialRule).toBe(true);
  });

  it('includes bearer token detection in content rules', () => {
    const policy = defaultPolicy();
    const hasBearerRule = policy.contentRules.some((r) => r.pattern.includes('Bearer'));
    expect(hasBearerRule).toBe(true);
  });
});
