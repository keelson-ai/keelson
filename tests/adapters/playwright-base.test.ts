import { describe, expect, it, vi } from 'vitest';

import { ForethoughtAdapter } from '../../src/adapters/forethought.js';
import { pw } from '../../src/adapters/playwright-base.js';
import type { AdapterConfig } from '../../src/types/index.js';

/* eslint-disable @typescript-eslint/no-explicit-any */

function makeConfig(overrides: Partial<AdapterConfig> = {}): AdapterConfig {
  return { type: 'forethought', baseUrl: 'https://example.com', ...overrides };
}

function makeMockElement(textContent = '') {
  return {
    textContent: vi.fn().mockResolvedValue(textContent),
    click: vi.fn().mockResolvedValue(undefined),
    fill: vi.fn().mockResolvedValue(undefined),
    press: vi.fn().mockResolvedValue(undefined),
    getAttribute: vi.fn().mockResolvedValue(null),
    contentFrame: vi.fn().mockResolvedValue(null),
  };
}

function buildFakePw({ sendShouldTimeout = false } = {}) {
  const greetingMsg = makeMockElement('Bot Response:\n      Hi there!');
  const replyMsg = makeMockElement('Bot Response:\n      Response text.');
  const inputEl = makeMockElement();

  let botCalls = 0;

  const frame: any = {
    $: vi.fn(async (sel: string) => (sel === 'input[type="text"]' ? inputEl : null)),
    $$: vi.fn(async (sel: string) => {
      if (sel !== '.js-bot-message') return [];
      botCalls++;
      if (sendShouldTimeout) return [greetingMsg]; // never grows → timeout
      return botCalls <= 2 ? [greetingMsg] : [greetingMsg, replyMsg];
    }),
    waitForSelector: vi.fn().mockResolvedValue(inputEl),
    evaluate: vi.fn().mockResolvedValue(false),
  };

  const contextClose = vi.fn().mockResolvedValue(undefined);
  const context: any = {
    newPage: vi.fn().mockResolvedValue(null as any), // set below
    close: contextClose,
  };

  const page: any = {
    goto: vi.fn().mockResolvedValue(undefined),
    waitForTimeout: vi.fn().mockResolvedValue(undefined),
    waitForFunction: vi.fn().mockResolvedValue(undefined),
    evaluate: vi.fn().mockResolvedValue(undefined),
    frame: vi.fn((opts: { name: string }) => (opts.name === 'Virtual Assistant Chat' ? frame : null)),
    $: vi.fn().mockResolvedValue(null),
  };
  context.newPage.mockResolvedValue(page);

  const browser: any = {
    newContext: vi.fn().mockResolvedValue(context),
    contexts: vi.fn().mockReturnValue([context]),
    close: vi.fn().mockResolvedValue(undefined),
  };

  // Mock the exported launchBrowser function
  vi.spyOn(pw, 'launchBrowser').mockResolvedValue(browser);

  return {
    page,
    frame,
    inputEl,
    browser,
    context,
    contextClose,
    resetBotCalls() {
      botCalls = 0;
    },
  };
}

describe('PlaywrightBaseAdapter — timedOut response', () => {
  it('returns timedOut: true when sendCore throws a timeout error (no adaptive timeout)', async () => {
    buildFakePw({ sendShouldTimeout: true });
    const adapter = new ForethoughtAdapter(makeConfig({ timeout: 50 }));

    const result = await adapter.send([{ role: 'user', content: 'test' }]);

    expect(result.timedOut).toBe(true);
    expect(result.content).toContain('timed out');
  });
});

describe('PlaywrightBaseAdapter — adaptive timeout', () => {
  it('retries with doubled timeout on first timeout, returns timedOut if both fail', async () => {
    buildFakePw({ sendShouldTimeout: true });
    const adapter = new ForethoughtAdapter(makeConfig({ timeout: 50, browserAdaptiveTimeout: true }));

    const result = await adapter.send([{ role: 'user', content: 'test' }]);

    expect(result.timedOut).toBe(true);
    expect(result.content).toContain('timed out');
    // Should have attempted twice (original + retry with fresh context)
  });

  it('succeeds on retry when second attempt resolves', async () => {
    let attempt = 0;
    buildFakePw();
    const adapter = new ForethoughtAdapter(makeConfig({ timeout: 50, browserAdaptiveTimeout: true }));

    // Patch sendCore to fail on first call, succeed on second
    const originalSendCore = (adapter as any).sendCore.bind(adapter);
    (adapter as any).sendCore = vi.fn(async (...args: any[]) => {
      attempt++;
      if (attempt === 1) {
        throw new Error('no reply within 0.05s');
      }
      return originalSendCore(...args);
    });

    const result = await adapter.send([{ role: 'user', content: 'test' }]);

    expect(result.timedOut).toBeUndefined();
    expect(result.content).toContain('Response text');
  });
});

describe('PlaywrightBaseAdapter — fresh context per send', () => {
  it('resets browser context on second send when freshContextPerSend is enabled', async () => {
    const { contextClose, resetBotCalls } = buildFakePw();
    const adapter = new ForethoughtAdapter(makeConfig({ browserFreshContextPerSend: true }));

    // First send — normal init
    await adapter.send([{ role: 'user', content: 'first' }]);

    resetBotCalls();

    // Second send — should reset context
    await adapter.send([{ role: 'user', content: 'second' }]);

    // Context.close should have been called during resetBrowserContext
    expect(contextClose).toHaveBeenCalled();
  });

  it('does not reset context when freshContextPerSend is disabled (default)', async () => {
    const { contextClose, resetBotCalls } = buildFakePw();
    const adapter = new ForethoughtAdapter(makeConfig());

    await adapter.send([{ role: 'user', content: 'first' }]);
    resetBotCalls();
    await adapter.send([{ role: 'user', content: 'second' }]);

    // Context.close should NOT have been called
    expect(contextClose).not.toHaveBeenCalled();
  });
});

describe('AdapterResponse.timedOut type', () => {
  it('normal response does not have timedOut', async () => {
    buildFakePw();
    const adapter = new ForethoughtAdapter(makeConfig());

    const result = await adapter.send([{ role: 'user', content: 'hi' }]);

    expect(result.timedOut).toBeUndefined();
    expect(result.latencyMs).toBeGreaterThanOrEqual(0);
  });
});
