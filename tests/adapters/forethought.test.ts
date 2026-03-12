import { describe, expect, it, vi } from 'vitest';

import { ForethoughtAdapter } from '../../src/adapters/forethought.js';
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

function buildFakePw() {
  const greetingMsg = makeMockElement('Bot Response:\n      Hi there!');
  const replyMsg = makeMockElement('Bot Response:\n      Forethought integrates with Zendesk.');
  const inputEl = makeMockElement();

  let botCalls = 0;

  const frame: any = {
    $: vi.fn(async (sel: string) => (sel === 'input[type="text"]' ? inputEl : null)),
    $$: vi.fn(async (sel: string) => {
      if (sel !== '.js-bot-message') return [];
      botCalls++;
      return botCalls <= 2 ? [greetingMsg] : [greetingMsg, replyMsg];
    }),
    waitForSelector: vi.fn().mockResolvedValue(inputEl),
    // isWidgetLoading expects boolean; getQuickReplyButtons expects string[]
    evaluate: vi.fn().mockResolvedValue(false),
  };

  const page: any = {
    goto: vi.fn().mockResolvedValue(undefined),
    waitForTimeout: vi.fn().mockResolvedValue(undefined),
    waitForFunction: vi.fn().mockResolvedValue(undefined),
    evaluate: vi.fn().mockResolvedValue(undefined),
    frame: vi.fn((opts: { name: string }) => (opts.name === 'Virtual Assistant Chat' ? frame : null)),
    $: vi.fn().mockResolvedValue(null),
  };

  const browser: any = {
    newContext: vi.fn().mockResolvedValue({ newPage: vi.fn().mockResolvedValue(page) }),
    close: vi.fn().mockResolvedValue(undefined),
  };

  return {
    pw: { chromium: { launch: vi.fn().mockResolvedValue(browser) } },
    page,
    frame,
    inputEl,
    browser,
    resetBotCalls() {
      botCalls = 0;
    },
  };
}

function patchPw(adapter: ForethoughtAdapter, pw: any): void {
  (adapter as any).loadPlaywright = vi.fn().mockResolvedValue(pw);
}

describe('ForethoughtAdapter', () => {
  it('constructs without error', () => {
    expect(new ForethoughtAdapter(makeConfig())).toBeDefined();
  });

  it('sends a message and extracts bot response', async () => {
    const { pw, inputEl } = buildFakePw();
    const adapter = new ForethoughtAdapter(makeConfig());
    patchPw(adapter, pw);

    const result = await adapter.send([{ role: 'user', content: 'What integrations?' }]);

    expect(result.content).toContain('Forethought integrates with Zendesk');
    expect(result.content).not.toContain('Bot Response:');
    expect(result.raw).toEqual({ method: 'forethought-widget' });
    expect(result.latencyMs).toBeGreaterThanOrEqual(0);
    expect(inputEl.fill).toHaveBeenCalledWith('What integrations?');
    expect(inputEl.press).toHaveBeenCalledWith('Enter');
  });

  it('navigates to baseUrl and opens widget', async () => {
    const { pw, page } = buildFakePw();
    const adapter = new ForethoughtAdapter(makeConfig({ baseUrl: 'https://forethought.ai/' }));
    patchPw(adapter, pw);

    await adapter.send([{ role: 'user', content: 'hi' }]);

    expect(page.goto).toHaveBeenCalledWith(
      'https://forethought.ai/',
      expect.objectContaining({ waitUntil: 'domcontentloaded' }),
    );
    expect(page.waitForFunction).toHaveBeenCalled();
    expect(page.evaluate).toHaveBeenCalled();
    expect(page.frame).toHaveBeenCalledWith({ name: 'Virtual Assistant Chat' });
  });

  it('extracts last user message from multi-turn', async () => {
    const { pw, inputEl } = buildFakePw();
    const adapter = new ForethoughtAdapter(makeConfig());
    patchPw(adapter, pw);

    await adapter.send([
      { role: 'user', content: 'first' },
      { role: 'assistant', content: 'reply' },
      { role: 'user', content: 'second' },
    ]);

    expect(inputEl.fill).toHaveBeenCalledWith('second');
  });

  it('throws when iframe not found', async () => {
    const { pw, page } = buildFakePw();
    page.frame = vi.fn().mockReturnValue(null);
    page.$ = vi.fn().mockResolvedValue(null);

    const adapter = new ForethoughtAdapter(makeConfig());
    patchPw(adapter, pw);

    await expect(adapter.send([{ role: 'user', content: 'hi' }])).rejects.toThrow('widget iframe not found');
  });

  it('throws when input not found', async () => {
    const { pw, frame } = buildFakePw();
    frame.$ = vi.fn().mockResolvedValue(null);

    const adapter = new ForethoughtAdapter(makeConfig());
    patchPw(adapter, pw);

    await expect(adapter.send([{ role: 'user', content: 'hi' }])).rejects.toThrow('chat input not found');
  });

  it('healthCheck returns true on success', async () => {
    const { pw } = buildFakePw();
    const adapter = new ForethoughtAdapter(makeConfig());
    patchPw(adapter, pw);

    expect(await adapter.healthCheck()).toBe(true);
  });

  it('healthCheck returns false on error', async () => {
    const { pw } = buildFakePw();
    pw.chromium.launch = vi.fn().mockRejectedValue(new Error('fail'));

    const adapter = new ForethoughtAdapter(makeConfig());
    patchPw(adapter, pw);

    expect(await adapter.healthCheck()).toBe(false);
  });

  it('close shuts down browser', async () => {
    const { pw, browser } = buildFakePw();
    const adapter = new ForethoughtAdapter(makeConfig());
    patchPw(adapter, pw);

    await adapter.send([{ role: 'user', content: 'hi' }]);
    await adapter.close();

    expect(browser.close).toHaveBeenCalled();
  });

  it('resetSession re-initializes on next send', async () => {
    const { pw, page, resetBotCalls } = buildFakePw();
    const adapter = new ForethoughtAdapter(makeConfig());
    patchPw(adapter, pw);

    await adapter.send([{ role: 'user', content: 'hi' }]);
    adapter.resetSession();

    patchPw(adapter, pw);
    resetBotCalls();

    await adapter.send([{ role: 'user', content: 'hello' }]);
    expect(page.goto).toHaveBeenCalledTimes(2);
  });
});
