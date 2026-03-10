import { BaseAdapter } from './base.js';
import type { AdapterConfig, AdapterResponse, Turn } from '../types/index.js';

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Browser-based chat widget adapter using Playwright.
 *
 * Automates a real browser to interact with any embedded AI chat widget
 * (Intercom Messenger, Drift, Zendesk, generic chat, etc.).
 *
 * Requires `playwright` as an optional peer dependency:
 *   pnpm add playwright && npx playwright install chromium
 *
 * Config options:
 *   - baseUrl: the page URL containing the chat widget
 *   - chatInputSelector: CSS selector for the chat input (auto-detected if omitted)
 *   - chatSubmitSelector: CSS selector for the submit button (auto-detected if omitted)
 *   - chatResponseSelector: CSS selector for bot response messages (auto-detected if omitted)
 *   - browserHeadless: run headless (default: true)
 */
export class BrowserAdapter extends BaseAdapter {
  private browser: any = null;
  private page: any = null;
  private initialized = false;

  private detectedInputSelector: string;
  private detectedSubmitSelector: string;
  private detectedResponseSelector: string;
  private readonly headless: boolean;
  private readonly responseStabilityMs: number;

  constructor(config: AdapterConfig) {
    super({ ...config, baseUrl: config.baseUrl });

    this.detectedInputSelector = config.chatInputSelector ?? '';
    this.detectedSubmitSelector = config.chatSubmitSelector ?? '';
    this.detectedResponseSelector = config.chatResponseSelector ?? '';
    this.headless = config.browserHeadless !== false;
    this.responseStabilityMs = config.browserResponseStabilityMs ?? 2000;
  }

  private async loadPlaywright(): Promise<any> {
    try {
      // Dynamic import to keep playwright as an optional peer dependency
      const moduleName = 'playwright';
      return await import(/* webpackIgnore: true */ moduleName);
    } catch {
      throw new Error(
        'Browser adapter requires playwright. Install it:\n' +
          '  pnpm add playwright && npx playwright install chromium',
      );
    }
  }

  private async ensureBrowser(): Promise<void> {
    if (this.initialized) return;

    const pw = await this.loadPlaywright();
    this.browser = await pw.chromium.launch({ headless: this.headless });
    const context = await this.browser.newContext({
      userAgent:
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    });
    this.page = await context.newPage();

    await this.page.goto(this.config.baseUrl, { waitUntil: 'networkidle', timeout: 60_000 });
    // Allow chat widgets to initialize
    await this.page.waitForTimeout(3000);

    if (!this.detectedInputSelector || !this.detectedResponseSelector) {
      await this.autoDetectSelectors();
    }

    this.initialized = true;
  }

  private async autoDetectSelectors(): Promise<void> {
    // Common chat widget selectors to probe
    const inputCandidates = [
      // Intercom Messenger
      'iframe[name="intercom-messenger-frame"]',
      // Generic chat inputs
      '[data-testid="chat-input"]',
      'textarea[placeholder*="message"]',
      'textarea[placeholder*="Message"]',
      'textarea[placeholder*="type"]',
      'textarea[placeholder*="Type"]',
      'textarea[placeholder*="Ask"]',
      'textarea[placeholder*="ask"]',
      'input[placeholder*="message"]',
      'input[placeholder*="Message"]',
      'input[placeholder*="type"]',
      'input[placeholder*="Ask"]',
      '[contenteditable="true"][role="textbox"]',
      '.chat-input textarea',
      '.chat-input input',
      '#chat-input',
      '[aria-label*="chat" i] textarea',
      '[aria-label*="chat" i] input',
      '[aria-label*="message" i]',
    ];

    const submitCandidates = [
      'button[type="submit"]',
      'button[aria-label*="send" i]',
      'button[aria-label*="Send" i]',
      '[data-testid="send-button"]',
      '.chat-submit',
      '#chat-submit',
    ];

    const responseCandidates = [
      '[data-testid="bot-message"]',
      '[data-testid="assistant-message"]',
      '.bot-message',
      '.assistant-message',
      '.agent-message',
      '[data-message-author="bot"]',
      '[data-author-type="bot"]',
      '[data-author-type="admin"]',
    ];

    // Check for Intercom iframe first — only set selectors not already provided by user
    const intercomFrame = await this.page.$('iframe[name="intercom-messenger-frame"]');
    if (intercomFrame) {
      if (!this.detectedInputSelector) this.detectedInputSelector = '__intercom_frame__';
      if (!this.detectedSubmitSelector) this.detectedSubmitSelector = '__intercom_frame__';
      if (!this.detectedResponseSelector) this.detectedResponseSelector = '__intercom_frame__';
      return;
    }

    // Try each candidate, skipping selectors already provided by the user
    if (!this.detectedInputSelector) {
      for (const sel of inputCandidates) {
        const el = await this.page.$(sel);
        if (el) {
          this.detectedInputSelector = sel;
          break;
        }
      }
    }

    if (!this.detectedSubmitSelector) {
      for (const sel of submitCandidates) {
        const el = await this.page.$(sel);
        if (el) {
          this.detectedSubmitSelector = sel;
          break;
        }
      }
    }

    if (!this.detectedResponseSelector) {
      for (const sel of responseCandidates) {
        const el = await this.page.$(sel);
        if (el) {
          this.detectedResponseSelector = sel;
          break;
        }
      }
    }

    if (!this.detectedInputSelector) {
      throw new Error(
        'Browser adapter: could not auto-detect chat input. ' +
          'Provide --chat-input-selector explicitly.',
      );
    }
  }

  async send(messages: Turn[]): Promise<AdapterResponse> {
    await this.ensureBrowser();

    const lastUser = messages.filter((m) => m.role === 'user').pop();
    const message = lastUser?.content ?? '';

    const start = performance.now();

    if (this.detectedInputSelector === '__intercom_frame__') {
      const content = await this.sendIntercomFrame(message);
      const latencyMs = Math.round(performance.now() - start);
      return { content, raw: { method: 'intercom-frame' }, latencyMs };
    }

    const content = await this.sendGenericWidget(message);
    const latencyMs = Math.round(performance.now() - start);
    return { content, raw: { method: 'generic-widget' }, latencyMs };
  }

  private async sendIntercomFrame(message: string): Promise<string> {
    const frame = this.page.frame({ name: 'intercom-messenger-frame' });

    if (!frame) {
      throw new Error('Browser adapter: Intercom messenger frame not found');
    }

    // Count existing messages before sending
    const beforeMessages = await frame.$$('[data-testid="message-body"], .intercom-block');
    const beforeCount = beforeMessages.length;

    // Find the composer input inside the Intercom frame
    const composerSelectors = [
      '[aria-label="Write a message\u2026"]',
      '[aria-label="Write your message\u2026"]',
      '.intercom-composer textarea',
      '.intercom-composer [contenteditable]',
      'textarea',
      '[contenteditable="true"]',
    ];

    let composer: any = null;
    for (const sel of composerSelectors) {
      composer = await frame.$(sel);
      if (composer) break;
    }

    if (!composer) {
      throw new Error('Browser adapter: could not find Intercom chat composer');
    }

    await composer.click();
    await composer.fill(message);
    await composer.press('Enter');

    // Wait for a new message to appear
    const timeout = this.config.timeout ?? 60_000;
    const deadline = Date.now() + timeout;

    while (Date.now() < deadline) {
      await this.page.waitForTimeout(this.responseStabilityMs);

      const afterMessages = await frame.$$('[data-testid="message-body"], .intercom-block');
      if (afterMessages.length > beforeCount) {
        const lastMsg = afterMessages[afterMessages.length - 1];
        const text = await lastMsg.textContent();
        if (text && text.trim()) {
          // Wait a bit more to ensure the message is complete (streaming)
          await this.page.waitForTimeout(1000);
          const finalMessages = await frame.$$('[data-testid="message-body"], .intercom-block');
          const finalMsg = finalMessages[finalMessages.length - 1];
          const finalText = await finalMsg.textContent();
          return (finalText ?? text).trim();
        }
      }
    }

    throw new Error(`Browser adapter: no Intercom reply within ${timeout / 1000}s`);
  }

  private async sendGenericWidget(message: string): Promise<string> {
    // Get current response count
    let beforeCount = 0;
    if (this.detectedResponseSelector) {
      const beforeMsgs = await this.page.$$(this.detectedResponseSelector);
      beforeCount = beforeMsgs.length;
    }

    // Type message
    const input = await this.page.$(this.detectedInputSelector);
    if (!input) {
      throw new Error(`Browser adapter: chat input not found at "${this.detectedInputSelector}"`);
    }

    await input.click();
    await input.fill(message);

    // Submit
    if (this.detectedSubmitSelector) {
      const btn = await this.page.$(this.detectedSubmitSelector);
      if (btn) {
        await btn.click();
      } else {
        await this.page.keyboard.press('Enter');
      }
    } else {
      await this.page.keyboard.press('Enter');
    }

    // Wait for response
    const timeout = this.config.timeout ?? 60_000;
    const deadline = Date.now() + timeout;

    while (Date.now() < deadline) {
      await this.page.waitForTimeout(this.responseStabilityMs);

      if (this.detectedResponseSelector) {
        const afterMsgs = await this.page.$$(this.detectedResponseSelector);
        if (afterMsgs.length > beforeCount) {
          const lastMsg = afterMsgs[afterMsgs.length - 1];
          const text = await lastMsg.textContent();
          if (text?.trim()) {
            // Wait for streaming to finish
            await this.page.waitForTimeout(1000);
            const finalMsgs = await this.page.$$(this.detectedResponseSelector);
            const finalMsg = finalMsgs[finalMsgs.length - 1];
            const finalText = await finalMsg.textContent();
            return (finalText ?? text).trim();
          }
        }
      } else {
        // No response selector — try to detect new content on the page
        await this.page.waitForTimeout(3000);
        return '[Browser adapter: response selector not configured — check page manually]';
      }
    }

    throw new Error(`Browser adapter: no reply within ${timeout / 1000}s`);
  }

  override async healthCheck(): Promise<boolean> {
    try {
      await this.ensureBrowser();
      return true;
    } catch {
      return false;
    }
  }

  override resetSession(): void {
    // Capture references before clearing, so the async close
    // cannot clobber a new browser created by ensureBrowser().
    const oldBrowser = this.browser;
    this.browser = null;
    this.page = null;
    this.initialized = false;

    if (oldBrowser) {
      void (oldBrowser as { close: () => Promise<void> }).close();
    }
  }

  override async close(): Promise<void> {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
      this.page = null;
      this.initialized = false;
    }
  }
}
