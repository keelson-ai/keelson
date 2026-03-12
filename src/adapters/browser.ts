import { PlaywrightBaseAdapter } from './playwright-base.js';
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
 *   - browserPreInteraction: JS snippet to run in page before chat interaction
 *   - browserFreshContextPerSend: fresh browser context per send (default: false)
 *   - browserAdaptiveTimeout: retry on timeout with 2x timeout (default: false)
 */
export class BrowserAdapter extends PlaywrightBaseAdapter {
  private detectedInputSelector: string;
  private detectedSubmitSelector: string;
  private detectedResponseSelector: string;

  constructor(config: AdapterConfig) {
    super(config);

    this.detectedInputSelector = config.chatInputSelector ?? '';
    this.detectedSubmitSelector = config.chatSubmitSelector ?? '';
    this.detectedResponseSelector = config.chatResponseSelector ?? '';
  }

  protected override async onBrowserReady(): Promise<void> {
    if (!this.detectedInputSelector || !this.detectedResponseSelector) {
      await this.autoDetectSelectors();
    }
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
        'Browser adapter: could not auto-detect chat input. ' + 'Provide --chat-input-selector explicitly.',
      );
    }
  }

  protected async sendCore(messages: Turn[]): Promise<AdapterResponse> {
    await this.ensureBrowserCore();

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
    const beforeMessages = await frame.$$('[data-testid="message-body"], [class*="intercom-block"]');
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

      const afterMessages = await frame.$$('[data-testid="message-body"], [class*="intercom-block"]');
      if (afterMessages.length > beforeCount) {
        const lastMsg = afterMessages[afterMessages.length - 1];
        const text = await lastMsg.textContent();
        if (text && text.trim()) {
          // Wait a bit more to ensure the message is complete (streaming)
          await this.page.waitForTimeout(1000);
          const finalMessages = await frame.$$('[data-testid="message-body"], [class*="intercom-block"]');
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

    // Wait for response using MutationObserver when we have a response selector
    if (this.detectedResponseSelector) {
      return this.waitForNewMessage(beforeCount);
    }

    // No response selector — try to detect new content on the page
    await this.page.waitForTimeout(3000);
    return '[Browser adapter: response selector not configured — check page manually]';
  }

  /**
   * Wait for a new bot message using a MutationObserver inside the page.
   * Falls back to polling if the observer doesn't fire.
   */
  private async waitForNewMessage(beforeCount: number): Promise<string> {
    const timeout = this.config.timeout ?? 60_000;
    const selector = this.detectedResponseSelector;

    // Use page.evaluate to install a MutationObserver that resolves
    // when a new element matching the response selector appears.
    const content = await Promise.race([
      this.page.evaluate(
        ({ sel, prevCount, stabilityMs }: { sel: string; prevCount: number; stabilityMs: number }) => {
          return new Promise<string>((resolve, reject) => {
            // Check immediately — response might already be there
            const existing = document.querySelectorAll(sel);
            if (existing.length > prevCount) {
              const last = existing[existing.length - 1];
              if (last.textContent?.trim()) {
                // Wait for stability then resolve
                setTimeout(() => {
                  const final = document.querySelectorAll(sel);
                  const finalEl = final[final.length - 1];
                  resolve((finalEl?.textContent ?? last.textContent ?? '').trim());
                }, stabilityMs);
                return;
              }
            }

            // Install MutationObserver on the document body
            const observer = new MutationObserver(() => {
              const msgs = document.querySelectorAll(sel);
              if (msgs.length > prevCount) {
                const last = msgs[msgs.length - 1];
                const text = last.textContent?.trim();
                if (text) {
                  // Wait for streaming to stabilize
                  setTimeout(() => {
                    observer.disconnect();
                    (window as any).__keelsonObserver = undefined;
                    const final = document.querySelectorAll(sel);
                    const finalEl = final[final.length - 1];
                    resolve((finalEl?.textContent ?? text).trim());
                  }, stabilityMs);
                }
              }
            });

            // Store ref so the timeout cleanup path can disconnect it
            (window as any).__keelsonObserver = observer;
            observer.observe(document.body, { childList: true, subtree: true, characterData: true });

            void reject; // rejection handled externally by Promise.race timeout
          });
        },
        { sel: selector, prevCount: beforeCount, stabilityMs: Math.min(this.responseStabilityMs, 3000) },
      ),
      // Timeout fallback
      new Promise<string>((_, reject) =>
        setTimeout(() => reject(new Error(`Browser adapter: no reply within ${timeout / 1000}s`)), timeout),
      ),
    ]).finally(() => {
      // Disconnect any lingering MutationObserver from the page context
      this.page
        ?.evaluate(() => {
          (window as any).__keelsonObserver?.disconnect();
        })
        .catch(() => {});
    });

    return content;
  }
}
