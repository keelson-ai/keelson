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
  private chatFrame: any = null;

  private static readonly RESPONSE_CANDIDATES = [
    '[data-testid="bot-message"]',
    '[data-testid="assistant-message"]',
    '.bot-message',
    '.assistant-message',
    '.agent-message',
    '[data-message-author="bot"]',
    '[data-author-type="bot"]',
    '[data-author-type="admin"]',
    'div.group\\/message',
    '.prose',
    '.markdown',
    '[class*="markdown"]',
  ];

  constructor(config: AdapterConfig) {
    super(config);

    this.detectedInputSelector = config.chatInputSelector ?? '';
    this.detectedSubmitSelector = config.chatSubmitSelector ?? '';
    this.detectedResponseSelector = config.chatResponseSelector ?? '';
  }

  protected override async onBrowserReady(): Promise<void> {
    this.chatFrame = null;
    if (!this.detectedInputSelector || !this.detectedResponseSelector) {
      await this.autoDetectSelectors();
    }
  }

  private async autoDetectSelectors(): Promise<void> {
    const inputCandidates = [
      'iframe[name="intercom-messenger-frame"]',
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

    // Check for Intercom iframe first — only set selectors not already provided by user
    const intercomFrame = await this.page.$('iframe[name="intercom-messenger-frame"]');
    if (intercomFrame) {
      if (!this.detectedInputSelector) this.detectedInputSelector = '__intercom_frame__';
      if (!this.detectedSubmitSelector) this.detectedSubmitSelector = '__intercom_frame__';
      if (!this.detectedResponseSelector) this.detectedResponseSelector = '__intercom_frame__';
      return;
    }

    const searchContexts: { ctx: any; isFrame: boolean }[] = [{ ctx: this.page, isFrame: false }];

    // Collect candidate iframes (skip non-chat iframes)
    const skipPatterns = ['stripe.com', 'google', 'analytics', 'recaptcha'];
    for (const frame of this.page.frames()) {
      const url = frame.url();
      if (
        url &&
        url !== 'about:blank' &&
        !skipPatterns.some((p) => url.includes(p)) &&
        frame !== this.page.mainFrame()
      ) {
        searchContexts.push({ ctx: frame, isFrame: true });
      }
    }

    for (const { ctx, isFrame } of searchContexts) {
      if (!this.detectedInputSelector) {
        for (const sel of inputCandidates) {
          if (sel.startsWith('iframe[')) continue; // skip iframe-matching selectors inside frames
          const el = await ctx.$(sel).catch(() => null);
          if (el) {
            this.detectedInputSelector = sel;
            if (isFrame) this.chatFrame = ctx;
            break;
          }
        }
      }

      if (this.detectedInputSelector && isFrame === !!this.chatFrame) {
        if (!this.detectedSubmitSelector) {
          for (const sel of submitCandidates) {
            const el = await ctx.$(sel).catch(() => null);
            if (el) {
              this.detectedSubmitSelector = sel;
              break;
            }
          }
        }

        if (!this.detectedResponseSelector) {
          for (const sel of BrowserAdapter.RESPONSE_CANDIDATES) {
            const el = await ctx.$(sel).catch(() => null);
            if (el) {
              this.detectedResponseSelector = sel;
              break;
            }
          }
        }

        break;
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

  private get widgetContext(): any {
    return this.chatFrame ?? this.page;
  }

  private async sendGenericWidget(message: string): Promise<string> {
    const ctx = this.widgetContext;

    let beforeCount = 0;
    if (this.detectedResponseSelector) {
      const beforeMsgs = await ctx.$$(this.detectedResponseSelector);
      beforeCount = beforeMsgs.length;
    }

    const input = await ctx.$(this.detectedInputSelector);
    if (!input) {
      throw new Error(`Browser adapter: chat input not found at "${this.detectedInputSelector}"`);
    }

    await input.click();
    await input.fill(message);

    if (this.detectedSubmitSelector) {
      const btn = await ctx.$(this.detectedSubmitSelector);
      if (btn) {
        await btn.click();
      } else {
        await input.press('Enter');
      }
    } else {
      await input.press('Enter');
    }

    if (this.detectedResponseSelector) {
      return this.waitForNewMessage(beforeCount);
    }

    // Response container may only appear after the first message
    await this.page.waitForTimeout(3000);
    await this.lateDetectResponseSelector(ctx);
    if (this.detectedResponseSelector) {
      return this.waitForNewMessage(0);
    }

    return '[Browser adapter: response selector not configured — check page manually]';
  }

  /** Detect response selector post-interaction (some UIs only render it after the first message). */
  private async lateDetectResponseSelector(ctx: any): Promise<void> {
    for (const sel of BrowserAdapter.RESPONSE_CANDIDATES) {
      const el = await ctx.$(sel).catch(() => null);
      if (el) {
        const text = await el.textContent().catch(() => '');
        if (text && text.trim().length > 5) {
          this.detectedResponseSelector = sel;
          break;
        }
      }
    }
  }

  /**
   * Wait for a new bot message using a MutationObserver inside the page.
   * Falls back to polling if the observer doesn't fire.
   */
  private async waitForNewMessage(beforeCount: number): Promise<string> {
    const timeout = this.config.timeout ?? 60_000;
    const selector = this.detectedResponseSelector;
    const ctx = this.widgetContext;

    const content = await Promise.race([
      ctx.evaluate(
        ({ sel, prevCount, stabilityMs }: { sel: string; prevCount: number; stabilityMs: number }) => {
          return new Promise<string>((resolve, reject) => {
            let stabilityTimer: ReturnType<typeof setTimeout> | null = null;
            let lastText = '';

            const checkStability = () => {
              const msgs = document.querySelectorAll(sel);
              if (msgs.length <= prevCount) return;

              const last = msgs[msgs.length - 1];
              const text = last.textContent?.trim() ?? '';
              if (!text || /^loading\.{0,3}$/i.test(text) || text === '…' || text === '...') return;

              if (text !== lastText) {
                lastText = text;
                if (stabilityTimer) clearTimeout(stabilityTimer);
                stabilityTimer = setTimeout(() => {
                  const final = document.querySelectorAll(sel);
                  const finalEl = final[final.length - 1];
                  const finalText = (finalEl?.textContent ?? text).trim();
                  if ((window as any).__keelsonObserver) {
                    (window as any).__keelsonObserver.disconnect();
                    (window as any).__keelsonObserver = undefined;
                  }
                  resolve(finalText);
                }, stabilityMs);
              }
            };

            checkStability();

            const observer = new MutationObserver(() => checkStability());

            (window as any).__keelsonObserver = observer;
            observer.observe(document.body, { childList: true, subtree: true, characterData: true });

            void reject; // rejection handled externally by Promise.race timeout
          });
        },
        { sel: selector, prevCount: beforeCount, stabilityMs: Math.min(this.responseStabilityMs, 3000) },
      ),
      new Promise<string>((_, reject) =>
        setTimeout(() => reject(new Error(`Browser adapter: no reply within ${timeout / 1000}s`)), timeout),
      ),
    ]).finally(() => {
      const cleanupCtx = this.chatFrame ?? this.page;
      cleanupCtx
        ?.evaluate(() => {
          (window as any).__keelsonObserver?.disconnect();
        })
        .catch(() => {});
    });

    return content;
  }
}
